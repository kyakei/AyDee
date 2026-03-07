use anyhow::Result;
use std::io::{self, Write};
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

use crate::output;

/// Run Kerberos user enumeration via AS-REQ without pre-auth
pub async fn run(
    target: &str,
    domain: Option<&str>,
    wordlist: Option<&str>,
    collected_users: &[String],
    non_interactive: bool,
) -> Result<()> {
    output::section("KERBEROS ENUMERATION");
    if !non_interactive && !prompt_yes_no_default_no("Run Kerberos username enumeration") {
        output::info("Kerberos enumeration skipped");
        return Ok(());
    }

    let domain = match domain {
        Some(d) => d.to_uppercase(),
        None => {
            output::warning("No domain specified — Kerberos user enum requires a domain name");
            output::info("Use: ./aydee <ip> -d <domain>");
            return Ok(());
        }
    };

    // Build the username list: collected users + wordlist/built-in
    let mut usernames: Vec<String> = Vec::new();

    // Add collected users first (from LDAP/SMB/RPC)
    if !collected_users.is_empty() {
        output::info(&format!(
            "Using {} usernames collected from other modules",
            collected_users.len()
        ));
        usernames.extend(collected_users.iter().cloned());

        // Pre2k-ish machine-account variants: if we have HOST$, try HOST too.
        let mut pre2k_variants = Vec::new();
        for user in collected_users {
            if let Some(stripped) = user.strip_suffix('$') {
                if !stripped.is_empty() {
                    pre2k_variants.push(stripped.to_string());
                }
            }
        }
        if !pre2k_variants.is_empty() {
            output::info(&format!(
                "Adding {} machine-account pre2k-style variants",
                pre2k_variants.len()
            ));
            usernames.extend(pre2k_variants);
        }
    }

    // Add from wordlist or built-in
    let wordlist_path = match wordlist {
        Some(w) => w.to_string(),
        None => {
            let common_paths = [
                "/usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt",
                "/usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames-dup.txt",
                "/usr/share/seclists/Usernames/Names/names.txt",
                "/opt/seclists/Usernames/Names/names.txt",
            ];
            let found = common_paths.iter().find(|p| Path::new(p).exists());
            match found {
                Some(p) => {
                    output::info(&format!("Using wordlist: {}", p));
                    p.to_string()
                }
                None => {
                    if collected_users.is_empty() {
                        output::info("No wordlist found, using built-in common AD usernames");
                    }
                    String::new()
                }
            }
        }
    };

    if !wordlist_path.is_empty() {
        match tokio::fs::read_to_string(&wordlist_path).await {
            Ok(content) => {
                let wl_users: Vec<String> = content
                    .lines()
                    .filter(|l| !l.is_empty())
                    .map(String::from)
                    .collect();
                usernames.extend(wl_users);
            }
            Err(e) => {
                output::fail(&format!("Failed to read wordlist: {}", e));
            }
        }
    } else if collected_users.is_empty() {
        // Only add built-in if no collected users AND no wordlist
        let builtin: Vec<String> = vec![
            "administrator",
            "admin",
            "guest",
            "krbtgt",
            "backup",
            "service",
            "test",
            "user",
            "svc_admin",
            "svc_backup",
            "svc_sql",
            "svc_web",
            "sql_svc",
            "web_svc",
            "exchange",
            "mail",
            "helpdesk",
            "support",
            "operator",
            "manager",
            "domain_admin",
            "enterprise_admin",
            "it_admin",
            "sa",
            "dba",
            "developer",
            "deploy",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        usernames.extend(builtin);
    }

    // Deduplicate (case-insensitive)
    usernames.sort_by_key(|a| a.to_lowercase());
    usernames.dedup_by(|a, b| a.to_lowercase() == b.to_lowercase());

    if usernames.len() > 100_000 {
        if non_interactive {
            output::warning(&format!(
                "Large username set detected ({}). Skipping Kerberos enumeration in non-interactive mode",
                usernames.len()
            ));
            return Ok(());
        }
        if !prompt_yes_no_default_no(&format!(
            "Large username set detected ({}). Continue Kerberos enumeration",
            usernames.len()
        )) {
            output::info("Kerberos enumeration aborted by user");
            return Ok(());
        }
    }

    output::info(&format!(
        "Enumerating {} usernames against {} (realm: {})",
        usernames.len(),
        target,
        domain
    ));

    let mut valid_users = Vec::new();
    let mut asrep_users = Vec::new();
    let mut checked = 0;

    println!();

    for username in &usernames {
        match check_user(target, &domain, username).await {
            Ok(KerbResult::Valid) => {
                output::success(&format!("VALID: {}@{}", username, domain));
                valid_users.push(username.clone());
            }
            Ok(KerbResult::AsRepRoastable) => {
                output::success(&format!(
                    "VALID (NO PRE-AUTH!): {}@{} — AS-REP roastable!",
                    username, domain
                ));
                valid_users.push(username.clone());
                asrep_users.push(username.clone());
            }
            Ok(KerbResult::NotFound) => {
                // Silent
            }
            Ok(KerbResult::Locked) => {
                output::warning(&format!("LOCKED: {}@{}", username, domain));
            }
            Ok(KerbResult::Disabled) => {
                output::info(&format!("DISABLED: {}@{}", username, domain));
            }
            Err(_) => {}
        }

        checked += 1;
        if checked % 100 == 0 {
            output::info(&format!(
                "Progress: {}/{} checked",
                checked,
                usernames.len()
            ));
        }
    }

    println!();
    output::info(&format!(
        "Checked {} usernames, found {} valid",
        checked,
        valid_users.len()
    ));

    if !valid_users.is_empty() {
        output::success(&format!("Valid users: {}", valid_users.join(", ")));
    }
    if !asrep_users.is_empty() {
        output::success(&format!("AS-REP Roastable: {}", asrep_users.join(", ")));
    }

    Ok(())
}

fn prompt_yes_no_default_no(prompt: &str) -> bool {
    print!("  [?] {}? [y/N]: ", prompt);
    let _ = io::stdout().flush();

    let mut input = String::new();
    match io::stdin().read_line(&mut input) {
        Ok(0) => false,
        Ok(_) => matches!(input.trim().to_ascii_lowercase().as_str(), "y" | "yes"),
        Err(_) => false,
    }
}

/// Result of checking a single user
enum KerbResult {
    Valid,          // KDC_ERR_PREAUTH_REQUIRED — user exists, needs preauth
    AsRepRoastable, // Got AS-REP — user exists, no preauth required
    NotFound,       // KDC_ERR_C_PRINCIPAL_UNKNOWN
    Locked,         // KDC_ERR_CLIENT_REVOKED
    Disabled,       // KDC_ERR_CLIENT_REVOKED with disabled flag
}

/// Build an AS-REQ for a given principal without pre-authentication
fn build_as_req(realm: &str, username: &str) -> Vec<u8> {
    // Build the cname (PrincipalName)
    let name_string = der_general_string(username);
    let name_seq = der_sequence(&name_string);
    let name_type = der_context_tag(0, &der_integer(1)); // NT-PRINCIPAL = 1
    let name_strings = der_context_tag(1, &name_seq);
    let cname_body = [name_type.as_slice(), name_strings.as_slice()].concat();
    let cname = der_sequence(&cname_body);

    // Build the sname (krbtgt/REALM)
    let sname_string1 = der_general_string("krbtgt");
    let sname_string2 = der_general_string(realm);
    let sname_seq = der_sequence(&[sname_string1, sname_string2].concat());
    let sname_type = der_context_tag(0, &der_integer(2)); // NT-SRV-INST = 2
    let sname_strings = der_context_tag(1, &sname_seq);
    let sname_body = [sname_type.as_slice(), sname_strings.as_slice()].concat();
    let sname = der_sequence(&sname_body);

    // Etype list: AES256-CTS, AES128-CTS, RC4-HMAC
    let etypes = der_sequence(
        &[
            der_integer(18), // AES256-CTS-HMAC-SHA1-96
            der_integer(17), // AES128-CTS-HMAC-SHA1-96
            der_integer(23), // RC4-HMAC
        ]
        .concat(),
    );

    // KDC-REQ-BODY
    let kdc_options = der_context_tag(0, &der_bit_string(&[0x40, 0x81, 0x00, 0x10])); // forwardable, renewable, canonicalize, renewable-ok
    let cname_field = der_context_tag(1, &cname);
    let realm_field = der_context_tag(2, &der_general_string(realm));
    let sname_field = der_context_tag(3, &sname);
    let till = der_context_tag(5, &der_generalized_time("20370913024805Z"));
    let nonce_val: u32 = 12381973; // arbitrary nonce
    let nonce = der_context_tag(7, &der_integer_u32(nonce_val));
    let etype_field = der_context_tag(8, &etypes);

    let req_body_inner = [
        kdc_options,
        cname_field,
        realm_field,
        sname_field,
        till,
        nonce,
        etype_field,
    ]
    .concat();
    let req_body = der_sequence(&req_body_inner);
    let req_body_field = der_context_tag(4, &req_body);

    // KDC-REQ (AS-REQ)
    let pvno = der_context_tag(1, &der_integer(5)); // Kerberos v5
    let msg_type = der_context_tag(2, &der_integer(10)); // AS-REQ = 10
                                                         // No padata — this is the key: no pre-auth data

    let as_req_body = [pvno, msg_type, req_body_field].concat();
    let as_req = der_sequence(&as_req_body);

    // Wrap in APPLICATION [10]
    let mut app_tag = vec![0x6a]; // Application tag 10
    app_tag.extend_from_slice(&der_length(as_req.len()));
    app_tag.extend_from_slice(&as_req);

    // Wrap with length prefix for TCP (4-byte big-endian length)
    let mut tcp_pkt = Vec::new();
    let len = app_tag.len() as u32;
    tcp_pkt.extend_from_slice(&len.to_be_bytes());
    tcp_pkt.extend_from_slice(&app_tag);

    tcp_pkt
}

/// Check if a user exists via AS-REQ
async fn check_user(target: &str, realm: &str, username: &str) -> Result<KerbResult> {
    let addr = format!("{}:88", target);
    let mut stream = timeout(Duration::from_secs(3), TcpStream::connect(&addr)).await??;

    let as_req = build_as_req(realm, username);
    stream.write_all(&as_req).await?;

    let mut len_buf = [0u8; 4];
    timeout(Duration::from_secs(3), stream.read_exact(&mut len_buf)).await??;
    let resp_len = u32::from_be_bytes(len_buf) as usize;

    if resp_len > 65535 {
        return Ok(KerbResult::NotFound);
    }

    let mut resp = vec![0u8; resp_len];
    timeout(Duration::from_secs(3), stream.read_exact(&mut resp)).await??;

    // Parse KRB-ERROR or AS-REP
    // If we got an AS-REP (application tag 11 = 0x6b), user has no preauth
    if !resp.is_empty() && (resp[0] & 0x1f) == 11 {
        return Ok(KerbResult::AsRepRoastable);
    }

    // If KRB-ERROR (application tag 30 = 0x7e), check error code
    if !resp.is_empty() && (resp[0] & 0x1f) == 30 {
        // Find error-code in the response
        // Error code is typically a context tag [6] INTEGER
        if let Some(error_code) = extract_krb_error_code(&resp) {
            return Ok(match error_code {
                6 => KerbResult::NotFound,  // KDC_ERR_C_PRINCIPAL_UNKNOWN
                18 => KerbResult::Valid,    // KDC_ERR_PREAUTH_REQUIRED
                24 => KerbResult::Valid,    // KDC_ERR_PREAUTH_FAILED (still means user exists)
                12 => KerbResult::Disabled, // KDC_ERR_POLICY
                36 => KerbResult::Locked,   // KDC_ERR_CLIENT_REVOKED
                _ => KerbResult::NotFound,
            });
        }
    }

    Ok(KerbResult::NotFound)
}

/// Extract error code from KRB-ERROR message
fn extract_krb_error_code(data: &[u8]) -> Option<u32> {
    // Walk through the ASN.1 structure to find error-code [6]
    // This is a simplified parser
    let mut pos = 0;

    // Skip application tag
    if pos >= data.len() {
        return None;
    }
    pos += 1; // tag
    let (_len, consumed) = parse_der_length(&data[pos..])?;
    pos += consumed;

    // Now inside SEQUENCE
    if pos >= data.len() || data[pos] != 0x30 {
        return None;
    }
    pos += 1;
    let (_, consumed) = parse_der_length(&data[pos..])?;
    pos += consumed;

    // Walk through context tags looking for [6] (error-code)
    while pos < data.len() {
        let tag = data[pos];
        pos += 1;

        let (field_len, consumed) = parse_der_length(&data[pos..])?;
        pos += consumed;

        if tag == 0xa6 {
            // Context tag [6] = error-code
            // Should contain an INTEGER
            if pos < data.len() && data[pos] == 0x02 {
                pos += 1;
                let (int_len, consumed) = parse_der_length(&data[pos..])?;
                pos += consumed;
                let mut val: u32 = 0;
                for i in 0..int_len {
                    if pos + i < data.len() {
                        val = (val << 8) | data[pos + i] as u32;
                    }
                }
                return Some(val);
            }
            return None;
        }

        pos += field_len;
    }

    None
}

// ASN.1 DER encoding helpers

fn der_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len < 0x100 {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, (len & 0xff) as u8]
    }
}

fn parse_der_length(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }
    if data[0] < 0x80 {
        Some((data[0] as usize, 1))
    } else if data[0] == 0x81 {
        if data.len() < 2 {
            return None;
        }
        Some((data[1] as usize, 2))
    } else if data[0] == 0x82 {
        if data.len() < 3 {
            return None;
        }
        Some(((data[1] as usize) << 8 | data[2] as usize, 3))
    } else {
        None
    }
}

fn der_integer(val: i32) -> Vec<u8> {
    let mut out = vec![0x02];
    if val >= 0 && val < 128 {
        out.push(1);
        out.push(val as u8);
    } else if val >= 128 && val < 256 {
        out.push(2);
        out.push(0);
        out.push(val as u8);
    } else {
        let bytes = val.to_be_bytes();
        // Strip leading zeros/sign-extension
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(3);
        let significant = &bytes[start..];
        if significant[0] & 0x80 != 0 {
            out.push((significant.len() + 1) as u8);
            out.push(0);
        } else {
            out.push(significant.len() as u8);
        }
        out.extend_from_slice(significant);
    }
    out
}

fn der_integer_u32(val: u32) -> Vec<u8> {
    let mut out = vec![0x02];
    let bytes = val.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(3);
    let significant = &bytes[start..];
    if significant[0] & 0x80 != 0 {
        out.push((significant.len() + 1) as u8);
        out.push(0);
    } else {
        out.push(significant.len() as u8);
    }
    out.extend_from_slice(significant);
    out
}

fn der_general_string(s: &str) -> Vec<u8> {
    let mut out = vec![0x1b]; // GeneralString tag
    out.extend_from_slice(&der_length(s.len()));
    out.extend_from_slice(s.as_bytes());
    out
}

fn der_generalized_time(s: &str) -> Vec<u8> {
    let mut out = vec![0x18]; // GeneralizedTime tag
    out.extend_from_slice(&der_length(s.len()));
    out.extend_from_slice(s.as_bytes());
    out
}

fn der_bit_string(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x03];
    out.extend_from_slice(&der_length(data.len() + 1));
    out.push(0); // padding bits
    out.extend_from_slice(data);
    out
}

fn der_sequence(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x30];
    out.extend_from_slice(&der_length(data.len()));
    out.extend_from_slice(data);
    out
}

fn der_context_tag(tag: u8, data: &[u8]) -> Vec<u8> {
    let mut out = vec![0xa0 | tag];
    out.extend_from_slice(&der_length(data.len()));
    out.extend_from_slice(data);
    out
}
