use anyhow::Result;
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration};

use crate::types::{Finding, ModuleResult, Severity, StageTimer};
use crate::ui;

const MAX_CONCURRENT: usize = 10; // Conservative to avoid KDC rate limiting

/// Run Kerberos user enumeration via AS-REQ without pre-auth.
pub async fn run(
    target: &str,
    domain: Option<&str>,
    wordlist: Option<&str>,
    collected_users: &[String],
    non_interactive: bool,
) -> Result<ModuleResult> {
    ui::section("KERBEROS ENUMERATION");
    let timer = StageTimer::start();
    let mut result = ModuleResult::new("kerberos");

    if !non_interactive {
        let confirm = dialoguer::Confirm::new()
            .with_prompt("  Run Kerberos username enumeration?")
            .default(false)
            .interact_opt()
            .unwrap_or(Some(false))
            .unwrap_or(false);
        if !confirm {
            ui::info("Kerberos enumeration skipped");
            result = result.skipped("user declined");
            return Ok(result);
        }
    }

    let domain = match domain {
        Some(d) => d.to_uppercase(),
        None => {
            ui::warning("No domain — Kerberos user enum requires a domain name");
            result = result.skipped("no domain");
            return Ok(result);
        }
    };

    // Build username list
    let mut usernames = build_username_list(collected_users, wordlist).await;
    usernames.sort_by_key(|a| a.to_lowercase());
    usernames.dedup_by(|a, b| a.to_lowercase() == b.to_lowercase());

    if usernames.is_empty() {
        ui::warning("No usernames to enumerate");
        result = result.skipped("empty username list");
        return Ok(result);
    }

    if usernames.len() > 100_000 && !non_interactive {
        let confirm = dialoguer::Confirm::new()
            .with_prompt(&format!(
                "  Large username set ({}). Continue?",
                usernames.len()
            ))
            .default(false)
            .interact_opt()
            .unwrap_or(Some(false))
            .unwrap_or(false);
        if !confirm {
            result = result.skipped("user declined large set");
            return Ok(result);
        }
    }

    let total = usernames.len();
    let pb = ui::progress_bar(total as u64, "KERB-ENUM");
    pb.set_message(format!("0/{} checked", total));

    // Concurrent enumeration
    let sem = std::sync::Arc::new(Semaphore::new(MAX_CONCURRENT));
    let target = std::sync::Arc::new(target.to_string());
    let domain = std::sync::Arc::new(domain);

    let mut handles = Vec::new();
    for username in usernames {
        let sem = sem.clone();
        let target = target.clone();
        let domain = domain.clone();
        let pb = pb.clone();

        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            let result = check_user(&target, &domain, &username).await;
            pb.inc(1);
            (username, result)
        }));
    }

    let mut valid_users = Vec::new();
    let mut asrep_users = Vec::new();
    let mut locked_users = Vec::new();
    let mut checked = 0u64;

    for handle in handles {
        if let Ok((username, check_result)) = handle.await {
            checked += 1;
            match check_result {
                Ok(KerbResult::Valid) => {
                    pb.println(format!(
                        "  {} VALID: {}@{}",
                        "[+]".to_string(),
                        username,
                        domain
                    ));
                    valid_users.push(username);
                }
                Ok(KerbResult::AsRepRoastable) => {
                    pb.println(format!(
                        "  {} AS-REP ROASTABLE: {}@{} — no pre-auth!",
                        "[!]".to_string(),
                        username,
                        domain
                    ));
                    valid_users.push(username.clone());
                    asrep_users.push(username);
                }
                Ok(KerbResult::Locked) => {
                    pb.println(format!("  [!] LOCKED: {}@{}", username, domain));
                    locked_users.push(username);
                }
                Ok(KerbResult::Disabled) => {
                    pb.println(format!("  [*] DISABLED: {}@{}", username, domain));
                }
                Ok(KerbResult::NotFound) | Err(_) => {}
            }

            if checked % 500 == 0 {
                pb.set_message(format!("{}/{} checked, {} valid", checked, total, valid_users.len()));
            }
        }
    }

    pb.finish_and_clear();

    // Report results
    if !valid_users.is_empty() {
        ui::success(&format!(
            "Found {} valid user(s): {}",
            valid_users.len(),
            if valid_users.len() <= 20 {
                valid_users.join(", ")
            } else {
                format!("{}, ... ({} more)", valid_users[..20].join(", "), valid_users.len() - 20)
            }
        ));
        result.collected_users.extend(valid_users);
    }

    if !asrep_users.is_empty() {
        ui::warning(&format!(
            "{} AS-REP roastable user(s): {}",
            asrep_users.len(),
            asrep_users.join(", ")
        ));
        let finding = Finding::new(
            "kerberos",
            "KERB-003",
            Severity::High,
            &format!("{} AS-REP roastable users via enumeration", asrep_users.len()),
        )
        .with_evidence(&asrep_users.join(", "))
        .with_recommendation("Enable Kerberos pre-authentication on all accounts")
        .with_mitre("T1558.004");
        result.findings.push(finding);
    }

    if !locked_users.is_empty() {
        ui::info(&format!("{} locked account(s)", locked_users.len()));
    }

    ui::stage_done(
        "KERBEROS",
        &format!("{} checked, {} valid", checked, result.collected_users.len()),
        &timer.elapsed_pretty(),
    );

    result = result.success(timer.elapsed());
    Ok(result)
}

// ── Username list builder ───────────────────────────────────────────────────

async fn build_username_list(collected: &[String], wordlist: Option<&str>) -> Vec<String> {
    let mut usernames: Vec<String> = collected.to_vec();

    // Add pre2k variants
    let pre2k: Vec<String> = collected
        .iter()
        .filter_map(|u| u.strip_suffix('$').map(|s| s.to_string()))
        .filter(|s| !s.is_empty())
        .collect();
    usernames.extend(pre2k);

    // Wordlist
    let wl_path = match wordlist {
        Some(w) => Some(w.to_string()),
        None => {
            let paths = [
                "/usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt",
                "/usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames-dup.txt",
                "/usr/share/seclists/Usernames/Names/names.txt",
                "/opt/seclists/Usernames/Names/names.txt",
            ];
            paths.iter().find(|p| Path::new(p).exists()).map(|p| p.to_string())
        }
    };

    if let Some(path) = wl_path {
        if let Ok(content) = tokio::fs::read_to_string(&path).await {
            let wl: Vec<String> = content
                .lines()
                .filter(|l| !l.is_empty())
                .map(String::from)
                .collect();
            ui::info(&format!("Loaded {} usernames from wordlist", wl.len()));
            usernames.extend(wl);
        }
    } else if collected.is_empty() {
        // Built-in common AD names
        let builtin = [
            "administrator", "admin", "guest", "krbtgt", "backup", "service", "test",
            "user", "svc_admin", "svc_backup", "svc_sql", "svc_web", "sql_svc", "web_svc",
            "exchange", "mail", "helpdesk", "support", "operator", "manager", "sa", "dba",
            "developer", "deploy", "svc_iis", "svc_mssql", "svc_http", "svc_sccm",
            "svc_wsus", "svc_exchange", "svc_ca", "svc_adfs",
        ];
        usernames.extend(builtin.iter().map(|s| s.to_string()));
    }

    usernames
}

// ── Kerberos AS-REQ check ───────────────────────────────────────────────────

enum KerbResult {
    Valid,
    AsRepRoastable,
    NotFound,
    Locked,
    Disabled,
}

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

    // AS-REP (app tag 11) = no pre-auth required
    if !resp.is_empty() && (resp[0] & 0x1f) == 11 {
        return Ok(KerbResult::AsRepRoastable);
    }

    // KRB-ERROR (app tag 30)
    if !resp.is_empty() && (resp[0] & 0x1f) == 30 {
        if let Some(code) = extract_krb_error_code(&resp) {
            return Ok(match code {
                6 => KerbResult::NotFound,   // PRINCIPAL_UNKNOWN
                18 => KerbResult::Valid,     // PREAUTH_REQUIRED
                24 => KerbResult::Valid,     // PREAUTH_FAILED
                12 => KerbResult::Disabled,  // POLICY
                36 => KerbResult::Locked,    // CLIENT_REVOKED
                _ => KerbResult::NotFound,
            });
        }
    }

    Ok(KerbResult::NotFound)
}

// ── ASN.1/DER encoding ─────────────────────────────────────────────────────

fn build_as_req(realm: &str, username: &str) -> Vec<u8> {
    let name_string = der_general_string(username);
    let name_seq = der_sequence(&name_string);
    let name_type = der_ctx(0, &der_integer(1));
    let name_strings = der_ctx(1, &name_seq);
    let cname = der_sequence(&[name_type, name_strings].concat());

    let sname_s1 = der_general_string("krbtgt");
    let sname_s2 = der_general_string(realm);
    let sname_seq = der_sequence(&[sname_s1, sname_s2].concat());
    let sname = der_sequence(&[der_ctx(0, &der_integer(2)), der_ctx(1, &sname_seq)].concat());

    let etypes = der_sequence(
        &[der_integer(18), der_integer(17), der_integer(23)].concat(),
    );

    let kdc_options = der_ctx(0, &der_bit_string(&[0x40, 0x81, 0x00, 0x10]));
    let req_body = der_sequence(
        &[
            kdc_options,
            der_ctx(1, &cname),
            der_ctx(2, &der_general_string(realm)),
            der_ctx(3, &sname),
            der_ctx(5, &der_generalized_time("20370913024805Z")),
            der_ctx(7, &der_integer_u32(12381973)),
            der_ctx(8, &etypes),
        ]
        .concat(),
    );

    let as_req_body = [
        der_ctx(1, &der_integer(5)),  // pvno
        der_ctx(2, &der_integer(10)), // AS-REQ
        der_ctx(4, &req_body),
    ]
    .concat();

    let as_req = der_sequence(&as_req_body);

    // APPLICATION [10]
    let mut app = vec![0x6a];
    app.extend_from_slice(&der_length(as_req.len()));
    app.extend_from_slice(&as_req);

    // TCP length prefix
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&(app.len() as u32).to_be_bytes());
    pkt.extend_from_slice(&app);
    pkt
}

fn extract_krb_error_code(data: &[u8]) -> Option<u32> {
    let mut pos = 0;
    if pos >= data.len() {
        return None;
    }
    pos += 1;
    let (_, consumed) = parse_der_length(&data[pos..])?;
    pos += consumed;

    if pos >= data.len() || data[pos] != 0x30 {
        return None;
    }
    pos += 1;
    let (_, consumed) = parse_der_length(&data[pos..])?;
    pos += consumed;

    while pos < data.len() {
        let tag = data[pos];
        pos += 1;
        let (field_len, consumed) = parse_der_length(&data[pos..])?;
        pos += consumed;

        if tag == 0xa6 {
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

// DER helpers
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
    } else if data[0] == 0x81 && data.len() >= 2 {
        Some((data[1] as usize, 2))
    } else if data[0] == 0x82 && data.len() >= 3 {
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
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(3);
        let sig = &bytes[start..];
        if sig[0] & 0x80 != 0 {
            out.push((sig.len() + 1) as u8);
            out.push(0);
        } else {
            out.push(sig.len() as u8);
        }
        out.extend_from_slice(sig);
    }
    out
}

fn der_integer_u32(val: u32) -> Vec<u8> {
    let mut out = vec![0x02];
    let bytes = val.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(3);
    let sig = &bytes[start..];
    if sig[0] & 0x80 != 0 {
        out.push((sig.len() + 1) as u8);
        out.push(0);
    } else {
        out.push(sig.len() as u8);
    }
    out.extend_from_slice(sig);
    out
}

fn der_general_string(s: &str) -> Vec<u8> {
    let mut out = vec![0x1b];
    out.extend_from_slice(&der_length(s.len()));
    out.extend_from_slice(s.as_bytes());
    out
}

fn der_generalized_time(s: &str) -> Vec<u8> {
    let mut out = vec![0x18];
    out.extend_from_slice(&der_length(s.len()));
    out.extend_from_slice(s.as_bytes());
    out
}

fn der_bit_string(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x03];
    out.extend_from_slice(&der_length(data.len() + 1));
    out.push(0);
    out.extend_from_slice(data);
    out
}

fn der_sequence(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x30];
    out.extend_from_slice(&der_length(data.len()));
    out.extend_from_slice(data);
    out
}

fn der_ctx(tag: u8, data: &[u8]) -> Vec<u8> {
    let mut out = vec![0xa0 | tag];
    out.extend_from_slice(&der_length(data.len()));
    out.extend_from_slice(data);
    out
}
