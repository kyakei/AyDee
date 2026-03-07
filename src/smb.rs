use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use aes::Aes256;
use anyhow::Result;
use base64::Engine;
use cbc::Decryptor;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::process::Command;
use tokio::time::{timeout, Duration};

use crate::auth_recon::AuthFinding;
use crate::output;

fn smb_tag_selected(selected: &[String], tag: &str) -> bool {
    if selected.is_empty() {
        return true;
    }
    selected.iter().any(|t| t.eq_ignore_ascii_case(tag))
}

/// Run SMB enumeration — NTLM info leak + null session checks
pub async fn run(target: &str, port: u16, selected_tags: &[String]) -> Result<Option<NtlmInfo>> {
    output::section("SMB ENUMERATION");
    output::info(&format!("Connecting to {}:{}", target, port));

    // Step 1: SMB2 Negotiate to get NTLM info
    let returned_info = if smb_tag_selected(selected_tags, "ntlm-info")
        || smb_tag_selected(selected_tags, "all")
    {
        let ntlm_info = ntlm_info_leak(target, port).await;
        match ntlm_info {
            Ok(Some(info)) => {
                output::success("NTLM info leak — domain details extracted!");
                if let Some(ref v) = info.dns_domain_name {
                    output::kv("DNS Domain Name", v);
                }
                if let Some(ref v) = info.dns_computer_name {
                    output::kv("DNS Computer Name", v);
                }
                if let Some(ref v) = info.dns_tree_name {
                    output::kv("DNS Tree Name", v);
                }
                if let Some(ref v) = info.netbios_domain_name {
                    output::kv("NetBIOS Domain Name", v);
                }
                if let Some(ref v) = info.netbios_computer_name {
                    output::kv("NetBIOS Computer Name", v);
                }
                if let Some(ref v) = info.product_version {
                    output::kv("OS Version", v);
                }
                if let Some(ref v) = info.timestamp {
                    output::kv("Server Time", v);
                }
                Some(info)
            }
            Ok(None) => {
                output::warning("NTLM info leak — could not extract info (NTLM may be disabled)");
                None
            }
            Err(e) => {
                output::fail(&format!("NTLM info leak failed: {}", e));
                None
            }
        }
    } else {
        None
    };

    // Step 2: Check for SMB signing
    if smb_tag_selected(selected_tags, "signing") || smb_tag_selected(selected_tags, "all") {
        check_smb_signing(target, port).await;
    }

    // Step 3: Check whether SMB1 is accepted
    if smb_tag_selected(selected_tags, "smb1") || smb_tag_selected(selected_tags, "all") {
        check_smb1_support(target, port).await;
    }

    // Step 4: Check null session (guest/anonymous)
    if smb_tag_selected(selected_tags, "null-session") || smb_tag_selected(selected_tags, "all") {
        check_null_session(target, port).await;
    }

    Ok(returned_info)
}

/// Authenticated SMB recon using smbclient:
/// - list shares
/// - attempt top-level listing on accessible disk shares
pub async fn run_authenticated(
    target: &str,
    username: &str,
    password: Option<&str>,
    ntlm_hash: Option<&str>,
    kerberos: bool,
    selected_tags: &[String],
) -> Result<SmbAuthResult> {
    output::section("SMB AUTHENTICATED RECON");
    output::info("Attempting authenticated SMB share discovery and listing");

    let mut combined = Vec::new();
    let mut findings = Vec::new();
    let mut methods_attempted = 0usize;

    let want_shares = smb_tag_selected(selected_tags, "shares")
        || smb_tag_selected(selected_tags, "auth-shares")
        || smb_tag_selected(selected_tags, "all");
    let want_list = smb_tag_selected(selected_tags, "list")
        || smb_tag_selected(selected_tags, "share-list")
        || smb_tag_selected(selected_tags, "all");
    let want_gpp = smb_tag_selected(selected_tags, "gpp")
        || smb_tag_selected(selected_tags, "sysvol")
        || smb_tag_selected(selected_tags, "all");
    let run_auth_share_checks = want_shares || want_list || want_gpp;
    let mut gpp_done = false;

    if let Some(pass) = password {
        methods_attempted += 1;
        if run_auth_share_checks {
            let shares = smbclient_list_shares(target, username, Some(pass), None, false).await;
            if let Ok(shares) = shares {
                output::success(&format!(
                    "Password method: discovered {} shares",
                    shares.len()
                ));
                combined.extend(shares.clone());
                if want_list {
                    list_share_roots(target, username, Some(pass), None, false, &shares).await;
                }
                if want_gpp && !gpp_done {
                    findings.extend(
                        enumerate_sysvol_gpp(target, username, Some(pass), None, false, &shares)
                            .await,
                    );
                    gpp_done = true;
                }
            }
        }
    }

    if let Some(hash) = ntlm_hash {
        methods_attempted += 1;
        if run_auth_share_checks {
            let shares = smbclient_list_shares(target, username, None, Some(hash), false).await;
            if let Ok(shares) = shares {
                output::success(&format!("NTLM method: discovered {} shares", shares.len()));
                combined.extend(shares.clone());
                if want_list {
                    list_share_roots(target, username, None, Some(hash), false, &shares).await;
                }
                if want_gpp && !gpp_done {
                    findings.extend(
                        enumerate_sysvol_gpp(target, username, None, Some(hash), false, &shares)
                            .await,
                    );
                    gpp_done = true;
                }
            }
        }
    }

    if kerberos {
        methods_attempted += 1;
        if run_auth_share_checks {
            let shares = smbclient_list_shares(target, username, None, None, true).await;
            if let Ok(shares) = shares {
                output::success(&format!(
                    "Kerberos method: discovered {} shares",
                    shares.len()
                ));
                combined.extend(shares.clone());
                if want_list {
                    list_share_roots(target, username, None, None, true, &shares).await;
                }
                if want_gpp && !gpp_done {
                    findings.extend(
                        enumerate_sysvol_gpp(target, username, None, None, true, &shares).await,
                    );
                }
            }
        }
    }

    if methods_attempted == 0 {
        output::warning("No SMB auth method provided (--password, --ntlm, or --kerberos)");
    } else if !want_shares {
        output::info("SMB auth methods attempted but share enumeration tags are not selected");
    }

    combined.sort();
    combined.dedup();
    Ok(SmbAuthResult {
        shares: combined,
        findings,
    })
}

#[derive(Debug, Default)]
pub struct SmbAuthResult {
    pub shares: Vec<String>,
    pub findings: Vec<AuthFinding>,
}

/// NTLM info extracted from Type 2 message
#[derive(Debug, Default)]
pub struct NtlmInfo {
    pub dns_domain_name: Option<String>,
    pub dns_computer_name: Option<String>,
    pub dns_tree_name: Option<String>,
    pub netbios_domain_name: Option<String>,
    pub netbios_computer_name: Option<String>,
    pub product_version: Option<String>,
    pub timestamp: Option<String>,
}

/// Craft an SMB2 Negotiate request
fn build_smb2_negotiate() -> Vec<u8> {
    let mut pkt = Vec::new();

    // SMB2 Header (64 bytes)
    pkt.extend_from_slice(b"\xfeSMB"); // Magic
    pkt.extend_from_slice(&64u16.to_le_bytes()); // Header size
    pkt.extend_from_slice(&[0; 2]); // Credit charge
    pkt.extend_from_slice(&[0; 4]); // Status
    pkt.extend_from_slice(&0u16.to_le_bytes()); // Command: SMB2_NEGOTIATE
    pkt.extend_from_slice(&1u16.to_le_bytes()); // Credits requested
    pkt.extend_from_slice(&[0; 4]); // Flags
    pkt.extend_from_slice(&[0; 4]); // Next command
    pkt.extend_from_slice(&1u64.to_le_bytes()); // Message ID
    pkt.extend_from_slice(&[0; 4]); // Reserved
    pkt.extend_from_slice(&[0; 4]); // Tree ID
    pkt.extend_from_slice(&[0; 8]); // Session ID
    pkt.extend_from_slice(&[0; 16]); // Signature

    // SMB2 Negotiate Request
    pkt.extend_from_slice(&36u16.to_le_bytes()); // Structure size
    pkt.extend_from_slice(&2u16.to_le_bytes()); // Dialect count
    pkt.extend_from_slice(&1u16.to_le_bytes()); // Security mode: signing enabled
    pkt.extend_from_slice(&[0; 2]); // Reserved
    pkt.extend_from_slice(&[0; 4]); // Capabilities
    pkt.extend_from_slice(&[0; 16]); // Client GUID
    pkt.extend_from_slice(&[0; 4]); // Negotiate context offset
    pkt.extend_from_slice(&[0; 2]); // Negotiate context count
    pkt.extend_from_slice(&[0; 2]); // Reserved2

    // Dialects: SMB 2.0.2, SMB 2.1
    pkt.extend_from_slice(&0x0202u16.to_le_bytes());
    pkt.extend_from_slice(&0x0210u16.to_le_bytes());

    // NetBIOS session service header (prepend length)
    let mut full = Vec::new();
    full.push(0x00); // Message type: Session Message
    let len = pkt.len() as u32;
    full.push(((len >> 16) & 0xff) as u8);
    full.push(((len >> 8) & 0xff) as u8);
    full.push((len & 0xff) as u8);
    full.extend_from_slice(&pkt);
    full
}

/// Craft an SMB2 Session Setup with NTLMSSP Negotiate (Type 1)
fn build_ntlmssp_negotiate(session_id: u64) -> Vec<u8> {
    let mut pkt = Vec::new();

    // NTLMSSP Negotiate message (Type 1)
    let mut ntlmssp = Vec::new();
    ntlmssp.extend_from_slice(b"NTLMSSP\x00"); // Signature
    ntlmssp.extend_from_slice(&1u32.to_le_bytes()); // Type 1
                                                    // Flags: NEGOTIATE_UNICODE | NEGOTIATE_OEM | REQUEST_TARGET | NEGOTIATE_NTLM | NEGOTIATE_ALWAYS_SIGN | NEGOTIATE_56 | NEGOTIATE_128
    let flags: u32 = 0xe2088297;
    ntlmssp.extend_from_slice(&flags.to_le_bytes());
    // Domain name fields (empty)
    ntlmssp.extend_from_slice(&[0; 8]);
    // Workstation fields (empty)
    ntlmssp.extend_from_slice(&[0; 8]);

    // Wrap in SPNEGO / GSS-API
    let security_blob = build_spnego_init(&ntlmssp);

    // SMB2 Header
    pkt.extend_from_slice(b"\xfeSMB"); // Magic
    pkt.extend_from_slice(&64u16.to_le_bytes()); // Header size
    pkt.extend_from_slice(&[0; 2]); // Credit charge
    pkt.extend_from_slice(&[0; 4]); // Status
    pkt.extend_from_slice(&1u16.to_le_bytes()); // Command: SMB2_SESSION_SETUP
    pkt.extend_from_slice(&1u16.to_le_bytes()); // Credits requested
    pkt.extend_from_slice(&[0; 4]); // Flags
    pkt.extend_from_slice(&[0; 4]); // Next command
    pkt.extend_from_slice(&2u64.to_le_bytes()); // Message ID
    pkt.extend_from_slice(&[0; 4]); // Reserved
    pkt.extend_from_slice(&[0; 4]); // Tree ID
    pkt.extend_from_slice(&session_id.to_le_bytes()); // Session ID
    pkt.extend_from_slice(&[0; 16]); // Signature

    // SMB2 Session Setup Request
    pkt.extend_from_slice(&25u16.to_le_bytes()); // Structure size
    pkt.push(0); // Flags
    pkt.push(1); // Security mode
    pkt.extend_from_slice(&[0; 4]); // Capabilities
    pkt.extend_from_slice(&[0; 4]); // Channel
    let sec_offset = 64 + 24; // Header + session setup fixed part
    pkt.extend_from_slice(&(sec_offset as u16).to_le_bytes()); // Security buffer offset
    pkt.extend_from_slice(&(security_blob.len() as u16).to_le_bytes()); // Security buffer length
    pkt.extend_from_slice(&[0; 8]); // Previous session ID
    pkt.extend_from_slice(&security_blob);

    // NetBIOS header
    let mut full = Vec::new();
    full.push(0x00);
    let len = pkt.len() as u32;
    full.push(((len >> 16) & 0xff) as u8);
    full.push(((len >> 8) & 0xff) as u8);
    full.push((len & 0xff) as u8);
    full.extend_from_slice(&pkt);
    full
}

/// Build a minimal SPNEGO NegTokenInit wrapping the NTLMSSP token
fn build_spnego_init(ntlmssp: &[u8]) -> Vec<u8> {
    // mechType OID for NTLMSSP: 1.3.6.1.4.1.311.2.2.10
    let mech_oid: &[u8] = &[
        0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a,
    ];
    let mech_types = asn1_sequence(mech_oid);
    let mech_types_ctx = asn1_context_tag(0, &mech_types);

    let mech_token = asn1_context_tag(2, &asn1_octet_string(ntlmssp));

    let mut neg_token_init_body = Vec::new();
    neg_token_init_body.extend_from_slice(&mech_types_ctx);
    neg_token_init_body.extend_from_slice(&mech_token);

    let neg_token_init = asn1_context_tag(0, &asn1_sequence(&neg_token_init_body));

    // Application tag wrapping SPNEGO OID + negotiation
    let spnego_oid: &[u8] = &[0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
    let mut app_body = Vec::new();
    app_body.extend_from_slice(spnego_oid);
    app_body.extend_from_slice(&neg_token_init);

    asn1_application_tag(0, &app_body)
}

fn asn1_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len < 0x100 {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, (len & 0xff) as u8]
    }
}

fn asn1_sequence(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x30];
    out.extend_from_slice(&asn1_length(data.len()));
    out.extend_from_slice(data);
    out
}

fn asn1_context_tag(tag: u8, data: &[u8]) -> Vec<u8> {
    let mut out = vec![0xa0 | tag];
    out.extend_from_slice(&asn1_length(data.len()));
    out.extend_from_slice(data);
    out
}

fn asn1_application_tag(tag: u8, data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x60 | tag];
    out.extend_from_slice(&asn1_length(data.len()));
    out.extend_from_slice(data);
    out
}

fn asn1_octet_string(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x04];
    out.extend_from_slice(&asn1_length(data.len()));
    out.extend_from_slice(data);
    out
}

/// Extract NTLM info via SMB2 Negotiate + Session Setup
async fn ntlm_info_leak(target: &str, port: u16) -> Result<Option<NtlmInfo>> {
    let addr = format!("{}:{}", target, port);
    let mut stream = timeout(Duration::from_secs(5), TcpStream::connect(&addr)).await??;

    // Send SMB2 Negotiate
    let negotiate = build_smb2_negotiate();
    stream.write_all(&negotiate).await?;

    // Read response
    let mut buf = vec![0u8; 8192];
    let n = timeout(Duration::from_secs(5), stream.read(&mut buf)).await??;
    if n < 4 {
        return Ok(None);
    }

    // Send NTLMSSP Negotiate (Session Setup)
    let session_setup = build_ntlmssp_negotiate(0);
    stream.write_all(&session_setup).await?;

    // Read Session Setup response with NTLMSSP Challenge (Type 2)
    let mut buf = vec![0u8; 8192];
    let n = timeout(Duration::from_secs(5), stream.read(&mut buf)).await??;
    if n < 4 {
        return Ok(None);
    }

    // Find NTLMSSP signature in response
    let data = &buf[..n];
    if let Some(pos) = find_bytes(data, b"NTLMSSP\x00") {
        let ntlmssp = &data[pos..];
        if ntlmssp.len() < 32 {
            return Ok(None);
        }

        // Verify it's a Type 2 (Challenge) message
        let msg_type = u32::from_le_bytes([ntlmssp[8], ntlmssp[9], ntlmssp[10], ntlmssp[11]]);
        if msg_type != 2 {
            return Ok(None);
        }

        return Ok(Some(parse_ntlm_type2(ntlmssp)));
    }

    Ok(None)
}

/// Parse NTLM Type 2 (Challenge) message to extract target info
fn parse_ntlm_type2(data: &[u8]) -> NtlmInfo {
    let mut info = NtlmInfo::default();

    if data.len() < 56 {
        return info;
    }

    // Version info at offset 48 (8 bytes) if flags indicate it
    if data.len() >= 56 {
        let major = data[48];
        let minor = data[49];
        let build = u16::from_le_bytes([data[50], data[51]]);
        if major > 0 {
            info.product_version = Some(format!("{}.{}.{}", major, minor, build));
        }
    }

    // Target info at: offset 40 = length, 42 = max length, 44 = offset
    if data.len() >= 48 {
        let target_len = u16::from_le_bytes([data[40], data[41]]) as usize;
        let target_offset = u32::from_le_bytes([data[44], data[45], data[46], data[47]]) as usize;

        if target_offset + target_len <= data.len() {
            let target_info = &data[target_offset..target_offset + target_len];
            parse_av_pairs(target_info, &mut info);
        }
    }

    info
}

/// Parse AV_PAIR structures from target info
fn parse_av_pairs(data: &[u8], info: &mut NtlmInfo) {
    let mut cursor = Cursor::new(data);
    loop {
        if data.len() < cursor.position() as usize + 4 {
            break;
        }
        let pos = cursor.position() as usize;
        let av_id = u16::from_le_bytes([data[pos], data[pos + 1]]);
        let av_len = u16::from_le_bytes([data[pos + 2], data[pos + 3]]) as usize;
        cursor.set_position((pos + 4) as u64);

        if av_id == 0 {
            // MsvAvEOL
            break;
        }

        let pos = cursor.position() as usize;
        if pos + av_len > data.len() {
            break;
        }
        let value = &data[pos..pos + av_len];
        cursor.set_position((pos + av_len) as u64);

        match av_id {
            1 => {
                // MsvAvNbComputerName
                info.netbios_computer_name = Some(decode_utf16le(value));
            }
            2 => {
                // MsvAvNbDomainName
                info.netbios_domain_name = Some(decode_utf16le(value));
            }
            3 => {
                // MsvAvDnsComputerName
                info.dns_computer_name = Some(decode_utf16le(value));
            }
            4 => {
                // MsvAvDnsDomainName
                info.dns_domain_name = Some(decode_utf16le(value));
            }
            5 => {
                // MsvAvDnsTreeName
                info.dns_tree_name = Some(decode_utf16le(value));
            }
            7 => {
                // MsvAvTimestamp (FILETIME - 100ns intervals since Jan 1 1601)
                if value.len() >= 8 {
                    let filetime = u64::from_le_bytes([
                        value[0], value[1], value[2], value[3], value[4], value[5], value[6],
                        value[7],
                    ]);
                    // Convert to Unix timestamp
                    let unix_ts = (filetime / 10_000_000).saturating_sub(11644473600);
                    let dt = chrono_from_unix(unix_ts);
                    info.timestamp = Some(dt);
                }
            }
            _ => {}
        }
    }
}

fn decode_utf16le(data: &[u8]) -> String {
    let u16s: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&u16s)
}

fn chrono_from_unix(ts: u64) -> String {
    // Simple UTC timestamp formatting without chrono dependency
    let secs_per_day: u64 = 86400;
    let days = ts / secs_per_day;
    let remaining = ts % secs_per_day;
    let hours = remaining / 3600;
    let minutes = (remaining % 3600) / 60;
    let seconds = remaining % 60;

    // Simple date from days since epoch (1970-01-01)
    let mut y = 1970i64;
    let mut d = days as i64;
    loop {
        let days_in_year = if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) {
            366
        } else {
            365
        };
        if d < days_in_year {
            break;
        }
        d -= days_in_year;
        y += 1;
    }
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let days_in_month = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut m = 0;
    for (i, &dim) in days_in_month.iter().enumerate() {
        if d < dim as i64 {
            m = i + 1;
            break;
        }
        d -= dim as i64;
    }
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        y,
        m,
        d + 1,
        hours,
        minutes,
        seconds
    )
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn build_smb1_negotiate() -> Vec<u8> {
    let mut pkt = Vec::new();

    // SMB1 Header
    pkt.extend_from_slice(b"\xffSMB"); // protocol
    pkt.push(0x72); // Negotiate Protocol
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // status
    pkt.push(0x18); // flags
    pkt.extend_from_slice(&0x53c8u16.to_le_bytes()); // flags2
    pkt.extend_from_slice(&0u16.to_le_bytes()); // PID high
    pkt.extend_from_slice(&[0u8; 8]); // signature
    pkt.extend_from_slice(&0u16.to_le_bytes()); // reserved
    pkt.extend_from_slice(&0u16.to_le_bytes()); // TID
    pkt.extend_from_slice(&0x1234u16.to_le_bytes()); // PID
    pkt.extend_from_slice(&0u16.to_le_bytes()); // UID
    pkt.extend_from_slice(&1u16.to_le_bytes()); // MID
    pkt.push(0); // WordCount

    let mut dialects = Vec::new();
    dialects.push(0x02);
    dialects.extend_from_slice(b"NT LM 0.12");
    dialects.push(0x00);

    pkt.extend_from_slice(&(dialects.len() as u16).to_le_bytes()); // ByteCount
    pkt.extend_from_slice(&dialects);

    let mut full = Vec::new();
    full.push(0x00); // session message
    let len = pkt.len() as u32;
    full.push(((len >> 16) & 0xff) as u8);
    full.push(((len >> 8) & 0xff) as u8);
    full.push((len & 0xff) as u8);
    full.extend_from_slice(&pkt);
    full
}

/// Check if SMB signing is required
async fn check_smb_signing(target: &str, port: u16) {
    println!();
    output::info("Checking SMB signing requirements...");

    let addr = format!("{}:{}", target, port);
    let Ok(mut stream) = timeout(Duration::from_secs(5), TcpStream::connect(&addr))
        .await
        .unwrap_or(Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "timeout",
        )))
    else {
        output::fail("Could not connect for signing check");
        return;
    };

    let negotiate = build_smb2_negotiate();
    if stream.write_all(&negotiate).await.is_err() {
        return;
    }

    let mut buf = vec![0u8; 8192];
    let Ok(n) = timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .unwrap_or(Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "timeout",
        )))
    else {
        return;
    };

    if n < 70 {
        return;
    }

    // SMB2 Negotiate response: SecurityMode at offset 4 (NetBIOS header) + 68
    let smb_data = &buf[4..n];
    if smb_data.len() >= 70 {
        let security_mode = u16::from_le_bytes([smb_data[68], smb_data[69]]);
        if security_mode & 0x02 != 0 {
            output::success("SMB signing is REQUIRED");
        } else if security_mode & 0x01 != 0 {
            output::warning("SMB signing is supported but NOT required — relay attacks possible!");
        } else {
            output::warning("SMB signing is NOT supported — relay attacks possible!");
        }
    }
}

async fn check_smb1_support(target: &str, port: u16) {
    println!();
    output::info("Checking SMBv1 protocol acceptance...");

    let addr = format!("{}:{}", target, port);
    let Ok(mut stream) = timeout(Duration::from_secs(5), TcpStream::connect(&addr))
        .await
        .unwrap_or(Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "timeout",
        )))
    else {
        output::fail("Could not connect for SMBv1 probe");
        return;
    };

    let pkt = build_smb1_negotiate();
    if stream.write_all(&pkt).await.is_err() {
        output::warning("SMBv1 probe write failed");
        return;
    }

    let mut buf = vec![0u8; 4096];
    let Ok(n) = timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .unwrap_or(Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "timeout",
        )))
    else {
        output::success("No SMBv1 response received");
        return;
    };

    if n >= 8 && &buf[4..8] == b"\xffSMB" {
        output::warning("SMBv1 negotiation accepted — legacy protocol support detected");
    } else {
        output::success("SMBv1 does not appear to be accepted");
    }
}

/// Check for SMB null session / guest access
async fn check_null_session(target: &str, port: u16) {
    println!();
    output::info("Checking for null session / guest access...");

    let addr = format!("{}:{}", target, port);
    let Ok(mut stream) = timeout(Duration::from_secs(5), TcpStream::connect(&addr))
        .await
        .unwrap_or(Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "timeout",
        )))
    else {
        output::fail("Could not connect for null session check");
        return;
    };

    // Send negotiate
    let negotiate = build_smb2_negotiate();
    if stream.write_all(&negotiate).await.is_err() {
        return;
    }

    let mut buf = vec![0u8; 8192];
    if timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .is_err()
    {
        return;
    }

    // Send session setup with null NTLMSSP auth
    // (empty credentials in NTLMSSP Type 3)
    let session_setup = build_ntlmssp_negotiate(0);
    if stream.write_all(&session_setup).await.is_err() {
        return;
    }

    let mut buf = vec![0u8; 8192];
    let Ok(n) = timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .unwrap_or(Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "timeout",
        )))
    else {
        return;
    };

    if n < 16 {
        return;
    }

    // Check NT status in SMB2 header (offset 4+8 = 12 in response after NetBIOS header)
    let smb_data = &buf[4..n];
    if smb_data.len() >= 12 {
        let nt_status = u32::from_le_bytes([smb_data[8], smb_data[9], smb_data[10], smb_data[11]]);
        match nt_status {
            0x00000000 => {
                output::success("Null session ACCEPTED — anonymous access enabled!");
                enumerate_null_shares(target).await;
            }
            0xc000006d => {
                output::fail("Null session REJECTED — STATUS_LOGON_FAILURE");
            }
            0xc0000022 => {
                output::fail("Null session REJECTED — STATUS_ACCESS_DENIED");
            }
            0xc0000072 => {
                output::fail("Account DISABLED");
            }
            0xc000006e => {
                output::fail("Account restrictions prevent login");
            }
            0xc0000016 | 0x00000016 => {
                output::info("STATUS_MORE_PROCESSING_REQUIRED — multi-step auth in progress");
            }
            _ => {
                output::info(&format!("NT Status: 0x{:08x}", nt_status));
            }
        }
    }
}

async fn enumerate_null_shares(target: &str) {
    output::info("Attempting anonymous share enumeration...");

    let cmd = Command::new("smbclient")
        .arg("-N")
        .arg("-L")
        .arg(format!("//{}", target))
        .output();

    let Ok(out) = timeout(Duration::from_secs(8), cmd).await else {
        output::warning("Anonymous share enumeration timed out");
        return;
    };
    let Ok(out) = out else {
        output::warning("Could not run smbclient for share enumeration");
        return;
    };

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        if stderr.to_ascii_lowercase().contains("not found") {
            output::warning("smbclient is not installed — cannot list shares automatically");
        } else {
            output::warning("Anonymous share enumeration command failed");
            if !stderr.trim().is_empty() {
                output::kv("smbclient stderr", stderr.trim());
            }
        }
        return;
    }

    let stdout = String::from_utf8_lossy(&out.stdout);
    let shares = parse_smbclient_share_list(&stdout);
    if shares.is_empty() {
        output::warning("No shares parsed from smbclient output");
        return;
    }

    output::success(&format!(
        "Anonymous share listing returned {} entries",
        shares.len()
    ));
    for share in shares {
        output::kv("Share", &share);
    }
}

fn parse_smbclient_share_list(output: &str) -> Vec<String> {
    let mut shares = Vec::new();
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("Sharename") || trimmed.starts_with("---") {
            continue;
        }

        // Typical format: "IPC$            IPC       Remote IPC"
        let cols: Vec<&str> = trimmed.split_whitespace().collect();
        if cols.len() >= 2 {
            let share = cols[0];
            let share_type = cols[1];
            if matches!(share_type, "Disk" | "IPC" | "Printer") {
                shares.push(format!("{} ({})", share, share_type));
            }
        }
    }

    shares.sort();
    shares.dedup();
    shares
}

async fn smbclient_list_shares(
    target: &str,
    username: &str,
    password: Option<&str>,
    ntlm_hash: Option<&str>,
    kerberos: bool,
) -> Result<Vec<String>> {
    let mut cmd = Command::new("smbclient");
    cmd.arg("-L").arg(format!("//{}", target));

    if kerberos {
        cmd.arg("-k");
        cmd.arg("-U").arg(username);
    } else if let Some(hash) = ntlm_hash {
        let hash_fmt = if hash.contains(':') {
            hash.to_string()
        } else {
            format!("aad3b435b51404eeaad3b435b51404ee:{}", hash)
        };
        cmd.arg("-U").arg(format!("{}%{}", username, hash_fmt));
        cmd.arg("--pw-nt-hash");
    } else if let Some(pass) = password {
        cmd.arg("-U").arg(format!("{}%{}", username, pass));
    } else {
        cmd.arg("-N");
    }

    let out = timeout(Duration::from_secs(10), cmd.output()).await??;
    if !out.status.success() {
        anyhow::bail!(
            "smbclient share list failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    Ok(parse_smbclient_share_list(&stdout))
}

async fn list_share_roots(
    target: &str,
    username: &str,
    password: Option<&str>,
    ntlm_hash: Option<&str>,
    kerberos: bool,
    shares: &[String],
) {
    let skip = ["IPC$", "PRINT$"];
    for share in shares.iter().take(16) {
        let share_name = share.split_whitespace().next().unwrap_or(share);
        if skip.contains(&share_name) {
            continue;
        }

        let mut cmd = Command::new("smbclient");
        cmd.arg(format!("//{}/{}", target, share_name))
            .arg("-c")
            .arg("ls");

        if kerberos {
            cmd.arg("-k").arg("-U").arg(username);
        } else if let Some(hash) = ntlm_hash {
            let hash_fmt = if hash.contains(':') {
                hash.to_string()
            } else {
                format!("aad3b435b51404eeaad3b435b51404ee:{}", hash)
            };
            cmd.arg("-U").arg(format!("{}%{}", username, hash_fmt));
            cmd.arg("--pw-nt-hash");
        } else if let Some(pass) = password {
            cmd.arg("-U").arg(format!("{}%{}", username, pass));
        } else {
            cmd.arg("-N");
        }

        match timeout(Duration::from_secs(8), cmd.output()).await {
            Ok(Ok(out)) if out.status.success() => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let entries = parse_smbclient_ls_entries(&stdout);
                if entries.is_empty() {
                    output::kv(
                        &format!("Share {}", share_name),
                        "accessible (no visible entries)",
                    );
                } else {
                    let sample = entries
                        .iter()
                        .take(5)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ");
                    output::kv(
                        &format!("Share {}", share_name),
                        &format!("accessible ({} entries: {})", entries.len(), sample),
                    );
                }
            }
            Ok(Ok(out)) => {
                let stderr = String::from_utf8_lossy(&out.stderr).to_ascii_lowercase();
                let stdout = String::from_utf8_lossy(&out.stdout).to_ascii_lowercase();
                let combined = format!("{} {}", stderr, stdout);
                let status = if combined.contains("nt_status_access_denied")
                    || combined.contains("access denied")
                {
                    "access denied"
                } else if combined.contains("nt_status_logon_failure")
                    || combined.contains("logon failure")
                {
                    "logon failure"
                } else if combined.contains("bad network name") || combined.contains("not found") {
                    "share not found"
                } else {
                    "not readable"
                };
                output::kv(&format!("Share {}", share_name), status);
            }
            _ => {
                output::kv(&format!("Share {}", share_name), "listing failed");
            }
        }
    }
}

fn parse_smbclient_ls_entries(output: &str) -> Vec<String> {
    let mut entries = Vec::new();
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("blocks of size") {
            continue;
        }
        let cols: Vec<&str> = trimmed.split_whitespace().collect();
        if cols.is_empty() {
            continue;
        }
        let name = cols[0];
        if matches!(name, "." | "..") {
            continue;
        }

        // Mark directories when smbclient indicates "D" in attributes column.
        let is_dir = cols.iter().any(|c| *c == "D");
        if is_dir {
            entries.push(format!("{}/", name));
        } else {
            entries.push(name.to_string());
        }
    }
    entries.sort();
    entries.dedup();
    entries
}

async fn enumerate_sysvol_gpp(
    target: &str,
    username: &str,
    password: Option<&str>,
    ntlm_hash: Option<&str>,
    kerberos: bool,
    shares: &[String],
) -> Vec<AuthFinding> {
    let sysvol_present = shares.iter().any(|s| {
        s.split_whitespace()
            .next()
            .is_some_and(|name| name.eq_ignore_ascii_case("SYSVOL"))
    });
    if !sysvol_present {
        output::info("SYSVOL share not accessible via current SMB auth method");
        return Vec::new();
    }

    let loot_dir = PathBuf::from("sysvol_loot");
    if let Err(e) = std::fs::create_dir_all(&loot_dir) {
        output::warning(&format!("Failed to create SYSVOL loot dir: {}", e));
        return Vec::new();
    }

    output::info("Attempting SYSVOL XML loot for GPP credential discovery");
    let mut cmd = Command::new("smbclient");
    cmd.arg(format!("//{}/SYSVOL", target))
        .arg("-c")
        .arg(format!(
            "lcd {}; prompt OFF; recurse ON; mask *.xml; mget *",
            loot_dir.display()
        ));
    add_smbclient_auth(&mut cmd, username, password, ntlm_hash, kerberos);

    let out = match timeout(Duration::from_secs(45), cmd.output()).await {
        Err(_) => {
            output::warning("SYSVOL XML loot timed out");
            return Vec::new();
        }
        Ok(Err(e)) => {
            output::warning(&format!("Could not run smbclient for SYSVOL loot ({})", e));
            return Vec::new();
        }
        Ok(Ok(out)) => out,
    };

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        if !stderr.trim().is_empty() {
            output::warning(&format!("SYSVOL loot failed: {}", stderr.trim()));
        } else {
            output::warning("SYSVOL loot failed");
        }
        return Vec::new();
    }

    let xml_files = collect_xml_files(&loot_dir);
    if xml_files.is_empty() {
        output::warning("SYSVOL loot completed but no XML files were downloaded");
        return Vec::new();
    }
    output::success(&format!("Downloaded {} SYSVOL XML files", xml_files.len()));

    let findings = scan_gpp_cpasswords(&xml_files);
    if findings.is_empty() {
        output::info("No GPP cpassword values found in looted SYSVOL XML files");
        return Vec::new();
    }

    output::warning(&format!(
        "Potential GPP credentials found in {} files",
        findings.len()
    ));
    for finding in findings.iter().take(10) {
        output::kv(
            "GPP",
            &format!(
                "{} | user={} | password={}",
                finding.path,
                finding.username.as_deref().unwrap_or("<unknown>"),
                finding.password.as_deref().unwrap_or("<undecoded>")
            ),
        );
    }

    findings
        .into_iter()
        .map(|finding| AuthFinding {
            id: "SMB-GPP-CPASSWORD".to_string(),
            severity: "high".to_string(),
            title: "GPP cpassword recovered from SYSVOL".to_string(),
            evidence: format!(
                "{} | user={} | password={}",
                finding.path,
                finding.username.as_deref().unwrap_or("<unknown>"),
                finding.password.as_deref().unwrap_or("<undecoded>")
            ),
            recommendation:
                "Remove legacy Group Policy Preference passwords and rotate any exposed accounts."
                    .to_string(),
        })
        .collect()
}

fn add_smbclient_auth(
    cmd: &mut Command,
    username: &str,
    password: Option<&str>,
    ntlm_hash: Option<&str>,
    kerberos: bool,
) {
    if kerberos {
        cmd.arg("-k").arg("-U").arg(username);
    } else if let Some(hash) = ntlm_hash {
        let hash_fmt = if hash.contains(':') {
            hash.to_string()
        } else {
            format!("aad3b435b51404eeaad3b435b51404ee:{}", hash)
        };
        cmd.arg("-U").arg(format!("{}%{}", username, hash_fmt));
        cmd.arg("--pw-nt-hash");
    } else if let Some(pass) = password {
        cmd.arg("-U").arg(format!("{}%{}", username, pass));
    } else {
        cmd.arg("-N");
    }
}

fn collect_xml_files(base: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut pending = vec![base.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            if meta.is_dir() {
                pending.push(path);
                continue;
            }
            if meta.is_file()
                && path
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("xml"))
            {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

struct GppFinding {
    path: String,
    username: Option<String>,
    password: Option<String>,
}

fn scan_gpp_cpasswords(files: &[PathBuf]) -> Vec<GppFinding> {
    let mut findings = Vec::new();
    for path in files {
        let Ok(content) = std::fs::read_to_string(path) else {
            continue;
        };
        let Some(cpassword) = extract_xml_attr(&content, "cpassword") else {
            continue;
        };
        let username = extract_xml_attr(&content, "userName")
            .or_else(|| extract_xml_attr(&content, "username"))
            .or_else(|| extract_xml_attr(&content, "newName"));
        findings.push(GppFinding {
            path: path.display().to_string(),
            username,
            password: decrypt_gpp_cpassword(&cpassword),
        });
    }
    findings
}

fn extract_xml_attr(content: &str, attr: &str) -> Option<String> {
    let patterns = [format!(r#"{}=""#, attr), format!(r#"{} = ""#, attr)];
    for pattern in patterns {
        if let Some(start) = content.find(&pattern) {
            let rest = &content[start + pattern.len()..];
            if let Some(end) = rest.find('"') {
                let value = rest[..end].trim();
                if !value.is_empty() {
                    return Some(value.to_string());
                }
            }
        }
    }
    None
}

fn decrypt_gpp_cpassword(cpassword: &str) -> Option<String> {
    const GPP_KEY: [u8; 32] = [
        0x4e, 0x99, 0x06, 0xe8, 0xfc, 0xb6, 0x6c, 0xc9, 0xfa, 0xf4, 0x93, 0x10, 0x62, 0x0f, 0xfe,
        0xe8, 0xf4, 0x96, 0xe8, 0x06, 0xcc, 0x05, 0x79, 0x90, 0x20, 0x9b, 0x09, 0xa4, 0x33, 0xb6,
        0x6c, 0x1b,
    ];
    let mut padded = cpassword.trim().to_string();
    while !padded.len().is_multiple_of(4) {
        padded.push('=');
    }

    let mut ciphertext = base64::engine::general_purpose::STANDARD
        .decode(padded.as_bytes())
        .ok()?;
    let iv = [0u8; 16];
    let decrypted = Decryptor::<Aes256>::new(&GPP_KEY.into(), &iv.into())
        .decrypt_padded_mut::<Pkcs7>(&mut ciphertext)
        .ok()?;

    if decrypted.len() % 2 != 0 {
        return None;
    }
    let utf16 = decrypted
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect::<Vec<_>>();
    Some(
        String::from_utf16_lossy(&utf16)
            .trim_end_matches('\u{0}')
            .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::extract_xml_attr;

    #[test]
    fn extracts_xml_attribute_values() {
        let xml = r#"<User userName="alice" cpassword="AQID" />"#;
        assert_eq!(extract_xml_attr(xml, "userName").as_deref(), Some("alice"));
        assert_eq!(extract_xml_attr(xml, "cpassword").as_deref(), Some("AQID"));
    }
}
