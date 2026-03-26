use aes::cipher::{BlockDecryptMut, KeyIvInit};
use anyhow::Result;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

use crate::types::{Finding, ModuleResult, Severity, StageTimer};
use crate::ui;

#[allow(dead_code)]
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

// ── Null session ────────────────────────────────────────────────────────────

/// Run SMB null session enumeration.
#[allow(dead_code)]
pub async fn run_null_session(target: &str) -> Result<ModuleResult> {
    ui::section("SMB NULL SESSION");
    let timer = StageTimer::start();
    let spin = ui::spinner("SMB-NULL");
    let mut result = ModuleResult::new("smb-null");

    spin.set_message("testing anonymous access...");

    // Try null session with smbclient
    let out = timeout(
        Duration::from_secs(15),
        Command::new("smbclient")
            .args(["-N", "-L", target, "--no-pass"])
            .output(),
    )
    .await;

    match out {
        Ok(Ok(output)) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let combined = format!("{}\n{}", stdout, stderr);
            ui::verbose_output("smbclient", &combined);

            if combined.contains("Sharename") || combined.contains("IPC$") {
                ui::success("Null session accepted — share listing available");

                let shares = parse_smbclient_shares(&combined);
                if !shares.is_empty() {
                    ui::info(&format!("{} share(s) visible:", shares.len()));
                    for (name, stype, comment) in &shares {
                        ui::kv(&format!("  {}", name), &format!("{} — {}", stype, comment));
                    }
                }

                let finding = Finding::new(
                    "smb",
                    "SMB-001",
                    Severity::Medium,
                    "SMB null session permitted",
                )
                .with_description("Anonymous SMB access is allowed, enabling share enumeration")
                .with_recommendation("Disable null session access via RestrictAnonymous registry key")
                .with_mitre("T1021.002");
                result.findings.push(finding);
            } else if combined.to_lowercase().contains("nt_status_access_denied")
                || combined.to_lowercase().contains("nt_status_logon_failure")
            {
                ui::info("Null session rejected (expected)");
            } else {
                ui::info(&format!("SMB response: {}", combined.lines().next().unwrap_or("unknown")));
            }
        }
        Ok(Err(e)) => {
            ui::warning(&format!("smbclient not available: {}", e));
        }
        Err(_) => {
            ui::warning("SMB null session test timed out");
        }
    }

    // Check SMB signing
    spin.set_message("checking SMB signing...");
    check_smb_signing(target, &mut result).await;

    ui::finish_spinner(&spin, "null session check complete");
    ui::stage_done("SMB NULL", "done", &timer.elapsed_pretty());

    result = result.success(timer.elapsed());
    Ok(result)
}

// ── Authenticated SMB ───────────────────────────────────────────────────────

/// Run authenticated SMB enumeration.
pub async fn run_authenticated(
    target: &str,
    domain: &str,
    username: &str,
    password: &str,
    ntlm: Option<&str>,
    tags: &[String],
) -> Result<ModuleResult> {
    ui::section("SMB AUTHENTICATED");
    let timer = StageTimer::start();
    let spin = ui::spinner("SMB-AUTH");
    let mut result = ModuleResult::new("smb-auth");

    let should_run = |tag: &str| -> bool {
        tags.is_empty() || tags.iter().any(|t| t.eq_ignore_ascii_case(tag))
    };

    // List shares
    spin.set_message("listing shares...");
    let shares = list_shares_authenticated(target, domain, username, password, ntlm).await;

    match shares {
        Ok(share_list) => {
            if share_list.is_empty() {
                ui::info("No shares visible");
            } else {
                ui::success(&format!("{} share(s) accessible:", share_list.len()));
                for (name, stype, comment) in &share_list {
                    ui::kv(&format!("  {}", name), &format!("{} — {}", stype, comment));
                }

                // Check for interesting shares
                let interesting = ["ADMIN$", "C$", "NETLOGON", "SYSVOL"];
                let admin_shares: Vec<_> = share_list
                    .iter()
                    .filter(|(n, _, _)| interesting.iter().any(|i| n.eq_ignore_ascii_case(i)))
                    .collect();

                if admin_shares.iter().any(|(n, _, _)| n.eq_ignore_ascii_case("ADMIN$") || n == "C$") {
                    let finding = Finding::new(
                        "smb",
                        "SMB-002",
                        Severity::High,
                        "Administrative share access (ADMIN$/C$)",
                    )
                    .with_description("Current credentials have access to administrative shares, indicating local admin privileges")
                    .with_recommendation("Restrict local admin access; implement LAPS and tiered admin model")
                    .with_mitre("T1021.002");
                    result.findings.push(finding);
                    ui::warning("Administrative share access detected (ADMIN$/C$)!");
                }
            }
        }
        Err(e) => {
            ui::warning(&format!("Share enumeration failed: {}", e));
        }
    }

    // SYSVOL GPP looting
    if should_run("gpp") || should_run("sysvol") {
        spin.set_message("checking SYSVOL for GPP passwords...");
        enumerate_sysvol_gpp(target, domain, username, password, ntlm, &mut result).await;
    }

    ui::finish_spinner(&spin, "authenticated enumeration complete");
    ui::stage_done("SMB AUTH", &format!("{} findings", result.findings.len()), &timer.elapsed_pretty());

    result = result.success(timer.elapsed());
    Ok(result)
}

// ── Share listing ───────────────────────────────────────────────────────────

async fn list_shares_authenticated(
    target: &str,
    domain: &str,
    username: &str,
    password: &str,
    ntlm: Option<&str>,
) -> Result<Vec<(String, String, String)>> {
    let user_arg = format!("{}\\{}", domain.split('.').next().unwrap_or(domain), username);

    let mut args = vec!["-gL".to_string(), target.to_string()];

    if let Some(hash) = ntlm {
        args.extend(["--pw-nt-hash".to_string(), "-U".to_string(), format!("{}%{}", user_arg, hash)]);
    } else {
        args.extend(["-U".to_string(), format!("{}%{}", user_arg, password)]);
    }

    let output = timeout(
        Duration::from_secs(20),
        Command::new("smbclient").args(&args).output(),
    )
    .await??;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    ui::verbose_output("smbclient", &stdout);
    ui::verbose_output("smbclient", &stderr);
    Ok(parse_smbclient_shares(&stdout))
}

fn parse_smbclient_shares(output: &str) -> Vec<(String, String, String)> {
    let mut shares = Vec::new();
    for line in output.lines() {
        // smbclient -g format: Disk|ShareName|Comment
        let parts: Vec<&str> = line.split('|').collect();
        if parts.len() >= 2 {
            let stype = parts[0].trim().to_string();
            let name = parts[1].trim().to_string();
            let comment = if parts.len() > 2 {
                parts[2].trim().to_string()
            } else {
                String::new()
            };
            if stype == "Disk" || stype == "IPC" || stype == "Printer" {
                shares.push((name, stype, comment));
            }
        }
    }
    shares
}

// ── SYSVOL GPP ──────────────────────────────────────────────────────────────

async fn enumerate_sysvol_gpp(
    target: &str,
    domain: &str,
    username: &str,
    password: &str,
    ntlm: Option<&str>,
    result: &mut ModuleResult,
) {
    let user_arg = format!(
        "{}\\{}",
        domain.split('.').next().unwrap_or(domain),
        username
    );
    let unc = format!("\\\\{}\\SYSVOL", target);

    let mut args = vec![unc.clone(), "-c".to_string(), "recurse; ls".to_string()];
    if let Some(hash) = ntlm {
        args.extend(["--pw-nt-hash".to_string(), "-U".to_string(), format!("{}%{}", user_arg, hash)]);
    } else {
        args.extend(["-U".to_string(), format!("{}%{}", user_arg, password)]);
    }

    let output = timeout(
        Duration::from_secs(30),
        Command::new("smbclient").args(&args).output(),
    )
    .await;

    let Ok(Ok(out)) = output else { return };
    let stdout = String::from_utf8_lossy(&out.stdout);
    ui::verbose_output("smbclient-sysvol", &stdout);

    // Look for Groups.xml or other GPP XML files
    let gpp_files = [
        "Groups.xml",
        "Services.xml",
        "Scheduledtasks.xml",
        "DataSources.xml",
        "Drives.xml",
    ];

    let mut found_gpp = false;
    for line in stdout.lines() {
        for gpp_file in &gpp_files {
            if line.to_ascii_lowercase().contains(&gpp_file.to_ascii_lowercase()) {
                ui::warning(&format!("GPP file found: {}", line.trim()));
                found_gpp = true;
            }
        }
    }

    if found_gpp {
        let finding = Finding::new(
            "smb",
            "GPP-001",
            Severity::High,
            "Group Policy Preference XML files found in SYSVOL",
        )
        .with_description("GPP XML files may contain cpassword values that can be decrypted with the publicly known AES key (MS14-025)")
        .with_recommendation("Remove GPP XML files with embedded credentials; use LAPS instead")
        .with_mitre("T1552.006");
        result.findings.push(finding);
    }
}

/// Decrypt a GPP cpassword value.
#[allow(dead_code)]
pub fn decrypt_gpp_password(cpassword: &str) -> Option<String> {
    // Microsoft's published AES-256-CBC key for GPP
    let key: [u8; 32] = [
        0x4e, 0x99, 0x06, 0xe8, 0xfc, 0xb6, 0x6c, 0xc9, 0xfa, 0xf4, 0x93, 0x10, 0x62, 0x0f,
        0xfe, 0xe8, 0xf4, 0x96, 0xe8, 0x06, 0xcc, 0x05, 0x79, 0x90, 0x20, 0x9b, 0x09, 0xa4,
        0x33, 0xb6, 0x6c, 0x1b,
    ];
    let iv = [0u8; 16];

    // Pad the base64 string
    let mut padded = cpassword.replace('-', "+").replace('_', "/");
    while padded.len() % 4 != 0 {
        padded.push('=');
    }

    let ciphertext = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &padded).ok()?;
    if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
        return None;
    }

    let mut buf = ciphertext.clone();
    let decryptor = Aes256CbcDec::new_from_slices(&key, &iv).ok()?;
    let decrypted = decryptor.decrypt_padded_mut::<aes::cipher::block_padding::Pkcs7>(&mut buf).ok()?;

    String::from_utf8(decrypted.to_vec()).ok()
}

// ── SMB signing check ───────────────────────────────────────────────────────

async fn check_smb_signing(target: &str, result: &mut ModuleResult) {
    // Use nxc/netexec/crackmapexec to check SMB signing
    let tools = ["nxc", "netexec", "crackmapexec"];

    for tool in tools {
        let out = timeout(
            Duration::from_secs(10),
            Command::new(tool)
                .args(["smb", target])
                .output(),
        )
        .await;

        if let Ok(Ok(output)) = out {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let combined = format!("{}\n{}", stdout, String::from_utf8_lossy(&output.stderr));
            ui::verbose_output(tool, &combined);

            if combined.to_lowercase().contains("signing:false")
                || combined.to_lowercase().contains("signing: false")
                || combined.contains("signing:False")
            {
                ui::warning("SMB signing is NOT enforced");
                let finding = Finding::new(
                    "smb",
                    "SMB-003",
                    Severity::High,
                    "SMB signing not enforced",
                )
                .with_description("SMB signing is not required, making the host vulnerable to NTLM relay attacks")
                .with_recommendation("Enable and require SMB signing via Group Policy")
                .with_mitre("T1557.001");
                result.findings.push(finding);
            } else if combined.to_lowercase().contains("signing:true")
                || combined.to_lowercase().contains("signing: true")
            {
                ui::success("SMB signing is enforced");
            }
            return;
        }
    }

    ui::info("SMB signing check: no compatible tool found (nxc/netexec/crackmapexec)");
}
