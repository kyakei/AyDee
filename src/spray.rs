use anyhow::Result;
use std::collections::HashSet;
use std::io::ErrorKind;
use tokio::process::Command;
use tokio::time::{sleep, timeout, Duration};

use crate::auth_recon::AuthFinding;
use crate::output;

pub async fn run_smb_password_spray(
    target: &str,
    domain: Option<&str>,
    spray_password: &str,
    explicit_user: Option<&str>,
    discovered_users: &[String],
    userlist_path: Option<&str>,
    max_users: usize,
    delay_ms: u64,
) -> Result<Vec<AuthFinding>> {
    output::section("PASSWORD SPRAY");
    output::info("Attempting SMB password spray with explicit operator-supplied password");

    let users = build_user_list(explicit_user, discovered_users, userlist_path, max_users).await?;
    if users.is_empty() {
        output::warning("Password spray skipped: no candidate usernames available");
        return Ok(Vec::new());
    }

    output::warning(&format!(
        "Spraying {} users against {} over SMB. Validate lockout policy before reuse.",
        users.len(),
        target
    ));

    let mut findings = Vec::new();
    let mut successes = Vec::new();
    let mut found_tool = false;

    for (idx, user) in users.iter().enumerate() {
        match try_smb_login(target, domain, user, spray_password).await {
            SprayAttempt::Success => {
                found_tool = true;
                output::success(&format!("VALID SMB LOGIN: {}", user));
                successes.push(user.clone());
            }
            SprayAttempt::Invalid => {
                found_tool = true;
            }
            SprayAttempt::Locked => {
                found_tool = true;
                output::warning(&format!("Potential lockout/disabled response for {}", user));
            }
            SprayAttempt::ToolMissing => {
                output::warning(
                    "No spray-capable backend found (tried: nxc, netexec, crackmapexec, smbclient)",
                );
                return Ok(Vec::new());
            }
            SprayAttempt::Other(detail) => {
                found_tool = true;
                output::kv("Spray Error", &format!("{}: {}", user, detail));
            }
        }

        if delay_ms > 0 && idx + 1 < users.len() {
            sleep(Duration::from_millis(delay_ms)).await;
        }
    }

    if !found_tool {
        output::warning("Password spray could not execute because SMB tooling was unavailable");
        return Ok(findings);
    }

    if successes.is_empty() {
        output::warning("Password spray completed with no confirmed SMB logins");
    } else {
        let evidence = successes.join(", ");
        findings.push(AuthFinding {
            id: "SPRAY-SMB-SUCCESS".to_string(),
            severity: "high".to_string(),
            title: "Password spray identified valid SMB credentials".to_string(),
            evidence,
            recommendation:
                "Reset exposed credentials if unauthorized and review lockout/MFA controls."
                    .to_string(),
        });
    }

    Ok(findings)
}

async fn build_user_list(
    explicit_user: Option<&str>,
    discovered_users: &[String],
    userlist_path: Option<&str>,
    max_users: usize,
) -> Result<Vec<String>> {
    let mut users = Vec::new();

    if let Some(user) = explicit_user {
        users.push(normalize_user(user));
    }
    users.extend(discovered_users.iter().map(|u| normalize_user(u)));

    if let Some(path) = userlist_path {
        let content = tokio::fs::read_to_string(path).await?;
        users.extend(
            content
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(normalize_user),
        );
    }

    let mut seen = HashSet::new();
    users.retain(|u| {
        !u.is_empty()
            && !u.ends_with('$')
            && !u.eq_ignore_ascii_case("krbtgt")
            && seen.insert(u.to_ascii_lowercase())
    });
    users.sort_by_key(|u| u.to_ascii_lowercase());
    if users.len() > max_users {
        users.truncate(max_users);
    }
    Ok(users)
}

fn normalize_user(user: &str) -> String {
    user.trim()
        .trim_end_matches('$')
        .split('@')
        .next()
        .unwrap_or(user)
        .rsplit('\\')
        .next()
        .unwrap_or(user)
        .trim()
        .to_string()
}

enum SprayAttempt {
    Success,
    Invalid,
    Locked,
    ToolMissing,
    Other(String),
}

async fn try_smb_login(
    target: &str,
    domain: Option<&str>,
    username: &str,
    password: &str,
) -> SprayAttempt {
    let mut saw_backend = false;
    let mut last_other: Option<String> = None;

    for bin in ["nxc", "netexec", "crackmapexec"] {
        match try_cme_style_login(bin, target, domain, username, password).await {
            SprayAttempt::ToolMissing => continue,
            SprayAttempt::Other(detail) => {
                saw_backend = true;
                last_other = Some(format!("{}: {}", bin, detail));
                continue;
            }
            result => return result,
        }
    }

    match try_smbclient_login(target, domain, username, password).await {
        SprayAttempt::ToolMissing if saw_backend => {
            SprayAttempt::Other(last_other.unwrap_or_else(|| "backend error".to_string()))
        }
        SprayAttempt::ToolMissing => SprayAttempt::ToolMissing,
        SprayAttempt::Other(detail) => {
            if let Some(prev) = last_other {
                SprayAttempt::Other(format!("{} | smbclient: {}", prev, detail))
            } else {
                SprayAttempt::Other(detail)
            }
        }
        result => result,
    }
}

async fn try_cme_style_login(
    bin: &str,
    target: &str,
    domain: Option<&str>,
    username: &str,
    password: &str,
) -> SprayAttempt {
    let mut cmd = Command::new(bin);
    cmd.arg("smb")
        .arg(target)
        .arg("-u")
        .arg(username)
        .arg("-p")
        .arg(password);
    if let Some(domain) = domain {
        cmd.arg("-d").arg(domain);
    }

    let out = match timeout(Duration::from_secs(15), cmd.output()).await {
        Err(_) => return SprayAttempt::Other("timed out".to_string()),
        Ok(Err(e)) if e.kind() == ErrorKind::NotFound => return SprayAttempt::ToolMissing,
        Ok(Err(e)) => return SprayAttempt::Other(e.to_string()),
        Ok(Ok(out)) => out,
    };

    classify_merged_output(
        &String::from_utf8_lossy(&out.stdout),
        &String::from_utf8_lossy(&out.stderr),
        username,
    )
}

async fn try_smbclient_login(
    target: &str,
    domain: Option<&str>,
    username: &str,
    password: &str,
) -> SprayAttempt {
    let mut cmd = Command::new("smbclient");
    cmd.arg("-g")
        .arg("-L")
        .arg(format!("//{}", target))
        .arg("-U")
        .arg(format!("{}%{}", username, password));
    if let Some(domain) = domain {
        cmd.arg("-W").arg(domain);
    }

    let out = match timeout(Duration::from_secs(12), cmd.output()).await {
        Err(_) => return SprayAttempt::Other("timed out".to_string()),
        Ok(Err(e)) if e.kind() == ErrorKind::NotFound => return SprayAttempt::ToolMissing,
        Ok(Err(e)) => return SprayAttempt::Other(e.to_string()),
        Ok(Ok(out)) => out,
    };

    if out.status.success() {
        return SprayAttempt::Success;
    }

    classify_merged_output(
        &String::from_utf8_lossy(&out.stdout),
        &String::from_utf8_lossy(&out.stderr),
        username,
    )
}

fn classify_merged_output(stdout: &str, stderr: &str, username: &str) -> SprayAttempt {
    let combined = format!(
        "{} {}",
        stderr.to_ascii_lowercase(),
        stdout.to_ascii_lowercase()
    );
    let user = username.to_ascii_lowercase();

    if combined.contains("account locked")
        || combined.contains("account disabled")
        || combined.contains("password must change")
        || combined.contains("status_account_locked_out")
    {
        return SprayAttempt::Locked;
    }

    if combined.contains("logon failure")
        || combined.contains("status_logon_failure")
        || combined.contains("wrong password")
        || combined.contains("access denied")
    {
        return SprayAttempt::Invalid;
    }

    if combined.contains("pwn3d")
        || combined.contains("status_success")
        || (combined.contains("[+]") && combined.contains(&user))
    {
        return SprayAttempt::Success;
    }

    SprayAttempt::Other(combined.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::normalize_user;

    #[test]
    fn normalizes_common_username_forms() {
        assert_eq!(normalize_user("CORP\\alice"), "alice");
        assert_eq!(normalize_user("alice@corp.local"), "alice");
        assert_eq!(normalize_user("dc01$"), "dc01");
    }
}
