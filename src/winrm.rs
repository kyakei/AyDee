use anyhow::Result;
use std::io::ErrorKind;
use tokio::process::Command;
use tokio::time::{timeout, Duration};

use crate::output;

pub async fn run_authenticated(
    target: &str,
    username: &str,
    password: Option<&str>,
    ntlm_hash: Option<&str>,
    kerberos: bool,
) -> Result<bool> {
    output::section("WINRM AUTHENTICATED RECON");
    output::info("Attempting WinRM credential validation");

    let mut attempted = false;
    let mut any_success = false;
    let mut found_tool = false;

    if let Some(pass) = password {
        attempted = true;
        let (ok, found) = run_method(target, username, &[("-p", pass)], &[]).await;
        found_tool |= found;
        any_success |= ok;
    }

    if let Some(hash) = ntlm_hash {
        attempted = true;
        let (ok, found) = run_method(target, username, &[("-H", hash)], &[]).await;
        found_tool |= found;
        any_success |= ok;
    }

    if kerberos {
        attempted = true;
        let (ok, found) = run_method(target, username, &[], &["-k", "--use-kcache"]).await;
        found_tool |= found;
        any_success |= ok;
    }

    if !attempted {
        output::warning("No WinRM auth method provided (--password, --ntlm, or -k/--kerberos)");
    } else if !found_tool {
        output::warning("No WinRM tooling found (tried: nxc, netexec, crackmapexec)");
    } else if any_success {
        output::success("WinRM credential validation succeeded");
    } else {
        output::warning("WinRM auth methods were attempted, but none succeeded");
    }

    Ok(any_success)
}

async fn run_method(
    target: &str,
    username: &str,
    kv_args: &[(&str, &str)],
    flag_args: &[&str],
) -> (bool, bool) {
    let bins = ["nxc", "netexec", "crackmapexec"];
    let mut found_any = false;

    for bin in bins {
        let mut cmd = Command::new(bin);
        cmd.arg("winrm").arg(target).arg("-u").arg(username);
        for (k, v) in kv_args {
            cmd.arg(k).arg(v);
        }
        for f in flag_args {
            cmd.arg(f);
        }

        let out = match timeout(Duration::from_secs(45), cmd.output()).await {
            Err(_) => {
                found_any = true;
                output::warning(&format!("{} winrm check timed out after 45s", bin));
                continue;
            }
            Ok(Err(e)) if e.kind() == ErrorKind::NotFound => continue,
            Ok(Err(e)) => {
                found_any = true;
                output::warning(&format!("Could not run {} ({})", bin, e));
                continue;
            }
            Ok(Ok(out)) => out,
        };

        found_any = true;
        let mut merged = String::new();
        merged.push_str(&String::from_utf8_lossy(&out.stdout));
        merged.push('\n');
        merged.push_str(&String::from_utf8_lossy(&out.stderr));
        let merged_trim = merged.trim();

        if looks_success(merged_trim, username) {
            output::success(&format!("{} winrm auth succeeded", bin));
            if !merged_trim.is_empty() {
                output::kv("WinRM Output", &trim_for_display(merged_trim, 220));
            }
            return (true, true);
        }

        if !merged_trim.is_empty() {
            output::warning(&format!("{} winrm auth failed", bin));
            output::kv("WinRM Output", &trim_for_display(merged_trim, 220));
        }
    }

    (false, found_any)
}

fn looks_success(out: &str, username: &str) -> bool {
    let l = out.to_ascii_lowercase();
    let u = username.to_ascii_lowercase();

    if l.contains("status_logon_failure")
        || l.contains("access is denied")
        || l.contains("authentication failed")
        || l.contains("auth failed")
        || l.contains("invalid credentials")
    {
        return false;
    }

    l.contains("pwn3d") || l.contains("status_success") || (l.contains("[+]") && l.contains(&u))
}

fn trim_for_display(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let clipped = s.chars().take(max).collect::<String>();
    format!("{} <snip>", clipped)
}
