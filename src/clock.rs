use std::io::IsTerminal;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::time::timeout;

use crate::ui;

/// Sync clock with the target DC. Prompts the user first, then handles
/// sudo escalation if not already root.
pub async fn sync_clock(target: &str, non_interactive: bool) {
    ui::section("CLOCK SYNC");

    // Ask user if they want to sync
    if !non_interactive && std::io::stdin().is_terminal() {
        let confirm = dialoguer::Confirm::new()
            .with_prompt("  Sync local clock with target DC?")
            .default(true)
            .interact_opt()
            .unwrap_or(Some(false))
            .unwrap_or(false);
        if !confirm {
            ui::stage_skip("CLOCK", "user declined");
            return;
        }
    }

    let spin = ui::spinner("CLOCK");
    spin.set_message(format!("syncing with {} ...", target));

    // Detect if we're already root
    let is_root = unsafe { libc::geteuid() } == 0;

    if is_root {
        // Already root — just run directly
        if try_sync_direct(target, &spin).await {
            return;
        }
        ui::finish_spinner_fail(&spin, "clock sync failed — no compatible tool found");
        ui::info("Install ntpdate or rdate");
        return;
    }

    // Not root — try without sudo first (will likely fail but fast check)
    if try_sync_direct(target, &spin).await {
        return;
    }

    // Need sudo — ask for password
    spin.finish_and_clear();
    let password = match rpassword::prompt_password("  [sudo] password: ") {
        Ok(p) if !p.is_empty() => p,
        _ => {
            ui::warning("No password provided — skipping clock sync");
            ui::info("Kerberos may fail due to clock skew (>5 min difference)");
            return;
        }
    };

    let spin = ui::spinner("CLOCK");
    spin.set_message(format!("syncing with {} (sudo) ...", target));

    if try_sync_sudo(target, &password, &spin).await {
        return;
    }

    ui::finish_spinner_fail(&spin, "clock sync failed");
    ui::warning("Kerberos may fail due to clock skew");
    ui::info("Try manually: sudo ntpdate -u <target>");
}

/// Try syncing without sudo.
async fn try_sync_direct(target: &str, spin: &indicatif::ProgressBar) -> bool {
    let candidates: &[(&str, &[&str])] = &[
        ("ntpdate", &["-u", target]),
        ("net", &["time", "set", "-S", target]),
        ("rdate", &["-n", "-s", target]),
    ];

    for (bin, args) in candidates {
        ui::verbose(&format!("trying: {} {}", bin, args.join(" ")));
        let out = timeout(
            Duration::from_secs(10),
            Command::new(bin).args(*args).output(),
        )
        .await;

        match out {
            Ok(Ok(output)) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                ui::verbose_output(bin, &stdout);
                ui::verbose_output(bin, &stderr);

                if output.status.success() {
                    let detail = stdout.trim().lines().next().unwrap_or("ok");
                    ui::finish_spinner(spin, &format!("synced via {}: {}", bin, truncate(detail, 60)));
                    return true;
                }
            }
            Ok(Err(_)) => continue, // binary not found
            Err(_) => continue,     // timeout
        }
    }
    false
}

/// Try syncing with sudo, piping the password to stdin.
async fn try_sync_sudo(target: &str, password: &str, spin: &indicatif::ProgressBar) -> bool {
    let candidates: &[(&str, &[&str])] = &[
        ("ntpdate", &["-u", target]),
        ("net", &["time", "set", "-S", target]),
        ("rdate", &["-n", "-s", target]),
    ];

    for (bin, args) in candidates {
        ui::verbose(&format!("trying sudo: {} {}", bin, args.join(" ")));

        let mut cmd = Command::new("sudo");
        cmd.arg("-S")
            .arg("-p")
            .arg("") // suppress sudo's own prompt
            .arg(bin)
            .args(*args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let child = match cmd.spawn() {
            Ok(c) => c,
            Err(_) => continue,
        };

        let mut child = child;
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(format!("{}\n", password).as_bytes()).await;
            drop(stdin);
        }

        let out = timeout(Duration::from_secs(15), child.wait_with_output()).await;

        match out {
            Ok(Ok(output)) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                ui::verbose_output(&format!("sudo {}", bin), &stdout);
                ui::verbose_output(&format!("sudo {}", bin), &stderr);

                // Check for wrong password
                if stderr.to_lowercase().contains("incorrect password")
                    || stderr.to_lowercase().contains("sorry, try again")
                {
                    ui::finish_spinner_fail(spin, "wrong sudo password");
                    return false;
                }

                if output.status.success() {
                    let detail = stdout.trim().lines().next().unwrap_or("ok");
                    ui::finish_spinner(
                        spin,
                        &format!("synced via sudo {}: {}", bin, truncate(detail, 60)),
                    );
                    return true;
                }
            }
            Ok(Err(_)) => continue,
            Err(_) => continue,
        }
    }
    false
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        format!("{}...", s.chars().take(max).collect::<String>())
    }
}
