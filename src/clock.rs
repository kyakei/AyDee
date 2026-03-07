use std::io::{self, IsTerminal, Write};
use std::process::Stdio;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::time::timeout;

use crate::output;

pub async fn maybe_fix_clock_skew(target: &str, enabled: bool, non_interactive: bool) {
    if !enabled {
        output::info("Clock skew auto-fix disabled");
        return;
    }

    output::section("CLOCK SKEW");
    output::info(&format!("Attempting automatic clock sync using {}", target));

    let mut attempted = false;
    let candidates: Vec<(&str, Vec<&str>)> = vec![
        ("ntpdate", vec!["-u", target]),
        ("rdate", vec!["-n", "-s", target]),
    ];

    for (bin, args) in candidates {
        let args_refs = args.iter().copied().collect::<Vec<_>>();

        let Some((ok, details)) = run_cmd(bin, &args_refs).await else {
            continue;
        };
        attempted = true;
        if ok {
            output::success(&format!(
                "Clock sync succeeded via `{}`",
                format_cmd(bin, &args_refs)
            ));
            if !details.is_empty() {
                output::kv("Time Sync Output", &details);
            }
            return;
        }
    }

    if attempted {
        output::warning(
            "Clock sync attempt failed (permissions/tooling). Kerberos may fail with clock skew (Kerberoast/AS-REP/TGT may not work reliably).",
        );
        maybe_prompt_privileged_retry(target, non_interactive).await;
    } else {
        output::warning("No supported time-sync tool found (`ntpdate` or `rdate`)");
        maybe_prompt_privileged_retry(target, non_interactive).await;
    }
}

async fn run_cmd(bin: &str, args: &[&str]) -> Option<(bool, String)> {
    let mut cmd = Command::new(bin);
    cmd.args(args);
    let out = timeout(Duration::from_secs(8), cmd.output())
        .await
        .ok()?
        .ok()?;
    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
    let details = if !stdout.is_empty() {
        stdout
    } else if !stderr.is_empty() {
        stderr
    } else {
        String::new()
    };
    Some((out.status.success(), trim_for_display(&details, 180)))
}

fn format_cmd(bin: &str, args: &[&str]) -> String {
    if args.is_empty() {
        return bin.to_string();
    }
    format!("{} {}", bin, args.join(" "))
}

fn trim_for_display(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let clipped = s.chars().take(max).collect::<String>();
    format!("{} <snip>", clipped)
}

async fn maybe_prompt_privileged_retry(target: &str, non_interactive: bool) {
    if non_interactive || !io::stdin().is_terminal() {
        output::info("Non-interactive session detected; skipping sudo password prompt.");
        return;
    }

    if !confirm_privileged_sync() {
        output::info(
            "Skipped privileged clock sync retry (Kerberos actions like Kerberoast/AS-REP/TGT may fail due to skew).",
        );
        return;
    }

    let password = match rpassword::prompt_password("  sudo password: ") {
        Ok(p) if !p.is_empty() => p,
        _ => {
            output::warning("No password provided; skipping privileged clock sync retry");
            return;
        }
    };

    let candidates: Vec<(&str, Vec<&str>)> = vec![
        ("ntpdate", vec!["-u", target]),
        ("rdate", vec!["-n", "-s", target]),
    ];

    for (tool, args) in candidates {
        let Some((ok, details)) = run_sudo_with_password(tool, &args, &password).await else {
            continue;
        };
        if ok {
            output::success(&format!(
                "Clock sync succeeded via `sudo {} {}`",
                tool,
                args.join(" ")
            ));
            if !details.is_empty() {
                output::kv("Time Sync Output", &details);
            }
            return;
        }
    }

    output::warning("Privileged clock sync retry failed");
}

fn confirm_privileged_sync() -> bool {
    print!("  [*] Enable privileged clock sync retry now? [y/N]: ");
    let _ = io::stdout().flush();
    let mut line = String::new();
    if io::stdin().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

async fn run_sudo_with_password(
    tool: &str,
    tool_args: &[&str],
    password: &str,
) -> Option<(bool, String)> {
    let mut cmd = Command::new("sudo");
    cmd.arg("-S")
        .arg("-p")
        .arg("")
        .arg(tool)
        .args(tool_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().ok()?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(format!("{}\n", password).as_bytes()).await;
    }
    let out = timeout(Duration::from_secs(10), child.wait_with_output())
        .await
        .ok()?
        .ok()?;
    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
    let details = if !stdout.is_empty() {
        stdout
    } else if !stderr.is_empty() {
        stderr
    } else {
        String::new()
    };
    Some((out.status.success(), trim_for_display(&details, 180)))
}
