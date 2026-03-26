use anyhow::Result;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

use crate::types::{Finding, ModuleResult, Severity, StageTimer};
use crate::ui;

/// Run WinRM credential validation.
pub async fn run(
    target: &str,
    domain: &str,
    username: &str,
    password: &str,
    ntlm: Option<&str>,
) -> Result<ModuleResult> {
    ui::section("WINRM VALIDATION");
    let timer = StageTimer::start();
    let spin = ui::spinner("WINRM");
    let mut result = ModuleResult::new("winrm");

    spin.set_message("validating credentials...");

    let tools = ["nxc", "netexec", "crackmapexec"];
    let mut tested = false;

    for tool in tools {
        let mut args = vec![
            "winrm".to_string(),
            target.to_string(),
            "-d".to_string(),
            domain.to_string(),
            "-u".to_string(),
            username.to_string(),
        ];

        if let Some(hash) = ntlm {
            args.push("-H".to_string());
            args.push(hash.to_string());
        } else {
            args.push("-p".to_string());
            args.push(password.to_string());
        }

        let out = timeout(
            Duration::from_secs(30),
            Command::new(tool).args(&args).output(),
        )
        .await;

        match out {
            Ok(Ok(output)) => {
                tested = true;
                let raw_stdout = String::from_utf8_lossy(&output.stdout);
                let raw_stderr = String::from_utf8_lossy(&output.stderr);
                ui::verbose_output(tool, &raw_stdout);
                ui::verbose_output(tool, &raw_stderr);
                let stdout = raw_stdout.to_lowercase();
                let stderr = raw_stderr.to_lowercase();
                let combined = format!("{}\n{}", stdout, stderr);

                if combined.contains("pwn3d") {
                    ui::success("WinRM access confirmed — command execution possible!");
                    let finding = Finding::new(
                        "winrm",
                        "WINRM-001",
                        Severity::Critical,
                        "WinRM command execution access (Pwn3d!)",
                    )
                    .with_description("Current credentials allow remote command execution via WinRM")
                    .with_recommendation("Review and restrict WinRM access; implement JEA; use tiered admin model")
                    .with_mitre("T1021.006");
                    result.findings.push(finding);
                } else if combined.contains("[+]") && combined.contains(&username.to_lowercase()) {
                    ui::success("WinRM authentication successful");
                    let finding = Finding::new(
                        "winrm",
                        "WINRM-002",
                        Severity::High,
                        "WinRM authentication successful",
                    )
                    .with_description("Credentials are valid for WinRM access")
                    .with_mitre("T1021.006");
                    result.findings.push(finding);
                } else if combined.contains("logon_failure") || combined.contains("access_denied") {
                    ui::info("WinRM authentication failed (credentials rejected)");
                } else {
                    ui::info(&format!("WinRM result: {}", combined.lines().next().unwrap_or("unknown")));
                }
                break;
            }
            Ok(Err(_)) => continue,
            Err(_) => {
                ui::warning("WinRM check timed out");
                break;
            }
        }
    }

    if !tested {
        ui::info("No compatible WinRM tool found (nxc/netexec/crackmapexec)");
    }

    ui::finish_spinner(&spin, "WinRM check complete");
    ui::stage_done("WINRM", "done", &timer.elapsed_pretty());

    result = result.success(timer.elapsed());
    Ok(result)
}
