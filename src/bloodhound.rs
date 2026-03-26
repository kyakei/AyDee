use anyhow::Result;
use std::fs::File;
use std::io::IsTerminal;
use std::io::ErrorKind;
use std::path::Path;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::time::{timeout, Duration};
use zip::read::ZipArchive;

use crate::types::{ModuleResult, StageTimer};
use crate::ui;

const BLOODHOUND_TIMEOUT_SECS: u64 = 180;

/// Run BloodHound data collection.
pub async fn run(
    target: &str,
    domain: &str,
    username: &str,
    password: &str,
    ntlm: Option<&str>,
    kerberos: bool,
    collection: &str,
    output_dir: &str,
    non_interactive: bool,
) -> Result<ModuleResult> {
    ui::section("BLOODHOUND COLLECTION");
    let timer = StageTimer::start();
    let mut result = ModuleResult::new("bloodhound");

    if !non_interactive && std::io::stdin().is_terminal() {
        let confirm = dialoguer::Confirm::new()
            .with_prompt("  Run BloodHound collection?")
            .default(true)
            .interact_opt()
            .unwrap_or(Some(true))
            .unwrap_or(true);
        if !confirm {
            ui::info("BloodHound collection skipped");
            result = result.skipped("user declined");
            return Ok(result);
        }
    }

    let spin = ui::spinner("BLOODHOUND");

    let bh_dir = format!("{}/bloodhound_output", output_dir);
    tokio::fs::create_dir_all(&bh_dir).await?;

    let mut attempted = false;
    let mut any_success = false;
    let mut installed = false;

    // Try password auth
    if !password.is_empty() {
        attempted = true;
        spin.set_message("collecting with password auth...");
        let (ok, found) = run_with_candidates(
            target, domain, username, collection, &bh_dir,
            &[("-p", password)],
            &[],
        ).await;
        installed |= found;
        if ok {
            any_success = true;
        } else if found {
            // Retry with --dns-tcp
            spin.set_message("retrying with --dns-tcp...");
            let (ok2, _) = run_with_candidates(
                target, domain, username, collection, &bh_dir,
                &[("-p", password)],
                &["--dns-tcp"],
            ).await;
            if ok2 { any_success = true; }
        }
    }

    // Try NTLM hash
    if !any_success {
        if let Some(hash) = ntlm {
            attempted = true;
            spin.set_message("collecting with NTLM hash...");
            let hashes = if hash.contains(':') {
                hash.to_string()
            } else {
                format!("aad3b435b51404eeaad3b435b51404ee:{}", hash)
            };
            let (ok, found) = run_with_candidates(
                target, domain, username, collection, &bh_dir,
                &[("--hashes", &hashes)],
                &[],
            ).await;
            installed |= found;
            if ok {
                any_success = true;
            } else if found {
                spin.set_message("retrying NTLM with --dns-tcp...");
                let (ok2, _) = run_with_candidates(
                    target, domain, username, collection, &bh_dir,
                    &[("--hashes", &hashes)],
                    &["--dns-tcp"],
                ).await;
                if ok2 { any_success = true; }
            }
        }
    }

    // Try Kerberos
    if !any_success && kerberos {
        attempted = true;
        spin.set_message("collecting with Kerberos...");
        let (ok, found) = run_with_candidates(
            target, domain, username, collection, &bh_dir,
            &[],
            &["-k"],
        ).await;
        installed |= found;
        if ok {
            any_success = true;
        } else if found {
            spin.set_message("retrying Kerberos with --dns-tcp...");
            let (ok2, _) = run_with_candidates(
                target, domain, username, collection, &bh_dir,
                &[],
                &["-k", "--dns-tcp"],
            ).await;
            if ok2 { any_success = true; }
        }
    }

    if !attempted {
        ui::finish_spinner_warn(&spin, "no auth method available for BloodHound");
        result = result.skipped("no auth");
        return Ok(result);
    }

    if !installed {
        ui::finish_spinner_warn(&spin, "bloodhound-python not installed");
        ui::info("Install: pip install bloodhound or pip install bloodhound-ce");
        result = result.skipped("tool not found");
        return Ok(result);
    }

    if any_success {
        spin.set_message("inspecting output...");
        let summary = summarize_output_dir(&bh_dir);
        ui::finish_spinner(&spin, &format!("collection complete — {}", summary));
        ui::kv("Output", &bh_dir);
    } else {
        ui::finish_spinner_fail(&spin, "collection failed — all methods attempted");
        result = result.failed("all methods failed", timer.elapsed());
        return Ok(result);
    }

    ui::stage_done("BLOODHOUND", "collected", &timer.elapsed_pretty());
    result = result.success(timer.elapsed());
    Ok(result)
}

// ── Runner ─────────────────────────────────────────────────────────────────

fn base_cmd(
    bin: &str,
    target: &str,
    domain: &str,
    username: &str,
    collection: &str,
    output_dir: &str,
) -> Command {
    let mut cmd = Command::new(bin);
    cmd.arg("-u").arg(username)
        .arg("-d").arg(domain)
        .arg("-ns").arg(target)
        .arg("-c").arg(collection)
        .arg("--zip")
        .arg("-o").arg(output_dir);
    cmd
}

async fn run_with_candidates(
    target: &str,
    domain: &str,
    username: &str,
    collection: &str,
    output_dir: &str,
    kv_args: &[(&str, &str)],
    flag_args: &[&str],
) -> (bool, bool) {
    let bins = ["bloodhound-python", "bloodhound-ce-python"];
    let mut found_any = false;

    for bin in bins {
        let mut cmd = base_cmd(bin, target, domain, username, collection, output_dir);
        for (k, v) in kv_args {
            cmd.arg(k).arg(v);
        }
        for f in flag_args {
            cmd.arg(f);
        }

        // Spawn with piped output so we can stream lines live
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

        ui::verbose(&format!("running: {} ...", bin));

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                if e.kind() == ErrorKind::NotFound {
                    ui::verbose(&format!("{} not found, skipping", bin));
                    continue;
                }
                ui::warning(&format!("Could not run {}: {}", bin, e));
                found_any = true;
                continue;
            }
        };

        found_any = true;

        // Stream stdout and stderr live
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let bin_name = bin.to_string();

        let stdout_handle = tokio::spawn({
            let label = bin_name.clone();
            async move {
                let mut lines = Vec::new();
                if let Some(out) = stdout {
                    let mut reader = BufReader::new(out).lines();
                    while let Ok(Some(line)) = reader.next_line().await {
                        ui::verbose(&format!("{}: {}", label, line));
                        lines.push(line);
                    }
                }
                lines
            }
        });

        let stderr_handle = tokio::spawn({
            let label = bin_name.clone();
            async move {
                let mut lines = Vec::new();
                if let Some(err) = stderr {
                    let mut reader = BufReader::new(err).lines();
                    while let Ok(Some(line)) = reader.next_line().await {
                        ui::verbose(&format!("{}: {}", label, line));
                        lines.push(line);
                    }
                }
                lines
            }
        });

        let wait_result = timeout(
            Duration::from_secs(BLOODHOUND_TIMEOUT_SECS),
            child.wait(),
        ).await;

        let _stdout_lines = stdout_handle.await.unwrap_or_default();
        let stderr_lines = stderr_handle.await.unwrap_or_default();

        match wait_result {
            Err(_) => {
                ui::warning(&format!("{} timed out after {}s", bin, BLOODHOUND_TIMEOUT_SECS));
                // Kill the timed-out process
                let _ = child.kill().await;
                continue;
            }
            Ok(Err(e)) => {
                ui::warning(&format!("{} wait error: {}", bin, e));
                continue;
            }
            Ok(Ok(status)) => {
                if status.success() {
                    ui::success(&format!("{} collection succeeded", bin));
                    return (true, true);
                }

                ui::verbose(&format!("{} failed (exit {:?})", bin, status.code()));
                if !stderr_lines.is_empty() {
                    if let Some(last) = stderr_lines.last() {
                        ui::info(&format!("{}: {}", bin, truncate(last.trim(), 80)));
                    }
                }
            }
        }
    }

    (false, found_any)
}

// ── Output inspection ──────────────────────────────────────────────────────

fn summarize_output_dir(output_dir: &str) -> String {
    let path = Path::new(output_dir);
    let Ok(entries) = std::fs::read_dir(path) else {
        return "output dir not readable".to_string();
    };

    let mut zip_count = 0usize;
    let mut total_json = 0usize;
    let mut all_kinds: Vec<String> = Vec::new();

    for entry in entries.flatten() {
        let entry_path = entry.path();
        let Ok(meta) = entry.metadata() else { continue };
        if !meta.is_file() { continue; }

        let is_zip = entry_path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("zip"));

        if is_zip {
            zip_count += 1;
            if let Some(info) = inspect_zip(&entry_path, meta.len()) {
                total_json += info.json_entries;
                all_kinds.extend(info.entry_kinds);

                ui::kv(
                    "  Zip",
                    &format!(
                        "{} ({} bytes, {} JSON entries)",
                        entry_path.display(), info.size_bytes, info.json_entries
                    ),
                );
            }
        }
    }

    all_kinds.sort();
    all_kinds.dedup();

    if !all_kinds.is_empty() {
        ui::kv("  Kinds", &all_kinds.join(", "));
    }

    // Write summary JSON
    if zip_count > 0 {
        let summary_path = Path::new(output_dir).join("collection_summary.json");
        let summary = serde_json::json!({
            "output_dir": output_dir,
            "zip_count": zip_count,
            "total_json_entries": total_json,
            "entry_kinds": all_kinds,
        });
        if let Ok(json) = serde_json::to_string_pretty(&summary) {
            let _ = std::fs::write(summary_path, json);
        }
    }

    format!("{} zip(s), {} JSON entries", zip_count, total_json)
}

struct ZipInfo {
    size_bytes: u64,
    json_entries: usize,
    entry_kinds: Vec<String>,
}

fn inspect_zip(path: &Path, size_bytes: u64) -> Option<ZipInfo> {
    let file = File::open(path).ok()?;
    let mut archive = ZipArchive::new(file).ok()?;
    let mut json_entries = 0usize;
    let mut entry_kinds = Vec::new();

    for idx in 0..archive.len() {
        let file = archive.by_index(idx).ok()?;
        let name = file.name().to_string();
        if name.ends_with(".json") {
            json_entries += 1;
            if let Some(kind) = classify_entry_kind(&name) {
                entry_kinds.push(kind);
            }
        }
    }

    entry_kinds.sort();
    entry_kinds.dedup();

    Some(ZipInfo {
        size_bytes,
        json_entries,
        entry_kinds,
    })
}

fn classify_entry_kind(name: &str) -> Option<String> {
    let file = Path::new(name)
        .file_name()?
        .to_str()?
        .trim_end_matches(".json");
    let kind = file
        .rsplit_once('_')
        .map(|(_, suffix)| suffix)
        .unwrap_or(file);
    Some(kind.to_string())
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max])
    }
}
