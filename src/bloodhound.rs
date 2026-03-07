use anyhow::Result;
use serde::Serialize;
use std::fs::File;
use std::io::ErrorKind;
use std::path::Path;
use tokio::process::Command;
use tokio::time::{timeout, Duration};
use zip::read::ZipArchive;

use crate::output;

#[derive(Debug, Clone, Serialize)]
struct BloodHoundZipSummary {
    path: String,
    size_bytes: u64,
    json_entries: usize,
    entry_kinds: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct BloodHoundSummary {
    output_dir: String,
    zip_count: usize,
    zips: Vec<BloodHoundZipSummary>,
}

/// Run BloodHound collection using available auth methods.
pub async fn run_collection(
    target: &str,
    domain: &str,
    username: &str,
    password: Option<&str>,
    ntlm_hash: Option<&str>,
    kerberos: bool,
    collection: &str,
) -> Result<bool> {
    let output_dir = "bloodhound_output";
    let mut attempted = false;
    let mut any_success = false;
    let mut installed = false;

    output::section("BLOODHOUND COLLECTION");
    output::info(&format!(
        "Attempting BloodHound collection with --collection {} --zip",
        collection
    ));

    if let Some(pass) = password {
        attempted = true;
        let (ok, found_binary) =
            run_password(target, domain, username, pass, collection, output_dir).await?;
        installed |= found_binary;
        if ok {
            any_success = true;
        }
    }

    if let Some(hash) = ntlm_hash {
        attempted = true;
        let (ok, found_binary) =
            run_ntlm(target, domain, username, hash, collection, output_dir).await?;
        installed |= found_binary;
        if ok {
            any_success = true;
        }
    }

    if kerberos {
        attempted = true;
        let (ok, found_binary) =
            run_kerberos(target, domain, username, collection, output_dir).await?;
        installed |= found_binary;
        if ok {
            any_success = true;
        }
    }

    if !attempted {
        output::warning("No BloodHound auth method provided (--password, --ntlm, or --kerberos)");
        Ok(false)
    } else if !installed {
        output::warning(
            "No BloodHound collector binary found (tried: bloodhound-python, bloodhound-ce-python)",
        );
        Ok(false)
    } else if any_success {
        summarize_output_dir(output_dir);
        output::success(&format!(
            "BloodHound collection completed. Zip output should be in ./{}/",
            output_dir
        ));
        Ok(true)
    } else {
        output::warning("BloodHound methods were attempted, but no collection succeeded");
        Ok(false)
    }
}

async fn run_password(
    target: &str,
    domain: &str,
    username: &str,
    password: &str,
    collection: &str,
    output_dir: &str,
) -> Result<(bool, bool)> {
    output::info("BloodHound auth method: password");
    let (ok, found) = run_with_candidates(
        target,
        domain,
        username,
        collection,
        output_dir,
        &[("-p", password)],
        &[],
    )
    .await?;
    if ok || !found {
        return Ok((ok, found));
    }
    output::info("Retrying BloodHound password method with --dns-tcp");
    let (ok2, found2) = run_with_candidates(
        target,
        domain,
        username,
        collection,
        output_dir,
        &[("-p", password)],
        &["--dns-tcp"],
    )
    .await?;
    Ok((ok || ok2, found || found2))
}

async fn run_ntlm(
    target: &str,
    domain: &str,
    username: &str,
    ntlm_hash: &str,
    collection: &str,
    output_dir: &str,
) -> Result<(bool, bool)> {
    output::info("BloodHound auth method: NTLM hash");
    let hashes = if ntlm_hash.contains(':') {
        ntlm_hash.to_string()
    } else {
        format!("aad3b435b51404eeaad3b435b51404ee:{}", ntlm_hash)
    };
    let (ok, found) = run_with_candidates(
        target,
        domain,
        username,
        collection,
        output_dir,
        &[("--hashes", &hashes)],
        &[],
    )
    .await?;
    if ok || !found {
        return Ok((ok, found));
    }
    output::info("Retrying BloodHound NTLM method with --dns-tcp");
    let (ok2, found2) = run_with_candidates(
        target,
        domain,
        username,
        collection,
        output_dir,
        &[("--hashes", &hashes)],
        &["--dns-tcp"],
    )
    .await?;
    Ok((ok || ok2, found || found2))
}

async fn run_kerberos(
    target: &str,
    domain: &str,
    username: &str,
    collection: &str,
    output_dir: &str,
) -> Result<(bool, bool)> {
    output::info("BloodHound auth method: Kerberos (-k)");
    let (ok, found) = run_with_candidates(
        target,
        domain,
        username,
        collection,
        output_dir,
        &[],
        &["-k"],
    )
    .await?;
    if ok || !found {
        return Ok((ok, found));
    }
    output::info("Retrying BloodHound Kerberos method with --dns-tcp");
    let (ok2, found2) = run_with_candidates(
        target,
        domain,
        username,
        collection,
        output_dir,
        &[],
        &["-k", "--dns-tcp"],
    )
    .await?;
    Ok((ok || ok2, found || found2))
}

fn base_cmd(
    bin: &str,
    target: &str,
    domain: &str,
    username: &str,
    collection: &str,
    output_dir: &str,
) -> Command {
    let mut cmd = Command::new(bin);
    cmd.arg("-u")
        .arg(username)
        .arg("-d")
        .arg(domain)
        .arg("-ns")
        .arg(target)
        .arg("-c")
        .arg(collection)
        .arg("--zip")
        .arg("-o")
        .arg(output_dir);
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
) -> Result<(bool, bool)> {
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

        match timeout(Duration::from_secs(120), cmd.output()).await {
            Err(_) => {
                found_any = true;
                output::warning(&format!("{} method timed out after 120s", bin));
                continue;
            }
            Ok(Err(e)) => {
                if e.kind() == ErrorKind::NotFound {
                    continue;
                }
                output::warning(&format!("Could not run {} ({})", bin, e));
                found_any = true;
                continue;
            }
            Ok(Ok(out)) => {
                found_any = true;
                if out.status.success() {
                    output::success(&format!("{} method succeeded", bin));
                    return Ok((true, true));
                }

                let stderr = String::from_utf8_lossy(&out.stderr);
                let stdout = String::from_utf8_lossy(&out.stdout);
                output::warning(&format!(
                    "{} method failed (exit {:?})",
                    bin,
                    out.status.code()
                ));
                if !stderr.trim().is_empty() {
                    output::kv("stderr", stderr.trim());
                } else if !stdout.trim().is_empty() {
                    output::kv("stdout", stdout.trim());
                }
            }
        }
    }

    Ok((false, found_any))
}

fn summarize_output_dir(output_dir: &str) {
    let path = Path::new(output_dir);
    let Ok(entries) = std::fs::read_dir(path) else {
        output::warning("BloodHound output directory could not be inspected");
        return;
    };

    let mut summaries = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        if path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("zip"))
        {
            summaries.push(inspect_zip(&path, meta.len()));
        }
    }

    let summaries = summaries.into_iter().flatten().collect::<Vec<_>>();
    if summaries.is_empty() {
        output::warning("BloodHound reported success, but no zip artifact was found yet");
        return;
    }

    output::success(&format!("BloodHound zip artifacts: {}", summaries.len()));
    for summary in summaries.iter().take(5) {
        output::kv(
            "Zip",
            &format!(
                "{} ({} bytes, {} JSON entries)",
                summary.path, summary.size_bytes, summary.json_entries
            ),
        );
        if !summary.entry_kinds.is_empty() {
            output::kv("Kinds", &summary.entry_kinds.join(", "));
        }
    }

    let summary = BloodHoundSummary {
        output_dir: output_dir.to_string(),
        zip_count: summaries.len(),
        zips: summaries,
    };
    let summary_path = Path::new(output_dir).join("collection_summary.json");
    if let Ok(json) = serde_json::to_string_pretty(&summary) {
        let _ = std::fs::write(summary_path, json);
    }
}

fn inspect_zip(path: &Path, size_bytes: u64) -> Option<BloodHoundZipSummary> {
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

    Some(BloodHoundZipSummary {
        path: path.display().to_string(),
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
