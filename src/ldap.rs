use anyhow::Result;
use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchEntry};
use std::time::Duration;

use crate::types::{Finding, LdapInfo, ModuleResult, Severity, StageTimer};
use crate::ui;

// ── Unauthenticated LDAP ────────────────────────────────────────────────────

/// Fingerprint via RootDSE (no bind required) and attempt anonymous enumeration.
pub async fn fingerprint(target: &str, port: u16) -> Result<(ModuleResult, LdapInfo)> {
    ui::section("LDAP FINGERPRINT");
    let timer = StageTimer::start();
    let spin = ui::spinner("LDAP");
    let mut result = ModuleResult::new("ldap-fingerprint");
    let mut info = LdapInfo::default();

    spin.set_message("querying RootDSE...");

    let url = if port == 636 || port == 3269 {
        format!("ldaps://{}:{}", target, port)
    } else {
        format!("ldap://{}:{}", target, port)
    };

    let settings = LdapConnSettings::new()
        .set_conn_timeout(Duration::from_secs(10))
        .set_starttls(false);

    let (conn, mut ldap) = match tokio::time::timeout(
        Duration::from_secs(15),
        LdapConnAsync::with_settings(settings, &url),
    )
    .await
    {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => {
            ui::finish_spinner_fail(&spin, &format!("connection failed: {}", e));
            result = result.failed(&e.to_string(), timer.elapsed());
            return Ok((result, info));
        }
        Err(_) => {
            ui::finish_spinner_fail(&spin, "connection timed out");
            result = result.failed("timeout", timer.elapsed());
            return Ok((result, info));
        }
    };

    tokio::spawn(async move { conn.drive().await });

    // Query RootDSE
    let rootdse = ldap
        .search("", Scope::Base, "(objectClass=*)", vec!["*"])
        .await
        .and_then(|r| r.success());

    match rootdse {
        Ok((rs, _res)) => {
            for entry in rs {
                let se = SearchEntry::construct(entry);
                // Extract key attributes
                if let Some(vals) = se.attrs.get("defaultNamingContext") {
                    if let Some(nc) = vals.first() {
                        info.naming_context = Some(nc.clone());
                        // Derive domain from DN
                        let domain = nc
                            .split(',')
                            .filter_map(|p| p.strip_prefix("DC=").or_else(|| p.strip_prefix("dc=")))
                            .collect::<Vec<_>>()
                            .join(".");
                        if !domain.is_empty() {
                            info.domain = Some(domain.clone());
                            ui::kv("Domain", &domain);
                        }
                        ui::kv("Naming Context", nc);
                    }
                }

                if let Some(vals) = se.attrs.get("dnsHostName") {
                    if let Some(h) = vals.first() {
                        info.dns_hostname = Some(h.clone());
                        ui::kv("DNS Hostname", h);
                    }
                }

                if let Some(vals) = se.attrs.get("domainFunctionality") {
                    if let Some(level) = vals.first() {
                        let label = functional_level_label(level);
                        info.functional_level = Some(label.to_string());
                        ui::kv("Domain Functional Level", label);
                    }
                }

                if let Some(vals) = se.attrs.get("forestFunctionality") {
                    if let Some(level) = vals.first() {
                        ui::kv("Forest Functional Level", functional_level_label(level));
                    }
                }

                // LDAP signing
                if let Some(vals) = se.attrs.get("supportedControl") {
                    let controls: Vec<&str> = vals.iter().map(|s| s.as_str()).collect();
                    if controls.contains(&"1.2.840.113556.1.4.473") {
                        ui::kv("Server-Side Sort", "supported");
                    }
                }

                if let Some(vals) = se.attrs.get("supportedSASLMechanisms") {
                    ui::kv("SASL Mechanisms", &vals.join(", "));
                }

                if let Some(vals) = se.attrs.get("isGlobalCatalogReady") {
                    if let Some(v) = vals.first() {
                        ui::kv("Global Catalog Ready", v);
                    }
                }
            }
        }
        Err(e) => {
            ui::finish_spinner_fail(&spin, &format!("RootDSE query failed: {}", e));
            let _ = ldap.unbind().await;
            result = result.failed(&e.to_string(), timer.elapsed());
            return Ok((result, info));
        }
    }

    // Check LDAP signing
    spin.set_message("checking LDAP signing...");
    check_ldap_signing(&mut result);

    ui::finish_spinner(&spin, "RootDSE enumerated");
    ui::stage_done(
        "LDAP FINGERPRINT",
        info.domain.as_deref().unwrap_or("unknown domain"),
        &timer.elapsed_pretty(),
    );

    let _ = ldap.unbind().await;
    result = result.success(timer.elapsed());
    Ok((result, info))
}

/// Run anonymous LDAP enumeration.
pub async fn run_anonymous(
    target: &str,
    port: u16,
    naming_context: Option<&str>,
) -> Result<ModuleResult> {
    ui::section("LDAP ANONYMOUS BIND");
    let timer = StageTimer::start();
    let spin = ui::spinner("LDAP-ANON");
    let mut result = ModuleResult::new("ldap-anonymous");

    let url = if port == 636 || port == 3269 {
        format!("ldaps://{}:{}", target, port)
    } else {
        format!("ldap://{}:{}", target, port)
    };

    let settings = LdapConnSettings::new()
        .set_conn_timeout(Duration::from_secs(10));

    let (conn, mut ldap) = match tokio::time::timeout(
        Duration::from_secs(15),
        LdapConnAsync::with_settings(settings, &url),
    )
    .await
    {
        Ok(Ok(pair)) => pair,
        _ => {
            ui::finish_spinner_fail(&spin, "connection failed");
            result = result.failed("connection failed", timer.elapsed());
            return Ok(result);
        }
    };

    tokio::spawn(async move { conn.drive().await });

    // Attempt anonymous bind
    spin.set_message("attempting null bind...");
    match ldap.simple_bind("", "").await {
        Ok(res) if res.rc == 0 => {
            ui::success("Anonymous bind successful");
            let finding = Finding::new(
                "ldap",
                "LDAP-001",
                Severity::Medium,
                "LDAP anonymous bind permitted",
            )
            .with_description("Anonymous LDAP binding is allowed, enabling unauthenticated enumeration")
            .with_recommendation("Disable anonymous LDAP access unless explicitly required")
            .with_mitre("T1087.002");
            result.findings.push(finding);
        }
        _ => {
            ui::info("Anonymous bind rejected (expected)");
            let _ = ldap.unbind().await;
            ui::finish_spinner(&spin, "anonymous bind rejected");
            result = result.success(timer.elapsed());
            return Ok(result);
        }
    }

    // Try to enumerate users
    if let Some(base) = naming_context {
        spin.set_message("enumerating users...");
        match ldap
            .search(
                base,
                Scope::Subtree,
                "(&(objectClass=user)(objectCategory=person))",
                vec!["sAMAccountName"],
            )
            .await.and_then(|r| r.success())
        {
            Ok((rs, _)) => {
                for entry in rs {
                    let se = SearchEntry::construct(entry);
                    if let Some(names) = se.attrs.get("sAMAccountName") {
                        for n in names {
                            result.collected_users.push(n.clone());
                        }
                    }
                }
                if !result.collected_users.is_empty() {
                    ui::success(&format!(
                        "Enumerated {} users via anonymous bind",
                        result.collected_users.len()
                    ));
                }
            }
            Err(_) => {
                ui::info("User enumeration via anonymous bind not permitted");
            }
        }

        // Try domain policy
        spin.set_message("checking domain policy exposure...");
        match ldap
            .search(
                base,
                Scope::Base,
                "(objectClass=*)",
                vec![
                    "minPwdLength",
                    "maxPwdAge",
                    "lockoutThreshold",
                    "lockoutDuration",
                    "pwdHistoryLength",
                ],
            )
            .await.and_then(|r| r.success())
        {
            Ok((rs, _)) => {
                for entry in rs {
                    let se = SearchEntry::construct(entry);
                    let has_policy = !se.attrs.is_empty();
                    if has_policy {
                        ui::warning("Domain password policy readable via anonymous bind");
                        for (k, v) in &se.attrs {
                            ui::kv(k, &v.join(", "));
                        }
                        let finding = Finding::new(
                            "ldap",
                            "LDAP-002",
                            Severity::Low,
                            "Domain password policy exposed via anonymous bind",
                        )
                        .with_recommendation(
                            "Restrict password policy attributes from anonymous read access",
                        );
                        result.findings.push(finding);
                    }
                }
            }
            Err(_) => {}
        }
    }

    let _ = ldap.unbind().await;
    ui::finish_spinner(&spin, "anonymous enumeration complete");
    ui::stage_done("LDAP ANONYMOUS", "done", &timer.elapsed_pretty());
    result = result.success(timer.elapsed());
    Ok(result)
}

// ── Authenticated LDAP ──────────────────────────────────────────────────────

/// Run authenticated LDAP reconnaissance.
pub async fn run_authenticated(
    target: &str,
    port: u16,
    domain: &str,
    username: &str,
    password: &str,
    _ntlm: Option<&str>,
    naming_context: Option<&str>,
    tags: &[String],
) -> Result<ModuleResult> {
    ui::section("AUTHENTICATED LDAP RECON");
    let timer = StageTimer::start();
    let spin = ui::spinner("LDAP-AUTH");
    let mut result = ModuleResult::new("ldap-auth");

    let url = if port == 636 || port == 3269 {
        format!("ldaps://{}:{}", target, port)
    } else {
        format!("ldap://{}:{}", target, port)
    };

    let settings = LdapConnSettings::new()
        .set_conn_timeout(Duration::from_secs(10));

    let (conn, mut ldap) = match tokio::time::timeout(
        Duration::from_secs(15),
        LdapConnAsync::with_settings(settings, &url),
    )
    .await
    {
        Ok(Ok(pair)) => pair,
        _ => {
            ui::finish_spinner_fail(&spin, "connection failed");
            result = result.failed("connection failed", timer.elapsed());
            return Ok(result);
        }
    };

    tokio::spawn(async move { conn.drive().await });

    // Bind with credentials — try multiple formats
    spin.set_message("authenticating...");
    let bind_dns = [
        format!("{}@{}", username, domain),                    // UPN
        format!("{}\\{}", domain.split('.').next().unwrap_or(domain), username), // Down-level
        username.to_string(),                                   // Plain
    ];

    let mut bound = false;
    for dn in &bind_dns {
        ui::verbose(&format!("LDAP bind attempt: {}", dn));
        match ldap.simple_bind(dn, password).await {
            Ok(res) if res.rc == 0 => {
                ui::success(&format!("Authenticated as {}", dn));
                bound = true;
                break;
            }
            Ok(res) => {
                ui::verbose(&format!("LDAP bind failed (rc={}): {}", res.rc, dn));
            }
            Err(e) => {
                ui::verbose(&format!("LDAP bind error: {} — {}", dn, e));
            }
        }
    }

    if !bound {
        ui::finish_spinner_fail(&spin, "authentication failed");
        result = result.failed("all bind attempts failed", timer.elapsed());
        let _ = ldap.unbind().await;
        return Ok(result);
    }

    let base = naming_context
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            domain
                .split('.')
                .map(|p| format!("DC={}", p))
                .collect::<Vec<_>>()
                .join(",")
        });

    let should_run = |tag: &str| -> bool {
        tags.is_empty() || tags.iter().any(|t| t.eq_ignore_ascii_case(tag))
    };

    // ── Collect users ───────────────────────────────────────────────────
    spin.set_message("collecting users...");
    match collect_usernames(&mut ldap, &base).await {
        Ok(users) => {
            ui::success(&format!("Collected {} users", users.len()));
            result.collected_users = users;
        }
        Err(e) => ui::warning(&format!("User collection failed: {}", e)),
    }

    // ── Kerberoastable SPNs ─────────────────────────────────────────────
    if should_run("kerberoast") {
        spin.set_message("checking Kerberoastable accounts...");
        collect_kerberoast(&mut ldap, &base, &mut result).await;
    }

    // ── AS-REP roastable ────────────────────────────────────────────────
    if should_run("asreproast") {
        spin.set_message("checking AS-REP roastable accounts...");
        collect_asrep_roastable(&mut ldap, &base, &mut result).await;
    }

    // ── Delegation ──────────────────────────────────────────────────────
    if should_run("delegation") {
        spin.set_message("checking delegation...");
        collect_delegation(&mut ldap, &base, &mut result).await;
    }

    // ── Machine Account Quota ───────────────────────────────────────────
    if should_run("maq") {
        spin.set_message("checking machine account quota...");
        collect_maq(&mut ldap, &base, &mut result).await;
    }

    // ── Trusts ──────────────────────────────────────────────────────────
    if should_run("trusts") {
        spin.set_message("enumerating trusts...");
        collect_trusts(&mut ldap, &base, &mut result).await;
    }

    // ── ADCS templates ──────────────────────────────────────────────────
    if should_run("adcs") {
        spin.set_message("checking AD CS templates...");
        collect_adcs_templates(&mut ldap, &base, &mut result).await;
    }

    // ── Obsolete computers ──────────────────────────────────────────────
    if should_run("computers") {
        spin.set_message("inventorying computers...");
        collect_computers(&mut ldap, &base, &mut result).await;
    }

    // ── Password policy ─────────────────────────────────────────────────
    if should_run("pso") {
        spin.set_message("checking password policies...");
        collect_password_policy(&mut ldap, &base, &mut result).await;
    }

    // ── DCSynC heuristics ───────────────────────────────────────────────
    if should_run("dcsync") {
        spin.set_message("checking replication rights...");
        collect_dcsync_heuristics(&mut ldap, &base, &mut result).await;
    }

    // ── LAPS ────────────────────────────────────────────────────────────
    if should_run("laps") {
        spin.set_message("checking LAPS...");
        collect_laps(&mut ldap, &base, &mut result).await;
    }

    // ── GPO inventory ───────────────────────────────────────────────────
    if should_run("gpo") {
        spin.set_message("enumerating GPOs...");
        collect_gpos(&mut ldap, &base, &mut result).await;
    }

    // ── Shadow Credentials ──────────────────────────────────────────────
    if should_run("shadow-creds") {
        spin.set_message("checking shadow credentials...");
        collect_shadow_credentials(&mut ldap, &base, &mut result).await;
    }

    // ── User descriptions (password hints) ──────────────────────────────
    if should_run("user-desc") {
        spin.set_message("checking user descriptions...");
        collect_user_descriptions(&mut ldap, &base, &mut result).await;
    }

    let _ = ldap.unbind().await;

    let finding_count = result.findings.len();
    ui::finish_spinner(
        &spin,
        &format!(
            "{} findings, {} users collected",
            finding_count,
            result.collected_users.len()
        ),
    );
    ui::stage_done(
        "LDAP AUTH RECON",
        &format!("{} findings", finding_count),
        &timer.elapsed_pretty(),
    );

    result = result.success(timer.elapsed());
    Ok(result)
}

// ── Collection functions ────────────────────────────────────────────────────

async fn collect_usernames(ldap: &mut ldap3::Ldap, base: &str) -> Result<Vec<String>> {
    let (rs, _) = ldap
        .search(
            base,
            Scope::Subtree,
            "(&(objectClass=user)(objectCategory=person))",
            vec!["sAMAccountName"],
        )
        .await?
        .success()?;

    let mut users = Vec::new();
    for entry in rs {
        let se = SearchEntry::construct(entry);
        if let Some(names) = se.attrs.get("sAMAccountName") {
            users.extend(names.iter().cloned());
        }
    }
    Ok(users)
}

async fn collect_kerberoast(ldap: &mut ldap3::Ldap, base: &str, result: &mut ModuleResult) {
    let filter = "(&(objectClass=user)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(sAMAccountName=krbtgt)))";
    let Ok((rs, _)) = ldap
        .search(base, Scope::Subtree, filter, vec!["sAMAccountName", "servicePrincipalName"])
        .await.and_then(|r| r.success())
    else {
        return;
    };

    let mut spn_users = Vec::new();
    for entry in rs {
        let se = SearchEntry::construct(entry);
        if let Some(names) = se.attrs.get("sAMAccountName") {
            if let Some(spns) = se.attrs.get("servicePrincipalName") {
                for name in names {
                    spn_users.push(format!("{} ({})", name, spns.join(", ")));
                }
            }
        }
    }

    if !spn_users.is_empty() {
        ui::warning(&format!("{} Kerberoastable account(s) found", spn_users.len()));
        for u in &spn_users {
            ui::kv("  SPN User", u);
        }
        let finding = Finding::new(
            "ldap",
            "KERB-001",
            Severity::High,
            &format!("{} Kerberoastable user account(s)", spn_users.len()),
        )
        .with_description("User accounts with SPNs can be Kerberoasted to crack their passwords offline")
        .with_evidence(&spn_users.join("\n"))
        .with_recommendation("Use managed service accounts (gMSA), rotate SPN account passwords frequently, and enforce strong passwords")
        .with_mitre("T1558.003");
        result.findings.push(finding);
    }
}

async fn collect_asrep_roastable(ldap: &mut ldap3::Ldap, base: &str, result: &mut ModuleResult) {
    let filter = "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))";
    let Ok((rs, _)) = ldap
        .search(base, Scope::Subtree, filter, vec!["sAMAccountName"])
        .await.and_then(|r| r.success())
    else {
        return;
    };

    let mut users = Vec::new();
    for entry in rs {
        let se = SearchEntry::construct(entry);
        if let Some(names) = se.attrs.get("sAMAccountName") {
            users.extend(names.iter().cloned());
        }
    }

    if !users.is_empty() {
        ui::warning(&format!("{} AS-REP roastable account(s)", users.len()));
        for u in &users {
            ui::kv("  No Pre-Auth", u);
        }
        let finding = Finding::new(
            "ldap",
            "KERB-002",
            Severity::High,
            &format!("{} AS-REP roastable user account(s)", users.len()),
        )
        .with_description("Accounts with Kerberos pre-authentication disabled can be AS-REP roasted")
        .with_evidence(&users.join(", "))
        .with_recommendation("Enable Kerberos pre-authentication for all user accounts")
        .with_mitre("T1558.004");
        result.findings.push(finding);
    }
}

async fn collect_delegation(ldap: &mut ldap3::Ldap, base: &str, result: &mut ModuleResult) {
    // Unconstrained delegation
    let filter = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(primaryGroupID=516)))";
    if let Ok((rs, _)) = ldap
        .search(base, Scope::Subtree, filter, vec!["sAMAccountName", "dNSHostName"])
        .await.and_then(|r| r.success())
    {
        let hosts: Vec<String> = rs
            .into_iter()
            .filter_map(|e| {
                let se = SearchEntry::construct(e);
                se.attrs.get("sAMAccountName").and_then(|n| n.first().cloned())
            })
            .collect();

        if !hosts.is_empty() {
            ui::warning(&format!("{} host(s) with unconstrained delegation", hosts.len()));
            let finding = Finding::new(
                "ldap",
                "DELEG-001",
                Severity::Critical,
                &format!("Unconstrained delegation on {} host(s)", hosts.len()),
            )
            .with_description("Unconstrained delegation allows impersonation of any user who authenticates to the host")
            .with_evidence(&hosts.join(", "))
            .with_recommendation("Replace with constrained delegation or RBCD; monitor for TGT harvesting")
            .with_mitre("T1550.003");
            result.findings.push(finding);
        }
    }

    // RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity)
    let filter = "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)";
    if let Ok((rs, _)) = ldap
        .search(
            base,
            Scope::Subtree,
            filter,
            vec!["sAMAccountName", "msDS-AllowedToActOnBehalfOfOtherIdentity"],
        )
        .await.and_then(|r| r.success())
    {
        let hosts: Vec<String> = rs
            .into_iter()
            .filter_map(|e| {
                let se = SearchEntry::construct(e);
                se.attrs.get("sAMAccountName").and_then(|n| n.first().cloned())
            })
            .collect();

        if !hosts.is_empty() {
            ui::info(&format!("{} host(s) with RBCD configured", hosts.len()));
            for h in &hosts {
                ui::kv("  RBCD", h);
            }
        }
    }
}

async fn collect_maq(ldap: &mut ldap3::Ldap, base: &str, result: &mut ModuleResult) {
    if let Ok((rs, _)) = ldap
        .search(
            base,
            Scope::Base,
            "(objectClass=*)",
            vec!["ms-DS-MachineAccountQuota"],
        )
        .await.and_then(|r| r.success())
    {
        for entry in rs {
            let se = SearchEntry::construct(entry);
            if let Some(vals) = se.attrs.get("ms-DS-MachineAccountQuota") {
                if let Some(quota) = vals.first() {
                    let q: i32 = quota.parse().unwrap_or(0);
                    ui::kv("Machine Account Quota", quota);
                    if q > 0 {
                        let finding = Finding::new(
                            "ldap",
                            "MAQ-001",
                            Severity::Medium,
                            &format!("Machine Account Quota is {} (default 10)", q),
                        )
                        .with_description("Non-zero MAQ allows any domain user to create machine accounts, enabling RBCD and relay attacks")
                        .with_recommendation("Set ms-DS-MachineAccountQuota to 0")
                        .with_mitre("T1136.002");
                        result.findings.push(finding);
                    }
                }
            }
        }
    }
}

async fn collect_trusts(ldap: &mut ldap3::Ldap, base: &str, result: &mut ModuleResult) {
    let filter = "(objectClass=trustedDomain)";
    if let Ok((rs, _)) = ldap
        .search(
            base,
            Scope::Subtree,
            filter,
            vec!["cn", "trustDirection", "trustType", "trustAttributes"],
        )
        .await.and_then(|r| r.success())
    {
        for entry in rs {
            let se = SearchEntry::construct(entry);
            let name = se.attrs.get("cn").and_then(|v| v.first()).cloned().unwrap_or_default();
            let direction = se
                .attrs
                .get("trustDirection")
                .and_then(|v| v.first())
                .map(|d| match d.as_str() {
                    "1" => "Inbound",
                    "2" => "Outbound",
                    "3" => "Bidirectional",
                    _ => "Unknown",
                })
                .unwrap_or("Unknown");

            ui::kv(&format!("Trust: {}", name), direction);

            let finding = Finding::new(
                "ldap",
                "TRUST-001",
                Severity::Info,
                &format!("Domain trust: {} ({})", name, direction),
            )
            .with_mitre("T1482");
            result.findings.push(finding);
        }
    }
}

async fn collect_adcs_templates(ldap: &mut ldap3::Ldap, base: &str, result: &mut ModuleResult) {
    let config_nc = base.find("DC=").map(|_| {
        let parts: Vec<&str> = base.split(',').collect();
        let dc_parts: Vec<&str> = parts.iter().filter(|p| p.starts_with("DC=")).copied().collect();
        format!("CN=Configuration,{}", dc_parts.join(","))
    });

    let Some(config_base) = config_nc else { return };
    let templates_base = format!("CN=Certificate Templates,CN=Public Key Services,CN=Services,{}", config_base);

    let filter = "(objectClass=pKICertificateTemplate)";
    if let Ok((rs, _)) = ldap
        .search(
            &templates_base,
            Scope::Subtree,
            filter,
            vec![
                "cn",
                "msPKI-Certificate-Name-Flag",
                "msPKI-Enrollment-Flag",
                "pKIExtendedKeyUsage",
                "msPKI-RA-Signature",
            ],
        )
        .await.and_then(|r| r.success())
    {
        let mut vulnerable_templates = Vec::new();

        for entry in rs {
            let se = SearchEntry::construct(entry);
            let name = se.attrs.get("cn").and_then(|v| v.first()).cloned().unwrap_or_default();
            let name_flag: u32 = se
                .attrs
                .get("msPKI-Certificate-Name-Flag")
                .and_then(|v| v.first())
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            let ra_sig: u32 = se
                .attrs
                .get("msPKI-RA-Signature")
                .and_then(|v| v.first())
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);

            // ESC1: ENROLLEE_SUPPLIES_SUBJECT flag + Client Auth EKU + no manager approval
            let supplies_subject = name_flag & 1 != 0;
            let eku = se.attrs.get("pKIExtendedKeyUsage").cloned().unwrap_or_default();
            let has_client_auth = eku.iter().any(|e| e == "1.3.6.1.5.5.7.3.2" || e == "1.3.6.1.4.1.311.20.2.2");
            let no_approval = ra_sig == 0;

            if supplies_subject && has_client_auth && no_approval {
                vulnerable_templates.push(format!("{} (ESC1: enrollee supplies subject + client auth)", name));
            }
        }

        if !vulnerable_templates.is_empty() {
            for t in &vulnerable_templates {
                ui::warning(t);
            }
            let finding = Finding::new(
                "ldap",
                "ADCS-001",
                Severity::Critical,
                &format!("{} vulnerable AD CS template(s) (ESC1)", vulnerable_templates.len()),
            )
            .with_description("Certificate templates allow enrollee to supply the subject name with Client Authentication EKU, enabling domain privilege escalation")
            .with_evidence(&vulnerable_templates.join("\n"))
            .with_recommendation("Remove ENROLLEE_SUPPLIES_SUBJECT flag, restrict enrollment permissions, or require manager approval")
            .with_mitre("T1649");
            result.findings.push(finding);
        }
    }
}

async fn collect_computers(ldap: &mut ldap3::Ldap, base: &str, result: &mut ModuleResult) {
    let filter = "(objectCategory=computer)";
    if let Ok((rs, _)) = ldap
        .search(
            base,
            Scope::Subtree,
            filter,
            vec!["sAMAccountName", "operatingSystem", "operatingSystemVersion"],
        )
        .await.and_then(|r| r.success())
    {
        let mut obsolete = Vec::new();
        let mut os_counts: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
        let obsolete_patterns = [
            "Windows Server 2003",
            "Windows Server 2008",
            "Windows XP",
            "Windows 7",
            "Windows Vista",
            "Windows Server 2012",
        ];

        for entry in rs {
            let se = SearchEntry::construct(entry);
            let os = se.attrs.get("operatingSystem").and_then(|v| v.first()).cloned().unwrap_or_default();
            let name = se.attrs.get("sAMAccountName").and_then(|v| v.first()).cloned().unwrap_or_default();

            if !name.is_empty() {
                result.collected_users.push(name.clone());
            }

            if !os.is_empty() {
                *os_counts.entry(os.clone()).or_insert(0) += 1;
            }

            if obsolete_patterns.iter().any(|p| os.contains(p)) {
                obsolete.push(format!("{} ({})", name, os));
            }
        }

        // Show OS inventory
        let total: u32 = os_counts.values().sum();
        ui::info(&format!("{} computer objects found", total));
        let mut sorted_os: Vec<_> = os_counts.into_iter().collect();
        sorted_os.sort_by(|a, b| b.1.cmp(&a.1));
        for (os, count) in sorted_os.iter().take(10) {
            ui::kv(&format!("  {} ({}x)", os, count), "");
        }

        if !obsolete.is_empty() {
            let finding = Finding::new(
                "ldap",
                "COMP-001",
                Severity::Medium,
                &format!("{} obsolete OS computer(s) found", obsolete.len()),
            )
            .with_description("End-of-life operating systems lack security patches and are high-value targets")
            .with_evidence(&obsolete.join("\n"))
            .with_recommendation("Decommission or isolate obsolete systems");
            result.findings.push(finding);
        }
    }
}

async fn collect_password_policy(ldap: &mut ldap3::Ldap, base: &str, result: &mut ModuleResult) {
    // Fine-grained password policies
    let filter = "(objectClass=msDS-PasswordSettings)";
    if let Ok((rs, _)) = ldap
        .search(
            base,
            Scope::Subtree,
            filter,
            vec![
                "cn",
                "msDS-MinimumPasswordLength",
                "msDS-LockoutThreshold",
                "msDS-PasswordComplexityEnabled",
            ],
        )
        .await.and_then(|r| r.success())
    {
        for entry in rs {
            let se = SearchEntry::construct(entry);
            let name = se.attrs.get("cn").and_then(|v| v.first()).cloned().unwrap_or_default();
            let min_len: u32 = se
                .attrs
                .get("msDS-MinimumPasswordLength")
                .and_then(|v| v.first())
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);

            ui::kv(&format!("PSO: {}", name), &format!("minLength={}", min_len));

            if min_len < 12 {
                let finding = Finding::new(
                    "ldap",
                    "PSO-001",
                    Severity::Low,
                    &format!("Weak password policy: {} (minLength={})", name, min_len),
                )
                .with_recommendation("Set minimum password length to at least 14 characters");
                result.findings.push(finding);
            }
        }
    }
}

async fn collect_dcsync_heuristics(ldap: &mut ldap3::Ldap, base: &str, _result: &mut ModuleResult) {
    // Check for non-default accounts with replication rights
    let filter = "(&(objectClass=group)(|(cn=Domain Admins)(cn=Enterprise Admins)(cn=Administrators)))";
    if let Ok((rs, _)) = ldap
        .search(base, Scope::Subtree, filter, vec!["cn", "member"])
        .await.and_then(|r| r.success())
    {
        for entry in rs {
            let se = SearchEntry::construct(entry);
            let name = se.attrs.get("cn").and_then(|v| v.first()).cloned().unwrap_or_default();
            let members = se.attrs.get("member").cloned().unwrap_or_default();
            ui::kv(&format!("  {}", name), &format!("{} member(s)", members.len()));
        }
    }
}

async fn collect_laps(ldap: &mut ldap3::Ldap, base: &str, result: &mut ModuleResult) {
    // Check if LAPS attributes are readable
    let filter = "(&(objectCategory=computer)(ms-Mcs-AdmPwd=*))";
    if let Ok((rs, _)) = ldap
        .search(
            base,
            Scope::Subtree,
            filter,
            vec!["sAMAccountName", "ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime"],
        )
        .await.and_then(|r| r.success())
    {
        let readable: Vec<String> = rs
            .into_iter()
            .filter_map(|e| {
                let se = SearchEntry::construct(e);
                if se.attrs.contains_key("ms-Mcs-AdmPwd") {
                    se.attrs.get("sAMAccountName").and_then(|v| v.first().cloned())
                } else {
                    None
                }
            })
            .collect();

        if !readable.is_empty() {
            ui::warning(&format!("LAPS passwords readable for {} host(s)", readable.len()));
            let finding = Finding::new(
                "ldap",
                "LAPS-001",
                Severity::High,
                &format!("LAPS passwords readable for {} computer(s)", readable.len()),
            )
            .with_description("Current credentials can read LAPS managed local admin passwords")
            .with_evidence(&readable.join(", "))
            .with_recommendation("Restrict LAPS read permissions to authorized admin groups only")
            .with_mitre("T1555");
            result.findings.push(finding);
        }
    }
}

async fn collect_gpos(ldap: &mut ldap3::Ldap, base: &str, _result: &mut ModuleResult) {
    let filter = "(objectClass=groupPolicyContainer)";
    if let Ok((rs, _)) = ldap
        .search(
            base,
            Scope::Subtree,
            filter,
            vec!["displayName", "gPCFileSysPath", "flags"],
        )
        .await.and_then(|r| r.success())
    {
        let count = rs.len();
        for entry in rs {
            let se = SearchEntry::construct(entry);
            let name = se
                .attrs
                .get("displayName")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();
            let path = se
                .attrs
                .get("gPCFileSysPath")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();

            if !name.is_empty() {
                ui::kv(&format!("  GPO: {}", name), &path);
            }
        }
        ui::info(&format!("{} GPO(s) enumerated", count));
    }
}

async fn collect_shadow_credentials(
    ldap: &mut ldap3::Ldap,
    base: &str,
    result: &mut ModuleResult,
) {
    // Check for objects with msDS-KeyCredentialLink (shadow credentials)
    let filter = "(msDS-KeyCredentialLink=*)";
    if let Ok((rs, _)) = ldap
        .search(
            base,
            Scope::Subtree,
            filter,
            vec!["sAMAccountName", "objectClass"],
        )
        .await.and_then(|r| r.success())
    {
        let objects: Vec<String> = rs
            .into_iter()
            .filter_map(|e| {
                let se = SearchEntry::construct(e);
                se.attrs.get("sAMAccountName").and_then(|v| v.first().cloned())
            })
            .collect();

        if !objects.is_empty() {
            ui::info(&format!(
                "{} object(s) with shadow credentials (msDS-KeyCredentialLink)",
                objects.len()
            ));
            for obj in &objects {
                ui::kv("  Shadow Cred", obj);
            }
            let finding = Finding::new(
                "ldap",
                "SHADOW-001",
                Severity::Info,
                &format!("{} object(s) with shadow credentials configured", objects.len()),
            )
            .with_description("msDS-KeyCredentialLink is set, which could indicate WHfB or Shadow Credentials attack")
            .with_mitre("T1556.007");
            result.findings.push(finding);
        }
    }
}

async fn collect_user_descriptions(
    ldap: &mut ldap3::Ldap,
    base: &str,
    result: &mut ModuleResult,
) {
    let filter = "(&(objectClass=user)(objectCategory=person)(description=*))";
    if let Ok((rs, _)) = ldap
        .search(
            base,
            Scope::Subtree,
            filter,
            vec!["sAMAccountName", "description"],
        )
        .await.and_then(|r| r.success())
    {
        let password_hints = [
            "pass", "pwd", "password", "cred", "secret", "p@ss", "key", "login",
        ];
        let mut suspicious = Vec::new();

        for entry in rs {
            let se = SearchEntry::construct(entry);
            let name = se.attrs.get("sAMAccountName").and_then(|v| v.first()).cloned().unwrap_or_default();
            let desc = se.attrs.get("description").and_then(|v| v.first()).cloned().unwrap_or_default();

            if password_hints
                .iter()
                .any(|h| desc.to_ascii_lowercase().contains(h))
            {
                suspicious.push(format!("{}: {}", name, desc));
            }
        }

        if !suspicious.is_empty() {
            ui::warning(&format!("{} user(s) with password hints in description", suspicious.len()));
            for s in &suspicious {
                ui::kv("  Hint", s);
            }
            let finding = Finding::new(
                "ldap",
                "USER-001",
                Severity::High,
                &format!("{} user description(s) contain password hints", suspicious.len()),
            )
            .with_description("User descriptions contain keywords suggesting passwords are stored in cleartext")
            .with_evidence(&suspicious.join("\n"))
            .with_recommendation("Remove passwords from description fields; use a vault or PAM solution")
            .with_mitre("T1552.001");
            result.findings.push(finding);
        }
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn functional_level_label(level: &str) -> &str {
    match level {
        "0" => "2000",
        "1" => "2003 Interim",
        "2" => "2003",
        "3" => "2008",
        "4" => "2008 R2",
        "5" => "2012",
        "6" => "2012 R2",
        "7" => "2016",
        "8" => "2019 (Preview)",
        "9" => "2022",
        "10" => "2025",
        _ => level,
    }
}

fn check_ldap_signing(_result: &mut ModuleResult) {
    // LDAP signing check is typically done via NTLM negotiation
    // For now we note it as info
    ui::info("LDAP signing check: requires NTLM negotiation (check via SMB/RPC)");
}
