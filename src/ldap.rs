use anyhow::Result;
use ldap3::{LdapConnAsync, Scope, SearchEntry};

use crate::output;

/// Info collected from LDAP enumeration
#[derive(Debug, Default)]
pub struct LdapInfo {
    pub domain: Option<String>,
    pub dns_hostname: Option<String>,
    pub usernames: Vec<String>,
}

fn ldap_tag_selected(selected: &[String], tag: &str) -> bool {
    if selected.is_empty() {
        return true;
    }
    selected.iter().any(|t| t.eq_ignore_ascii_case(tag))
}

/// Convert a DN like "DC=corp,DC=local" to "corp.local"
fn dn_to_domain(dn: &str) -> String {
    dn.split(',')
        .filter_map(|part| {
            let part = part.trim();
            if part.to_uppercase().starts_with("DC=") {
                Some(&part[3..])
            } else {
                None
            }
        })
        .collect::<Vec<_>>()
        .join(".")
}

/// Attempt LDAP null bind and enumerate Root DSE
pub async fn run(target: &str, port: u16, selected_tags: &[String]) -> Result<LdapInfo> {
    let mut info = LdapInfo::default();

    let scheme = if port == 636 || port == 3269 {
        "ldaps"
    } else {
        "ldap"
    };

    output::section("LDAP ENUMERATION");
    output::info(&format!(
        "Attempting null bind on {}://{}:{}",
        scheme, target, port
    ));

    let url = format!("{}://{}:{}", scheme, target, port);

    let (conn, mut ldap) = match LdapConnAsync::new(&url).await {
        Ok(c) => c,
        Err(e) => {
            output::fail(&format!("Connection failed: {}", e));
            return Ok(info);
        }
    };

    // Drive the connection in the background
    tokio::spawn(async move {
        if let Err(e) = conn.drive().await {
            eprintln!("LDAP connection error: {}", e);
        }
    });

    // Try explicit anonymous bind (null bind)
    let mut explicit_null_bind_ok = false;
    match ldap.simple_bind("", "").await {
        Ok(result) => {
            if result.rc == 0 {
                output::success("Null bind successful — anonymous access allowed!");
                explicit_null_bind_ok = true;
            } else {
                output::fail(&format!("Null bind rejected (rc: {})", result.rc));
                output::info("Trying anonymous Root DSE query without explicit bind...");
            }
        }
        Err(e) => {
            output::fail(&format!("Bind error: {}", e));
            output::info("Trying anonymous Root DSE query without explicit bind...");
        }
    }

    // Enumerate Root DSE
    let show_rootdse = ldap_tag_selected(selected_tags, "rootdse")
        || ldap_tag_selected(selected_tags, "naming-contexts")
        || ldap_tag_selected(selected_tags, "dns-hostname")
        || ldap_tag_selected(selected_tags, "all");

    if show_rootdse {
        output::info("Querying Root DSE...");
        println!();
    }

    let root_dse_attrs = vec![
        "defaultNamingContext",
        "rootDomainNamingContext",
        "configurationNamingContext",
        "schemaNamingContext",
        "namingContexts",
        "dnsHostName",
        "serverName",
        "ldapServiceName",
        "domainFunctionality",
        "forestFunctionality",
        "domainControllerFunctionality",
        "supportedSASLMechanisms",
        "supportedLDAPVersion",
        "supportedControl",
        "isGlobalCatalogReady",
        "isSynchronized",
    ];

    let search_result = ldap
        .search("", Scope::Base, "(objectClass=*)", root_dse_attrs)
        .await;

    match search_result {
        Ok(result) => {
            match result.success() {
                Ok((rs, _status)) => {
                    if !explicit_null_bind_ok {
                        output::warning(
                            "Anonymous Root DSE query succeeded without explicit null bind (informational)",
                        );
                    }
                    for entry in rs {
                        let entry = SearchEntry::construct(entry);
                        for (attr, values) in &entry.attrs {
                            let display_attr = attr.as_str();

                            // Extract domain from defaultNamingContext
                            if display_attr.eq_ignore_ascii_case("defaultNamingContext") {
                                if let Some(dn) = values.first() {
                                    let domain = dn_to_domain(dn);
                                    if !domain.is_empty() {
                                        info.domain = Some(domain);
                                    }
                                }
                            }

                            // Extract dnsHostName
                            if display_attr.eq_ignore_ascii_case("dnsHostName") {
                                if let Some(h) = values.first() {
                                    info.dns_hostname = Some(h.clone());
                                }
                            }

                            match display_attr {
                                "domainFunctionality" if show_rootdse => {
                                    let level = values
                                        .first()
                                        .map(|v| functional_level(v))
                                        .unwrap_or("unknown".to_string());
                                    output::kv("Domain Functional Level", &level);
                                }
                                "forestFunctionality" if show_rootdse => {
                                    let level = values
                                        .first()
                                        .map(|v| functional_level(v))
                                        .unwrap_or("unknown".to_string());
                                    output::kv("Forest Functional Level", &level);
                                }
                                "domainControllerFunctionality" if show_rootdse => {
                                    let level = values
                                        .first()
                                        .map(|v| functional_level(v))
                                        .unwrap_or("unknown".to_string());
                                    output::kv("DC Functional Level", &level);
                                }
                                "supportedSASLMechanisms" if show_rootdse => {
                                    output::kv("SASL Mechanisms", &values.join(", "));
                                }
                                "supportedControl" if show_rootdse => {
                                    output::kv(
                                        "Supported Controls",
                                        &format!("{} controls", values.len()),
                                    );
                                }
                                "supportedLDAPVersion" if show_rootdse => {
                                    output::kv("LDAP Versions", &values.join(", "));
                                }
                                _ if show_rootdse => {
                                    for value in values {
                                        output::kv(display_attr, value);
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
                Err(e) => {
                    output::fail(&format!("Root DSE query returned error: {}", e));
                }
            }
        }
        Err(e) => {
            output::fail(&format!("Root DSE query failed: {}", e));
        }
    }

    // Try to enumerate usernames from default naming context
    if let Some(ref domain) = info.domain {
        let base_dn = domain
            .split('.')
            .map(|part| format!("DC={}", part))
            .collect::<Vec<_>>()
            .join(",");

        if ldap_tag_selected(selected_tags, "policy") || ldap_tag_selected(selected_tags, "all") {
            collect_domain_policy(&mut ldap, &base_dn).await;
        }
        if ldap_tag_selected(selected_tags, "users") || ldap_tag_selected(selected_tags, "all") {
            collect_usernames(&mut ldap, &base_dn, &mut info.usernames).await;
        }
    }

    // Check LDAP signing
    if ldap_tag_selected(selected_tags, "signing") || ldap_tag_selected(selected_tags, "all") {
        check_ldap_signing(&mut ldap).await;
    }

    let _ = ldap.unbind().await;
    Ok(info)
}

async fn collect_usernames(ldap: &mut ldap3::Ldap, base_dn: &str, usernames: &mut Vec<String>) {
    println!();
    output::info("Attempting anonymous LDAP user enumeration...");

    let search = ldap
        .search(
            base_dn,
            Scope::Subtree,
            "(&(objectCategory=person)(objectClass=user)(sAMAccountName=*))",
            vec!["sAMAccountName"],
        )
        .await;

    let Ok(search_result) = search else {
        output::warning("LDAP user enumeration query failed");
        return;
    };

    let Ok((entries, _)) = search_result.success() else {
        output::warning("LDAP user enumeration rejected by server");
        return;
    };

    for entry in entries {
        let entry = SearchEntry::construct(entry);
        if let Some(values) = entry.attrs.get("sAMAccountName") {
            for name in values {
                if !name.is_empty() {
                    usernames.push(name.clone());
                }
            }
        }
    }

    usernames.sort_by_key(|u| u.to_lowercase());
    usernames.dedup_by(|a, b| a.eq_ignore_ascii_case(b));

    if usernames.is_empty() {
        output::warning("No usernames returned via anonymous LDAP");
    } else {
        output::success(&format!(
            "Collected {} usernames from LDAP",
            usernames.len()
        ));
    }
}

async fn collect_domain_policy(ldap: &mut ldap3::Ldap, base_dn: &str) {
    println!();
    output::info("Checking anonymous LDAP read access to domain password/lockout policy...");

    let attrs = vec![
        "lockoutThreshold",
        "minPwdLength",
        "pwdProperties",
        "maxPwdAge",
        "minPwdAge",
    ];

    let search = ldap
        .search(base_dn, Scope::Base, "(objectClass=domainDNS)", attrs)
        .await;

    let Ok(search_result) = search else {
        output::warning("Could not query anonymous domain policy attributes");
        return;
    };
    let Ok((entries, _)) = search_result.success() else {
        output::warning("Anonymous domain policy read rejected by server");
        return;
    };

    let mut exposed = false;
    for entry in entries {
        let entry = SearchEntry::construct(entry);
        for (attr, values) in entry.attrs {
            if let Some(first) = values.first() {
                if !first.is_empty() {
                    exposed = true;
                    output::kv(&format!("Policy {}", attr), first);
                }
            }
        }
    }

    if exposed {
        output::warning(
            "Password/lockout policy attributes are readable anonymously (informational exposure)",
        );
    } else {
        output::success("No obvious anonymous domain policy attribute exposure");
    }
}

/// Check if LDAP signing is enforced
async fn check_ldap_signing(ldap: &mut ldap3::Ldap) {
    println!();
    output::info("Checking LDAP signing requirements...");

    // Try an unsigned search — if it works, signing is NOT enforced
    match ldap
        .search("", Scope::Base, "(objectClass=*)", vec!["dnsHostName"])
        .await
    {
        Ok(_) => {
            output::warning("LDAP signing is NOT enforced — relay attacks possible");
        }
        Err(_) => {
            output::success("LDAP signing appears to be enforced");
        }
    }
}

/// Convert domain/forest functional level number to human-readable string
fn functional_level(level: &str) -> String {
    match level {
        "0" => "Windows 2000".to_string(),
        "1" => "Windows Server 2003 Interim".to_string(),
        "2" => "Windows Server 2003".to_string(),
        "3" => "Windows Server 2008".to_string(),
        "4" => "Windows Server 2008 R2".to_string(),
        "5" => "Windows Server 2012".to_string(),
        "6" => "Windows Server 2012 R2".to_string(),
        "7" => "Windows Server 2016".to_string(),
        "8" => "Windows Server 2019".to_string(),
        "9" => "Windows Server 2022".to_string(),
        "10" => "Windows Server 2025".to_string(),
        _ => format!("Unknown ({})", level),
    }
}
