use anyhow::Result;
use hickory_resolver::config::*;
use hickory_resolver::TokioAsyncResolver;

use crate::output;

/// AD-specific SRV record queries to enumerate
const SRV_QUERIES: &[(&str, &str)] = &[
    ("_ldap._tcp.dc._msdcs", "Domain Controllers"),
    ("_kerberos._tcp", "Kerberos KDC"),
    ("_gc._tcp", "Global Catalog"),
    ("_kpasswd._tcp", "Kerberos Password Change"),
    ("_ldap._tcp.pdc._msdcs", "Primary Domain Controller"),
    ("_ldap._tcp.gc._msdcs", "Global Catalog (MSDCS)"),
];

/// Run DNS-based AD enumeration
pub async fn run(target: &str) -> Result<Option<String>> {
    output::section("DNS ENUMERATION");

    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

    output::info(&format!("Attempting domain discovery from {}", target));
    let domain = discover_domain_from_target(target).await;
    if let Some(ref d) = domain {
        output::success(&format!("Domain: {}", d));
    } else {
        output::warning("Reverse DNS lookup failed");
    }

    // If we don't have a domain, we can't do SRV enumeration
    let domain = match domain {
        Some(d) => d,
        None => {
            output::warning("Could not determine domain name from DNS");
            output::info("Try providing the domain with: ./aydee <ip> -d <domain>");
            return Ok(None);
        }
    };

    // Enumerate SRV records
    output::info(&format!("Enumerating SRV records for {}", domain));
    println!();

    for (srv, description) in SRV_QUERIES {
        let query = format!("{}.{}.", srv, domain);
        match resolver.srv_lookup(query.clone()).await {
            Ok(lookup) => {
                output::success(description);
                for record in lookup.iter() {
                    output::kv(
                        "Host",
                        &format!(
                            "{} (port: {}, priority: {}, weight: {})",
                            record.target().to_string().trim_end_matches('.'),
                            record.port(),
                            record.priority(),
                            record.weight()
                        ),
                    );
                }
            }
            Err(_) => {
                output::fail(&format!("{} — no records", description));
            }
        }
    }

    println!();
    check_open_recursion(target).await;

    Ok(Some(domain))
}

/// Discover a likely AD domain from an IP/FQDN target.
/// For IP targets, this performs reverse DNS and strips the host label.
/// For FQDN targets, this strips the first label directly.
pub async fn discover_domain_from_target(target: &str) -> Option<String> {
    // If target is an IP literal, don't treat dot-separated octets as a hostname.
    if target.parse::<std::net::IpAddr>().is_err() {
        if let Some(domain) = domain_from_hostname(target) {
            return Some(domain);
        }
    }

    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

    let addr = target.parse::<std::net::IpAddr>().ok()?;
    let lookup = resolver.reverse_lookup(addr).await.ok()?;
    let hostname = lookup.iter().next()?.to_string();

    domain_from_hostname(hostname.trim_end_matches('.'))
}

pub fn is_valid_domain_name(value: &str) -> bool {
    let v = value.trim().trim_matches('.').to_ascii_lowercase();
    if v.is_empty() {
        return false;
    }
    if v.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }
    if !v.chars().any(|c| c.is_ascii_alphabetic()) {
        return false;
    }
    let labels: Vec<&str> = v.split('.').collect();
    if labels.iter().any(|l| l.is_empty()) {
        return false;
    }
    for label in labels {
        if label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
    }
    true
}

pub fn normalize_domain_name(value: &str) -> Option<String> {
    let v = value.trim().trim_matches('.').to_ascii_lowercase();
    if is_valid_domain_name(&v) {
        Some(v)
    } else {
        None
    }
}

/// Convert hostname/FQDN to a likely AD DNS domain:
/// - `dc01.pirate.htb` -> `pirate.htb`
/// - `pirate.htb` -> `pirate.htb`
/// - `localhost` -> None
pub fn domain_from_hostname(hostname: &str) -> Option<String> {
    let h = hostname.trim().trim_matches('.').to_ascii_lowercase();
    let parts: Vec<&str> = h.split('.').filter(|p| !p.is_empty()).collect();
    let candidate = match parts.len() {
        0 | 1 => return None,
        2 => h,
        _ => parts[1..].join("."),
    };
    normalize_domain_name(&candidate)
}

/// Prefer a better domain candidate.
/// - invalid current -> replace with valid candidate
/// - if both valid and candidate is more specific (`pirate.htb` over `htb`) -> replace
pub fn should_replace_domain(current: &str, candidate: &str) -> bool {
    let Some(cur) = normalize_domain_name(current) else {
        return true;
    };
    let Some(cand) = normalize_domain_name(candidate) else {
        return false;
    };
    if cur == cand {
        return false;
    }
    let cur_labels = cur.split('.').count();
    let cand_labels = cand.split('.').count();
    if cand_labels > cur_labels && cand.ends_with(&format!(".{}", cur)) {
        return true;
    }
    false
}

async fn check_open_recursion(target: &str) {
    let Ok(ip) = target.parse::<std::net::IpAddr>() else {
        return;
    };

    let ns_group = NameServerConfigGroup::from_ips_clear(&[ip], 53, true);
    let resolver = TokioAsyncResolver::tokio(
        ResolverConfig::from_parts(None, vec![], ns_group),
        ResolverOpts::default(),
    );

    output::info("Testing DNS recursion behavior (unauthenticated query)...");
    match resolver.lookup_ip("www.microsoft.com.").await {
        Ok(ips) if ips.iter().next().is_some() => {
            output::warning(
                "Potential open recursion: target DNS resolved external name for unauthenticated query",
            );
            output::info("Verify recursion ACL policy before treating this as exposure");
        }
        _ => {
            output::success("No obvious open-recursion response for external lookup");
        }
    }
}
