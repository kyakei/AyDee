mod auth_recon;
mod attacks;
mod bloodhound;
mod clock;
mod credential_attacks;
mod dns;
mod kerberos;
mod ldap;
mod output;
mod report;
mod rpc;
mod scanner;
mod smb;

use anyhow::{Context, Result};
use clap::builder::styling::{AnsiColor, Effects, Styles};
use clap::Parser;
use colored::*;
use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use std::time::Instant;

/// AyDee — Active Directory Enumeration Tool
#[derive(Parser, Debug)]
#[command(
    name = "aydee",
    about = "AyDee - Active Directory Enumeration Tool",
    version,
    styles = cli_styles(),
    before_help = "\x1b[1;31m\n                  _\n   __ _ _   _  __| | ___  ___\n  / _` | | | |/ _` |/ _ \\/ _ \\\n | (_| | |_| | (_| |  __/  __/\n  \\__,_|\\__, |\\__,_|\\___|\\___|\n        |___/\n\x1b[0m",
    after_help = "Examples\n  Basic:       aydee 10.10.10.100\n  Custom scan: aydee 10.10.10.100 -P 389,636,8080\n  All ports:   aydee 10.10.10.100 -P- --timeout 3\n  Password:    aydee 10.10.10.100 -d corp.local -u alice -p 'Password123!'\n  NTLM:        aydee 10.10.10.100 -d corp.local -u alice -H aad3b435b51404eeaad3b435b51404ee:11223344556677889900aabbccddeeff\n  CCache:      aydee 10.10.10.100 --ccache ./alice.ccache -k -u alice\n  BH:          aydee 10.10.10.100 --collection All -u alice -k --ccache ./alice.ccache"
)]
struct Args {
    /// Target IP address
    target: String,

    /// Custom ports to scan (e.g., "389,636" or "80-100" or "-" for all)
    #[arg(short = 'P', long, help_heading = "Scan")]
    ports: Option<String>,

    /// Connection timeout in seconds
    #[arg(short, long, default_value = "2", help_heading = "Scan")]
    timeout: u64,

    /// Disable automatic startup clock skew fix attempts (Kerberos helper)
    #[arg(long = "no-fix-clock-skew", help_heading = "Scan")]
    no_fix_clock_skew: bool,

    /// Domain name (auto-detected if not provided)
    #[arg(short, long, help_heading = "Scan")]
    domain: Option<String>,

    /// Wordlist for Kerberos user enumeration
    #[arg(short, long, help_heading = "Scan")]
    wordlist: Option<String>,

    /// Username for authenticated AD recon (e.g., user or user@domain)
    #[arg(short = 'u', long = "username", visible_alias = "auth-user", help_heading = "Authentication")]
    username: Option<String>,

    /// Password for authenticated AD recon
    #[arg(short = 'p', long = "password", visible_alias = "auth-pass", help_heading = "Authentication")]
    password: Option<String>,

    /// NTLM hash for authenticated AD recon (NTHASH or LMHASH:NTHASH)
    #[arg(short = 'H', long = "ntlm", visible_alias = "auth-ntlm", help_heading = "Authentication")]
    ntlm: Option<String>,

    /// Enable Kerberos auth mode for external collectors (e.g. bloodhound-python -k)
    #[arg(short = 'k', long = "kerberos", help_heading = "Authentication")]
    kerberos_auth: bool,

    /// Kerberos ticket cache path (sets KRB5CCNAME, e.g. ./alice.ccache)
    #[arg(long = "ccache", help_heading = "Authentication")]
    ccache: Option<String>,

    /// BloodHound collection scope (default: All)
    #[arg(long, default_value = "All", help_heading = "Collection/Output")]
    collection: String,

    /// Write structured JSON report to this path
    #[arg(long, default_value = "aydee_report.json", help_heading = "Collection/Output")]
    report_json: String,
}

fn cli_styles() -> Styles {
    Styles::styled()
        .header(AnsiColor::Red.on_default().effects(Effects::BOLD))
        .usage(AnsiColor::Yellow.on_default().effects(Effects::BOLD))
        .literal(AnsiColor::Cyan.on_default().effects(Effects::BOLD))
        .placeholder(AnsiColor::Green.on_default())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let start = Instant::now();
    let existing_ccache = env::var("KRB5CCNAME").ok();
    setup_run_output_dir(&args.target);
    let no_tags: Vec<String> = Vec::new();

    // Show banner
    output::banner();
    output::info(&format!("Target: {}", args.target.white().bold()));
    if let Some(ref domain) = args.domain {
        output::info(&format!("Domain: {}", domain.white().bold()));
    }
    let kerberos_auth_effective =
        args.kerberos_auth || args.ccache.is_some() || existing_ccache.is_some();

    if let Some(ref ccache) = args.ccache {
        let cache_value = if ccache.contains(':') {
            ccache.clone()
        } else {
            format!("FILE:{}", ccache)
        };
        env::set_var("KRB5CCNAME", &cache_value);
        output::success("Kerberos ccache configured");
        output::kv("KRB5CCNAME", &cache_value);
    } else if let Some(ref cache_value) = existing_ccache {
        output::success("Using pre-exported Kerberos ccache from environment");
        output::kv("KRB5CCNAME", cache_value);
    }

    if args.username.is_some()
        && (args.password.is_some() || args.ntlm.is_some() || kerberos_auth_effective)
    {
        output::success("Authenticated mode enabled");
    } else {
        output::info("Authenticated mode not enabled (no credentials provided)");
    }

    clock::maybe_fix_clock_skew(&args.target, !args.no_fix_clock_skew).await;

    // Phase 1: Port scan
    let results = scanner::run(&args.target, args.ports.as_deref(), args.timeout)
        .await
        .context("Invalid --ports value (examples: 389,636 | 80-100 | -)")?;

    let open_ports: Vec<u16> = results.iter().filter(|r| r.open).map(|r| r.port).collect();

    if open_ports.is_empty() {
        output::fail("No open ports found — target may be down or filtered");
        return Ok(());
    }

    // Show available recon entry points based on discovered ports/credentials
    let auth_enabled = args.username.is_some()
        && (args.password.is_some() || args.ntlm.is_some() || kerberos_auth_effective);
    print_entry_points(&open_ports, auth_enabled);

    // Track discovered domain + usernames across modules
    let mut discovered_domain = args.domain.clone();
    let mut collected_users: HashSet<String> = HashSet::new();
    let mut auth_findings: Vec<auth_recon::AuthFinding> = Vec::new();
    let mut ldap_auth_ok = false;
    let mut smb_auth_ok = false;
    let mut bloodhound_ok = false;
    let mut modules_run: Vec<&str> = Vec::new();

    // Try early domain inference directly from target (IP reverse DNS or FQDN)
    if discovered_domain.is_none() {
        discovered_domain = dns::discover_domain_from_target(&args.target).await;
        if let Some(ref domain) = discovered_domain {
            output::success(&format!(
                "Discovered domain from target identity: {}",
                domain
            ));
        }
    }

    // Phase 2: Auto-dispatch unauth modules based on open ports

    // DNS enumeration (port 53)
    if open_ports.contains(&53) {
        if let Ok(Some(domain)) = dns::run(&args.target).await {
            add_domain_candidate(&mut discovered_domain, domain);
        }
        modules_run.push("DNS");
    }

    // LDAP null bind (ports 389, 636, 3268, 3269)
    let ldap_ports = [389, 636, 3268, 3269];
    let ldap_open = open_ports.iter().find(|p| ldap_ports.contains(p)).copied();
    if let Some(port) = ldap_open {
        let ldap_info = ldap::run(&args.target, port, &no_tags).await?;
        if let Some(domain) = ldap_info.domain {
            add_domain_candidate(&mut discovered_domain, domain);
        }
        if let Some(hostname) = ldap_info.dns_hostname {
            if let Some(domain) = dns::domain_from_hostname(&hostname) {
                add_domain_candidate(&mut discovered_domain, domain);
            }
        }
        for user in ldap_info.usernames {
            add_user_candidate(&mut collected_users, user);
        }
        modules_run.push("LDAP");
    }

    if let Some(port) = ldap_open {
        if let (Some(user), Some(pass)) = (&args.username, &args.password) {
            if let Some(domain) = discovered_domain.as_deref() {
                let auth_result =
                    auth_recon::run(&args.target, port, user, pass, domain, &no_tags).await?;
                ldap_auth_ok = auth_result.ldap_bind_ok;
                for user in auth_result.usernames {
                    add_user_candidate(&mut collected_users, user);
                }
                auth_findings.extend(auth_result.findings);
                modules_run.push("Auth LDAP");
            } else {
                output::warning(
                    "No domain available for authenticated LDAP recon bundle; skipping auth LDAP findings",
                );
            }
        } else if args.username.is_some() && (args.ntlm.is_some() || kerberos_auth_effective) {
            output::warning(
                "Authenticated LDAP recon currently requires --password; skipping auth LDAP feature",
            );
        } else if args.username.is_some() {
            output::warning("Auth LDAP skipped: provide --password with --username");
        }
    }

    // SMB enumeration (port 445, 139)
    let smb_ports = [445, 139];
    if let Some(port) = open_ports.iter().find(|p| smb_ports.contains(p)).copied() {
        if let Some(info) = smb::run(&args.target, port, &no_tags).await? {
            if let Some(domain) = info
                .dns_domain_name
                .or(info.dns_tree_name)
                .or(info.netbios_domain_name)
            {
                add_domain_candidate(&mut discovered_domain, domain);
            }
            if let Some(name) = info.netbios_computer_name {
                add_user_candidate(&mut collected_users, format!("{}$", name));
            }
            if let Some(name) = info.dns_computer_name {
                let host = name.split('.').next().unwrap_or(&name).to_string();
                if !host.is_empty() {
                    add_user_candidate(&mut collected_users, format!("{}$", host));
                }
            }
        }
        if let Some(user) = args.username.as_deref() {
            let smb_auth_shares = smb::run_authenticated(
                &args.target,
                user,
                args.password.as_deref(),
                args.ntlm.as_deref(),
                kerberos_auth_effective,
                &no_tags,
            )
            .await?;
            smb_auth_ok = !smb_auth_shares.is_empty();
            for share in smb_auth_shares {
                let share_user = share
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .trim_end_matches('$')
                    .to_ascii_lowercase();
                if !share_user.is_empty() && share_user.len() > 2 {
                    add_user_candidate(&mut collected_users, share_user);
                }
            }
        }
        modules_run.push("SMB");
    }

    // RPC enumeration (port 135)
    if open_ports.contains(&135) {
        rpc::run(&args.target).await?;
        modules_run.push("RPC");
    }

    // Additional unauth attack-surface checks (AD CS relay surface, etc.)
    attacks::run(&args.target, &open_ports).await?;
    modules_run.push("Unauth Attack Surface");

    // Kerberos user enumeration (port 88)
    if open_ports.contains(&88) {
        let mut kerberos_users: Vec<String> = collected_users.iter().cloned().collect();
        kerberos_users.sort_by_key(|u| u.to_lowercase());

        kerberos::run(
            &args.target,
            discovered_domain.as_deref(),
            args.wordlist.as_deref(),
            &kerberos_users,
        )
        .await?;
        modules_run.push("Kerberos");
    }

    // Try every supported credential attack path when we have target/domain plus any creds/users.
    if let Some(domain) = discovered_domain.as_deref() {
        let mut all_users = collected_users.iter().cloned().collect::<Vec<_>>();
        all_users.sort_by_key(|u| u.to_lowercase());
        let cred_findings = credential_attacks::run(
            &args.target,
            domain,
            args.username.as_deref(),
            args.password.as_deref(),
            args.ntlm.as_deref(),
            kerberos_auth_effective,
            &all_users,
        )
        .await;
        auth_findings.extend(cred_findings);
        modules_run.push("Credential Attacks");
    } else {
        output::warning("Credential attacks skipped: domain unresolved");
    }

    // BloodHound collection (if credentials available)
    let auth_domain = discovered_domain.as_deref();

    if let (Some(user), Some(domain)) = (args.username.as_deref(), auth_domain) {
        bloodhound_ok = bloodhound::run_collection(
            &args.target,
            domain,
            user,
            args.password.as_deref(),
            args.ntlm.as_deref(),
            kerberos_auth_effective,
            &args.collection,
        )
        .await?;
        modules_run.push("BloodHound");
    } else if args.username.is_some()
        || args.password.is_some()
        || args.ntlm.is_some()
        || kerberos_auth_effective
    {
        output::warning(
            "Auth creds partially provided or domain unresolved — skipping BloodHound collection",
        );
    }

    // Final summary
    let elapsed = start.elapsed();
    output::section("SCAN COMPLETE");
    output::info(&format!(
        "{} open ports on {}",
        open_ports.len(),
        args.target
    ));

    if !modules_run.is_empty() {
        output::success(&format!("Modules executed: {}", modules_run.join(", ")));
    }

    if let Some(ref domain) = discovered_domain {
        output::success(&format!("Domain: {}", domain));
    }

    if !auth_findings.is_empty() {
        output::section("AUTH FINDINGS");
        for finding in &auth_findings {
            output::warning(&format!(
                "{} [{}]",
                finding.title,
                finding.severity.to_ascii_uppercase()
            ));
            output::kv("ID", &finding.id);
            output::kv("Evidence", &finding.evidence);
        }
    }

    if auth_enabled {
        output::section("CREDENTIAL VALIDATION");
        output::kv("LDAP (389/636)", if ldap_auth_ok { "working" } else { "not confirmed" });
        output::kv("SMB (445/139)", if smb_auth_ok { "working" } else { "not confirmed" });
        output::kv(
            "BloodHound collection",
            if bloodhound_ok { "working" } else { "not confirmed" },
        );
    }

    // JSON report export
    let mut usernames: Vec<String> = collected_users.into_iter().collect();
    usernames.sort_by_key(|u| u.to_lowercase());
    let report = report::RunReport {
        target: args.target.clone(),
        domain: discovered_domain.clone(),
        usernames_collected: usernames,
        authenticated_findings: auth_findings.clone(),
    };
    if let Err(e) = report::write_json(&args.report_json, &report) {
        output::warning(&format!("Failed to write JSON report: {}", e));
    } else {
        output::success(&format!("JSON report written: {}", args.report_json));
    }

    output::info(&format!("Completed in {:.2}s", elapsed.as_secs_f64()));
    println!();

    Ok(())
}

fn setup_run_output_dir(target: &str) {
    let cwd = match env::current_dir() {
        Ok(c) => c,
        Err(_) => return,
    };

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let safe_target = target
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect::<String>();

    let out_dir: PathBuf = cwd
        .join("results")
        .join(format!("{}_{}", safe_target, ts));

    if let Err(e) = fs::create_dir_all(&out_dir) {
        output::warning(&format!("Could not create run output dir {} ({})", out_dir.display(), e));
        return;
    }
    if let Err(e) = env::set_current_dir(&out_dir) {
        output::warning(&format!(
            "Could not switch to run output dir {} ({})",
            out_dir.display(),
            e
        ));
        return;
    }
    output::info(&format!("Results directory: {}", out_dir.display()));
}

fn add_domain_candidate(current: &mut Option<String>, candidate: String) {
    if current.is_none() {
        *current = Some(candidate.trim().to_ascii_lowercase());
    }
}

fn add_user_candidate(users: &mut HashSet<String>, candidate: String) {
    let trimmed = candidate.trim();
    if !trimmed.is_empty() {
        users.insert(trimmed.to_string());
    }
}

fn print_entry_points(open_ports: &[u16], auth_enabled: bool) {
    output::section("RECON ENTRY POINTS");
    output::info("Detected opportunities from open services:");

    if open_ports.contains(&53) {
        output::kv("DNS", "domain discovery, SRV records, recursion test");
    }
    if open_ports.iter().any(|p| matches!(*p, 389 | 636 | 3268 | 3269)) {
        output::kv("LDAP/GC", "RootDSE, anonymous reads, user discovery");
        if auth_enabled {
            output::kv("LDAP (auth)", "expanded directory/user collection");
        }
    }
    if open_ports.iter().any(|p| matches!(*p, 445 | 139)) {
        output::kv("SMB", "NTLM info leak, signing/null session/SMBv1 checks");
    }
    if open_ports.contains(&135) {
        output::kv("RPC", "endpoint mapper and coercion-surface hints");
    }
    if open_ports.iter().any(|p| matches!(*p, 80 | 443 | 8080 | 8443)) {
        output::kv("HTTP/S", "AD CS ESC8 relay precondition checks (/certsrv)");
    }
    if open_ports.contains(&88) {
        output::kv("Kerberos", "user enum, AS-REP roastable and pre2k-style machine account attempts");
    }
    if auth_enabled {
        output::kv(
            "BloodHound",
            "attempt `bloodhound-python --collection All --zip` using password/hash/kerberos methods",
        );
    }
}
