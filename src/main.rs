mod attacks;
mod auth_recon;
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
mod spray;
mod winrm;

use anyhow::{Context, Result};
use clap::builder::styling::{AnsiColor, Effects, Styles};
use clap::{Parser, ValueEnum};
use colored::*;
use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::time::Instant;
use std::time::{SystemTime, UNIX_EPOCH};

const MODULE_NAMES: &[&str] = &[
    "dns",
    "ldap",
    "auth-ldap",
    "smb",
    "rpc",
    "attacks",
    "kerberos",
    "spray",
    "credential-attacks",
    "winrm",
    "bloodhound",
];

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum RunMode {
    Auto,
    Semi,
    Manual,
}

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

    /// Execution mode: auto runs the full pipeline, semi skips noisy spray/attack/collection stages, manual requires --only
    #[arg(long, value_enum, default_value_t = RunMode::Auto, help_heading = "Execution")]
    mode: RunMode,

    /// Comma-separated module allowlist (dns,ldap,auth-ldap,smb,spray,rpc,attacks,kerberos,credential-attacks,winrm,bloodhound)
    #[arg(long, help_heading = "Execution")]
    only: Option<String>,

    /// Comma-separated check tags forwarded to modules (e.g. users,policy,signing,kerberoast,adcs)
    #[arg(long, help_heading = "Execution")]
    tags: Option<String>,

    /// Disable interactive confirmations and skip prompt-driven retries
    #[arg(long, help_heading = "Execution")]
    non_interactive: bool,

    /// Explicit password candidate to spray across discovered users over SMB
    #[arg(long, help_heading = "Execution")]
    spray_password: Option<String>,

    /// Optional username file for password spraying (one user per line)
    #[arg(long, help_heading = "Execution")]
    spray_userlist: Option<String>,

    /// Maximum usernames to try during password spraying
    #[arg(long, default_value = "50", help_heading = "Execution")]
    spray_max_users: usize,

    /// Delay between spray attempts in milliseconds
    #[arg(long, default_value = "250", help_heading = "Execution")]
    spray_delay_ms: u64,

    /// Username for authenticated AD recon (e.g., user or user@domain)
    #[arg(
        short = 'u',
        long = "username",
        visible_alias = "auth-user",
        help_heading = "Authentication"
    )]
    username: Option<String>,

    /// Password for authenticated AD recon
    #[arg(
        short = 'p',
        long = "password",
        visible_alias = "auth-pass",
        help_heading = "Authentication"
    )]
    password: Option<String>,

    /// NTLM hash for authenticated AD recon (NTHASH or LMHASH:NTHASH)
    #[arg(
        short = 'H',
        long = "ntlm",
        visible_alias = "auth-ntlm",
        help_heading = "Authentication"
    )]
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
    #[arg(
        long,
        default_value = "aydee_report.json",
        help_heading = "Collection/Output"
    )]
    report_json: String,

    /// Write plaintext operator summary to this path
    #[arg(
        long,
        default_value = "aydee_summary.txt",
        help_heading = "Collection/Output"
    )]
    report_text: String,

    /// Write workspace manifest JSON to this path
    #[arg(
        long,
        default_value = "workspace_manifest.json",
        help_heading = "Collection/Output"
    )]
    manifest_json: String,
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
    let started_unix = report::now_unix();
    let launch_cwd = env::current_dir().ok();
    let existing_ccache = env::var("KRB5CCNAME").ok();
    let selected_modules = parse_csv_list(args.only.as_deref());
    let selected_tags = parse_csv_list(args.tags.as_deref());
    setup_run_output_dir(&args.target);
    let results_dir = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

    // Show banner
    output::banner();
    output::info(&format!("Target: {}", args.target.white().bold()));
    if let Some(ref domain) = args.domain {
        output::info(&format!("Domain: {}", domain.white().bold()));
    }
    output::kv("Mode", run_mode_label(args.mode));
    if !selected_modules.is_empty() {
        output::kv("Module Filter", &selected_modules.join(", "));
    }
    if !selected_tags.is_empty() {
        output::kv("Tags", &selected_tags.join(", "));
    }
    if args.spray_password.is_some() {
        output::warning("Password spray is enabled for this run");
    }
    let kerberos_ticket_present = args.ccache.is_some() || existing_ccache.is_some();
    let kerberos_auth_enabled = args.kerberos_auth;

    if args.mode == RunMode::Manual && selected_modules.is_empty() {
        output::warning("Manual mode requires --only with at least one module name");
        output::kv("Available Modules", &MODULE_NAMES.join(", "));
        return Ok(());
    }

    if let Some(ref ccache) = args.ccache {
        let cache_value = resolve_ccache_env_value(launch_cwd.as_deref(), ccache);
        env::set_var("KRB5CCNAME", &cache_value);
        output::success("Kerberos ccache configured");
        output::kv("KRB5CCNAME", &cache_value);
    } else if let Some(ref cache_value) = existing_ccache {
        output::success("Using pre-exported Kerberos ccache from environment");
        output::kv("KRB5CCNAME", cache_value);
    }

    if args.username.is_some()
        && (args.password.is_some() || args.ntlm.is_some() || kerberos_auth_enabled)
    {
        output::success("Authenticated mode enabled");
    } else {
        output::info("Authenticated mode not enabled (no credentials provided)");
    }
    if kerberos_ticket_present && !kerberos_auth_enabled {
        output::info("Kerberos ticket cache detected, but -k/--kerberos not set (using password/hash paths only)");
    }

    if args.mode == RunMode::Semi && selected_modules.is_empty() {
        output::info(
            "Semi mode enabled: active stages (spray, kerberos, credential-attacks, bloodhound) stay skipped unless selected with --only",
        );
    }

    clock::maybe_fix_clock_skew(&args.target, !args.no_fix_clock_skew, args.non_interactive).await;

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
        && (args.password.is_some() || args.ntlm.is_some() || kerberos_auth_enabled);
    print_entry_points(&open_ports, auth_enabled);

    // Track discovered domain + usernames across modules
    let mut discovered_domain = args.domain.clone();
    let mut collected_users: HashSet<String> = HashSet::new();
    let mut auth_findings: Vec<auth_recon::AuthFinding> = Vec::new();
    let mut ldap_auth_ok = false;
    let mut smb_auth_ok = false;
    let mut winrm_auth_ok = false;
    let mut bloodhound_ok = false;
    let mut modules_run: Vec<&str> = Vec::new();
    let mut module_reports: Vec<report::ModuleReport> = Vec::new();

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
    if should_run_module(args.mode, &selected_modules, "dns") {
        if open_ports.contains(&53) {
            if let Ok(Some(domain)) = dns::run(&args.target).await {
                add_domain_candidate(&mut discovered_domain, domain);
            }
            modules_run.push("DNS");
            module_reports.push(module_record("dns", "completed", None::<String>));
        } else {
            module_reports.push(module_record("dns", "skipped", Some("port 53 closed")));
        }
    } else {
        module_reports.push(module_record(
            "dns",
            "skipped",
            Some("disabled by mode/selection"),
        ));
    }

    // LDAP null bind (ports 389, 636, 3268, 3269)
    let ldap_ports = [389, 636, 3268, 3269];
    let ldap_open = open_ports.iter().find(|p| ldap_ports.contains(p)).copied();
    if should_run_module(args.mode, &selected_modules, "ldap") {
        if let Some(port) = ldap_open {
            let ldap_info = ldap::run(&args.target, port, &selected_tags).await?;
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
            module_reports.push(module_record(
                "ldap",
                "completed",
                Some(format!("port {}", port)),
            ));
        } else {
            module_reports.push(module_record(
                "ldap",
                "skipped",
                Some("no LDAP/GC port open"),
            ));
        }
    } else {
        module_reports.push(module_record(
            "ldap",
            "skipped",
            Some("disabled by mode/selection"),
        ));
    }

    if should_run_module(args.mode, &selected_modules, "auth-ldap") {
        if let Some(port) = ldap_open {
            if let (Some(user), Some(pass)) = (&args.username, &args.password) {
                if let Some(domain) = discovered_domain.as_deref() {
                    let auth_result = auth_recon::run(
                        &args.target,
                        port,
                        user,
                        pass,
                        domain,
                        &selected_tags,
                        args.non_interactive,
                    )
                    .await?;
                    ldap_auth_ok = auth_result.ldap_bind_ok;
                    for user in auth_result.usernames {
                        add_user_candidate(&mut collected_users, user);
                    }
                    auth_findings.extend(auth_result.findings);
                    modules_run.push("Auth LDAP");
                    module_reports.push(module_record(
                        "auth-ldap",
                        "completed",
                        Some(format!("port {}", port)),
                    ));
                } else {
                    output::warning(
                        "No domain available for authenticated LDAP recon bundle; skipping auth LDAP findings",
                    );
                    module_reports.push(module_record(
                        "auth-ldap",
                        "skipped",
                        Some("domain unresolved"),
                    ));
                }
            } else if args.username.is_some() && (args.ntlm.is_some() || kerberos_auth_enabled) {
                output::warning(
                    "Authenticated LDAP recon currently requires --password; skipping auth LDAP feature",
                );
                module_reports.push(module_record(
                    "auth-ldap",
                    "skipped",
                    Some("password auth required"),
                ));
            } else if args.username.is_some() {
                output::warning("Auth LDAP skipped: provide --password with --username");
                module_reports.push(module_record(
                    "auth-ldap",
                    "skipped",
                    Some("password missing"),
                ));
            } else {
                module_reports.push(module_record(
                    "auth-ldap",
                    "skipped",
                    Some("no username supplied"),
                ));
            }
        } else {
            module_reports.push(module_record(
                "auth-ldap",
                "skipped",
                Some("no LDAP/GC port open"),
            ));
        }
    } else {
        module_reports.push(module_record(
            "auth-ldap",
            "skipped",
            Some("disabled by mode/selection"),
        ));
    }

    // SMB enumeration (port 445, 139)
    let smb_ports = [445, 139];
    if should_run_module(args.mode, &selected_modules, "smb") {
        if let Some(port) = open_ports.iter().find(|p| smb_ports.contains(p)).copied() {
            if let Some(info) = smb::run(&args.target, port, &selected_tags).await? {
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
                let smb_auth = smb::run_authenticated(
                    &args.target,
                    user,
                    args.password.as_deref(),
                    args.ntlm.as_deref(),
                    kerberos_auth_enabled,
                    &selected_tags,
                )
                .await?;
                smb_auth_ok = !smb_auth.shares.is_empty();
                auth_findings.extend(smb_auth.findings);
                for share in smb_auth.shares {
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
            module_reports.push(module_record(
                "smb",
                "completed",
                Some(format!("port {}", port)),
            ));
        } else {
            module_reports.push(module_record("smb", "skipped", Some("no SMB port open")));
        }
    } else {
        module_reports.push(module_record(
            "smb",
            "skipped",
            Some("disabled by mode/selection"),
        ));
    }

    if should_run_module(args.mode, &selected_modules, "spray") {
        if let Some(spray_password) = args.spray_password.as_deref() {
            if open_ports.iter().any(|p| smb_ports.contains(p)) {
                let mut all_users = collected_users.iter().cloned().collect::<Vec<_>>();
                all_users.sort_by_key(|u| u.to_lowercase());
                let spray_findings = spray::run_smb_password_spray(
                    &args.target,
                    discovered_domain.as_deref(),
                    spray_password,
                    args.username.as_deref(),
                    &all_users,
                    args.spray_userlist.as_deref(),
                    args.spray_max_users,
                    args.spray_delay_ms,
                )
                .await?;
                let finding_count = spray_findings.len();
                auth_findings.extend(spray_findings);
                modules_run.push("Password Spray");
                module_reports.push(module_record(
                    "spray",
                    "completed",
                    Some(format!("{} findings", finding_count)),
                ));
            } else {
                module_reports.push(module_record("spray", "skipped", Some("no SMB port open")));
            }
        } else {
            module_reports.push(module_record(
                "spray",
                "skipped",
                Some("no --spray-password supplied"),
            ));
        }
    } else {
        module_reports.push(module_record(
            "spray",
            "skipped",
            Some("disabled by mode/selection"),
        ));
    }

    // RPC enumeration (port 135)
    if should_run_module(args.mode, &selected_modules, "rpc") {
        if open_ports.contains(&135) {
            rpc::run(&args.target).await?;
            modules_run.push("RPC");
            module_reports.push(module_record("rpc", "completed", None::<String>));
        } else {
            module_reports.push(module_record("rpc", "skipped", Some("port 135 closed")));
        }
    } else {
        module_reports.push(module_record(
            "rpc",
            "skipped",
            Some("disabled by mode/selection"),
        ));
    }

    // Additional unauth attack-surface checks (AD CS relay surface, etc.)
    if should_run_module(args.mode, &selected_modules, "attacks") {
        attacks::run(&args.target, &open_ports).await?;
        modules_run.push("Unauth Attack Surface");
        module_reports.push(module_record("attacks", "completed", None::<String>));
    } else {
        module_reports.push(module_record(
            "attacks",
            "skipped",
            Some("disabled by mode/selection"),
        ));
    }

    // Kerberos user enumeration (port 88)
    if should_run_module(args.mode, &selected_modules, "kerberos") {
        if open_ports.contains(&88) {
            let mut kerberos_users: Vec<String> = collected_users.iter().cloned().collect();
            kerberos_users.sort_by_key(|u| u.to_lowercase());

            kerberos::run(
                &args.target,
                discovered_domain.as_deref(),
                args.wordlist.as_deref(),
                &kerberos_users,
                args.non_interactive,
            )
            .await?;
            modules_run.push("Kerberos");
            module_reports.push(module_record("kerberos", "completed", None::<String>));
        } else {
            module_reports.push(module_record("kerberos", "skipped", Some("port 88 closed")));
        }
    } else {
        module_reports.push(module_record(
            "kerberos",
            "skipped",
            Some("disabled by mode/selection"),
        ));
    }

    // Try every supported credential attack path when we have target/domain plus any creds/users.
    if should_run_module(args.mode, &selected_modules, "credential-attacks") {
        if let Some(domain) = discovered_domain.as_deref() {
            let mut all_users = collected_users.iter().cloned().collect::<Vec<_>>();
            all_users.sort_by_key(|u| u.to_lowercase());
            let cred_findings = credential_attacks::run(
                &args.target,
                domain,
                args.username.as_deref(),
                args.password.as_deref(),
                args.ntlm.as_deref(),
                kerberos_auth_enabled,
                &all_users,
            )
            .await;
            auth_findings.extend(cred_findings);
            modules_run.push("Credential Attacks");
            module_reports.push(module_record(
                "credential-attacks",
                "completed",
                Some(format!("{} findings", auth_findings.len())),
            ));
        } else {
            output::warning("Credential attacks skipped: domain unresolved");
            module_reports.push(module_record(
                "credential-attacks",
                "skipped",
                Some("domain unresolved"),
            ));
        }
    } else {
        module_reports.push(module_record(
            "credential-attacks",
            "skipped",
            Some("disabled by mode/selection"),
        ));
    }

    // BloodHound collection (if credentials available)
    let auth_domain = discovered_domain.as_deref();

    // WinRM credential validation/checks (if WinRM port open and credentials provided)
    if should_run_module(args.mode, &selected_modules, "winrm") {
        if open_ports.contains(&5985) || open_ports.contains(&5986) {
            if let Some(user) = args.username.as_deref() {
                winrm_auth_ok = winrm::run_authenticated(
                    &args.target,
                    user,
                    args.password.as_deref(),
                    args.ntlm.as_deref(),
                    kerberos_auth_enabled,
                )
                .await?;
                modules_run.push("WinRM");
                module_reports.push(module_record("winrm", "completed", None::<String>));
            } else {
                module_reports.push(module_record(
                    "winrm",
                    "skipped",
                    Some("no username supplied"),
                ));
            }
        } else {
            module_reports.push(module_record(
                "winrm",
                "skipped",
                Some("WinRM ports closed"),
            ));
        }
    } else {
        module_reports.push(module_record(
            "winrm",
            "skipped",
            Some("disabled by mode/selection"),
        ));
    }

    if should_run_module(args.mode, &selected_modules, "bloodhound") {
        if let (Some(user), Some(domain)) = (args.username.as_deref(), auth_domain) {
            bloodhound_ok = bloodhound::run_collection(
                &args.target,
                domain,
                user,
                args.password.as_deref(),
                args.ntlm.as_deref(),
                kerberos_auth_enabled,
                &args.collection,
            )
            .await?;
            modules_run.push("BloodHound");
            module_reports.push(module_record("bloodhound", "completed", None::<String>));
        } else if args.username.is_some()
            || args.password.is_some()
            || args.ntlm.is_some()
            || kerberos_auth_enabled
        {
            output::warning(
                "Auth creds partially provided or domain unresolved — skipping BloodHound collection",
            );
            module_reports.push(module_record(
                "bloodhound",
                "skipped",
                Some("domain unresolved or incomplete credentials"),
            ));
        } else {
            module_reports.push(module_record(
                "bloodhound",
                "skipped",
                Some("no credentials supplied"),
            ));
        }
    } else {
        module_reports.push(module_record(
            "bloodhound",
            "skipped",
            Some("disabled by mode/selection"),
        ));
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
        output::kv(
            "LDAP (389/636)",
            if ldap_auth_ok {
                "working"
            } else {
                "not confirmed"
            },
        );
        output::kv(
            "SMB (445/139)",
            if smb_auth_ok {
                "working"
            } else {
                "not confirmed"
            },
        );
        output::kv(
            "WinRM (5985/5986)",
            if winrm_auth_ok {
                "working"
            } else {
                "not confirmed"
            },
        );
        output::kv(
            "BloodHound collection",
            if bloodhound_ok {
                "working"
            } else {
                "not confirmed"
            },
        );
    }

    // JSON report export
    let mut usernames: Vec<String> = collected_users.into_iter().collect();
    usernames.sort_by_key(|u| u.to_lowercase());
    let report = report::RunReport {
        target: args.target.clone(),
        domain: discovered_domain.clone(),
        mode: run_mode_label(args.mode).to_string(),
        results_dir: results_dir.display().to_string(),
        selected_modules: selected_modules.clone(),
        selected_tags: selected_tags.clone(),
        open_ports: open_ports.clone(),
        usernames_collected: usernames,
        authenticated_findings: auth_findings.clone(),
        modules: module_reports.clone(),
        started_unix,
        duration_secs: elapsed.as_secs_f64(),
    };
    if let Err(e) = report::write_json(&args.report_json, &report) {
        output::warning(&format!("Failed to write JSON report: {}", e));
    } else {
        output::success(&format!("JSON report written: {}", args.report_json));
    }
    if let Err(e) = report::write_text(&args.report_text, &report) {
        output::warning(&format!("Failed to write text report: {}", e));
    } else {
        output::success(&format!("Text report written: {}", args.report_text));
    }
    match report::collect_artifacts(&results_dir) {
        Ok(artifacts) => {
            let manifest = report::WorkspaceManifest {
                target: args.target.clone(),
                domain: discovered_domain.clone(),
                results_dir: results_dir.display().to_string(),
                generated_unix: report::now_unix(),
                reports: vec![args.report_json.clone(), args.report_text.clone()],
                modules: module_reports,
                artifacts,
            };
            if let Err(e) = report::write_workspace_manifest(&args.manifest_json, &manifest) {
                output::warning(&format!("Failed to write workspace manifest: {}", e));
            } else {
                output::success(&format!(
                    "Workspace manifest written: {}",
                    args.manifest_json
                ));
            }
        }
        Err(e) => {
            output::warning(&format!("Failed to collect workspace artifacts: {}", e));
        }
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

    let out_dir: PathBuf = cwd.join("results").join(format!("{}_{}", safe_target, ts));

    if let Err(e) = fs::create_dir_all(&out_dir) {
        output::warning(&format!(
            "Could not create run output dir {} ({})",
            out_dir.display(),
            e
        ));
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
    let Some(candidate_norm) = dns::normalize_domain_name(&candidate) else {
        return;
    };
    match current {
        None => {
            *current = Some(candidate_norm);
        }
        Some(cur) => {
            if dns::should_replace_domain(cur, &candidate_norm) {
                *current = Some(candidate_norm);
            }
        }
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
    if open_ports
        .iter()
        .any(|p| matches!(*p, 389 | 636 | 3268 | 3269))
    {
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
    if open_ports
        .iter()
        .any(|p| matches!(*p, 80 | 443 | 8080 | 8443))
    {
        output::kv("HTTP/S", "AD CS ESC8 relay precondition checks (/certsrv)");
    }
    if open_ports.iter().any(|p| matches!(*p, 5985 | 5986)) {
        output::kv(
            "WinRM",
            "credential validation and remote management auth checks",
        );
    }
    if open_ports.contains(&88) {
        output::kv(
            "Kerberos",
            "user enum, AS-REP roastable and pre2k-style machine account attempts",
        );
    }
    if auth_enabled {
        output::kv(
            "BloodHound",
            "attempt `bloodhound-python --collection All --zip` using password/hash/kerberos methods",
        );
    }
}

fn parse_csv_list(spec: Option<&str>) -> Vec<String> {
    let mut out = spec
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_ascii_lowercase())
        .collect::<Vec<_>>();
    out.sort();
    out.dedup();
    out
}

fn run_mode_label(mode: RunMode) -> &'static str {
    match mode {
        RunMode::Auto => "auto",
        RunMode::Semi => "semi",
        RunMode::Manual => "manual",
    }
}

fn should_run_module(mode: RunMode, selected_modules: &[String], module: &str) -> bool {
    if selected_modules
        .iter()
        .any(|m| m == "all" || m.eq_ignore_ascii_case(module))
    {
        return true;
    }
    if !selected_modules.is_empty() {
        return false;
    }
    match mode {
        RunMode::Auto => true,
        RunMode::Semi => !matches!(
            module,
            "kerberos" | "spray" | "credential-attacks" | "bloodhound"
        ),
        RunMode::Manual => false,
    }
}

fn module_record(
    name: &str,
    status: &str,
    detail: Option<impl Into<String>>,
) -> report::ModuleReport {
    report::ModuleReport {
        name: name.to_string(),
        status: status.to_string(),
        detail: detail.map(|s| s.into()),
    }
}

fn resolve_ccache_env_value(base_dir: Option<&Path>, spec: &str) -> String {
    const PREFIXES: &[&str] = &["FILE:", "DIR:", "KEYRING:", "KCM:", "MEMORY:", "API:"];

    if let Some(prefix) = PREFIXES.iter().find(|prefix| {
        spec.len() >= prefix.len() && spec[..prefix.len()].eq_ignore_ascii_case(prefix)
    }) {
        let path_part = &spec[prefix.len()..];
        if prefix.eq_ignore_ascii_case("FILE:") {
            return format!("FILE:{}", absolutize_path(base_dir, path_part).display());
        }
        return spec.to_string();
    }

    format!("FILE:{}", absolutize_path(base_dir, spec).display())
}

fn absolutize_path(base_dir: Option<&Path>, path: &str) -> PathBuf {
    let candidate = PathBuf::from(path);
    if candidate.is_absolute() {
        return candidate;
    }
    if let Some(base) = base_dir {
        return base.join(candidate);
    }
    candidate
}

#[cfg(test)]
mod tests {
    use super::{
        absolutize_path, parse_csv_list, resolve_ccache_env_value, should_run_module, RunMode,
    };
    use std::path::Path;

    #[test]
    fn resolves_relative_ccache_against_launch_directory() {
        let base = Path::new("/tmp/aydee");
        let resolved = resolve_ccache_env_value(Some(base), "./alice.ccache");
        assert_eq!(resolved, "FILE:/tmp/aydee/./alice.ccache");
    }

    #[test]
    fn preserves_non_file_ccache_scheme() {
        let resolved =
            resolve_ccache_env_value(Some(Path::new("/tmp/aydee")), "KEYRING:persistent:42");
        assert_eq!(resolved, "KEYRING:persistent:42");
    }

    #[test]
    fn leaves_absolute_paths_unchanged() {
        let resolved = absolutize_path(Some(Path::new("/tmp/aydee")), "/tmp/alice.ccache");
        assert_eq!(resolved, Path::new("/tmp/alice.ccache"));
    }

    #[test]
    fn parses_csv_filters_case_insensitively() {
        let parsed = parse_csv_list(Some("LDAP, smb ,ldap"));
        assert_eq!(parsed, vec!["ldap".to_string(), "smb".to_string()]);
    }

    #[test]
    fn semi_mode_skips_active_modules_by_default() {
        assert!(!should_run_module(RunMode::Semi, &[], "kerberos"));
        assert!(!should_run_module(RunMode::Semi, &[], "spray"));
        assert!(should_run_module(RunMode::Semi, &[], "ldap"));
    }
}
