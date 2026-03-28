mod attacks;
mod bloodhound;
mod clock;
mod credential;
mod dns;
mod kerberos;
mod ldap;
mod report;
mod rpc;
mod scanner;
mod smb;
mod spray;
mod types;
mod ui;
mod winrm;

use anyhow::Result;
use clap::Parser;
use std::env;
use std::path::{Path, PathBuf};
use std::time::Instant;

#[allow(unused_imports)]
use types::{AuthMethod, AuthStrategy, LdapInfo, ModuleResult, RunMode};

// ── CLI arguments ───────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "aydee", version = "2.1.0")]
#[command(about = "Active Directory enumeration and reconnaissance toolkit")]
struct Args {
    /// Target DC IP or hostname
    #[arg(short, long, visible_alias = "dc")]
    target: String,

    /// Domain name (e.g., corp.local)
    #[arg(short, long)]
    domain: Option<String>,

    /// Username for authentication
    #[arg(short, long, visible_alias = "auth-user")]
    username: Option<String>,

    /// Password for authentication
    #[arg(short, long, visible_alias = "auth-pass")]
    password: Option<String>,

    /// NTLM hash (NTHASH or LMHASH:NTHASH)
    #[arg(short = 'H', long, visible_alias = "auth-ntlm")]
    ntlm: Option<String>,

    /// Use Kerberos authentication
    #[arg(short = 'k', long)]
    kerberos: bool,

    /// Kerberos ccache file path
    #[arg(long)]
    ccache: Option<String>,

    /// BloodHound collection scope (e.g., All, Default, DCOnly)
    #[arg(long, default_value = "All")]
    collection: String,

    /// Run mode: auto, semi, manual
    #[arg(short, long, value_enum, default_value_t = RunMode::Auto)]
    mode: RunMode,

    /// Only run these modules (comma-separated)
    #[arg(long, value_delimiter = ',')]
    only: Vec<String>,

    /// Only run checks with these tags (comma-separated)
    #[arg(long, value_delimiter = ',')]
    tags: Vec<String>,

    /// Custom port specification (e.g., "80,443,8080" or "1-1024" or "-" for all)
    #[arg(short = 'P', long)]
    ports: Option<String>,

    /// TCP connect timeout in seconds for port scanning
    #[arg(long, default_value_t = 2)]
    timeout: u64,

    /// LDAP port to use
    #[arg(long, default_value_t = 389)]
    ldap_port: u16,

    /// Wordlist for Kerberos user enumeration
    #[arg(short, long)]
    wordlist: Option<String>,

    /// Passwords for spray (comma-separated)
    #[arg(long, value_delimiter = ',', visible_alias = "spray-password")]
    spray_passwords: Vec<String>,

    /// External user list file for spray
    #[arg(long, visible_alias = "spray-userlist")]
    userlist: Option<String>,

    /// Max users per spray round
    #[arg(long, default_value_t = 50, visible_alias = "spray-max-users")]
    spray_limit: usize,

    /// Delay between spray attempts (ms)
    #[arg(long, default_value_t = 100, visible_alias = "spray-delay-ms")]
    spray_delay: u64,

    /// Disable startup clock skew fix attempts
    #[arg(long = "no-fix-clock-skew", visible_alias = "no-clock")]
    no_clock: bool,

    /// Verbose output (show subprocess output and debug info)
    #[arg(short, long)]
    verbose: bool,

    /// Quiet mode — only show findings and errors
    #[arg(short, long)]
    quiet: bool,

    /// Non-interactive mode (skip all prompts)
    #[arg(long)]
    non_interactive: bool,

    /// Output directory
    #[arg(short, long)]
    output: Option<String>,

    /// JSON report output path, relative to the results directory unless absolute
    #[arg(long, default_value = "aydee_report.json")]
    report_json: String,

    /// Text summary output path, relative to the results directory unless absolute
    #[arg(long, default_value = "aydee_summary.txt")]
    report_text: String,

    /// Workspace manifest output path, relative to the results directory unless absolute
    #[arg(long, default_value = "workspace_manifest.json")]
    manifest_json: String,
}

// ── Module list ─────────────────────────────────────────────────────────────

#[allow(dead_code)]
const ALL_MODULES: &[&str] = &[
    "scan",
    "dns",
    "ldap",
    "ldap-auth",
    "smb-auth",
    "rpc",
    "winrm",
    "kerberos",
    "spray",
    "credential",
    "bloodhound",
    "attacks",
];

// ── Main ────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let run_start = Instant::now();
    let launch_cwd = env::current_dir().ok();
    let existing_ccache = env::var("KRB5CCNAME").ok();

    // Set global verbose flag
    ui::set_verbose(args.verbose);
    ui::set_quiet(args.quiet);

    // Banner
    ui::banner();

    // Proxychains / tunnel detection
    if env::var("LD_PRELOAD").unwrap_or_default().contains("proxychains")
        || env::var("PROXYCHAINS_CONF_FILE").is_ok()
    {
        ui::warning("Proxychains detected — UDP-based modules (DNS, NTP clock sync) will likely fail");
        ui::info("Consider: --no-clock and providing -d <domain> manually to skip DNS discovery");
    }

    if let Some(ccache) = args.ccache.as_deref() {
        let cache_value = resolve_ccache_env_value(launch_cwd.as_deref(), ccache);
        env::set_var("KRB5CCNAME", &cache_value);
        ui::success("Kerberos ccache configured");
        ui::kv("KRB5CCNAME", &cache_value);
    } else if let Some(cache_value) = existing_ccache.as_deref() {
        ui::success("Using pre-exported Kerberos ccache from environment");
        ui::kv("KRB5CCNAME", cache_value);
    }

    // Auth strategy
    let auth = determine_auth_strategy(&args);
    let auth_label = match &auth {
        AuthStrategy::Supplied { method } => match method {
            AuthMethod::Password => "password",
            AuthMethod::NtlmHash => "ntlm-hash",
            AuthMethod::Kerberos => "kerberos",
        },
        AuthStrategy::AnonymousOnly => "anonymous",
        AuthStrategy::Incomplete => "incomplete",
    };

    // Target info box
    ui::target_box(
        &args.target,
        args.domain.as_deref(),
        args.username.as_deref(),
        &args.mode.to_string(),
    );
    ui::kv("Mode", &args.mode.to_string());
    if !args.only.is_empty() {
        ui::kv("Module Filter", &args.only.join(", "));
    }
    if !args.tags.is_empty() {
        ui::kv("Tags", &args.tags.join(", "));
    }
    if !args.spray_passwords.is_empty() {
        ui::warning("Password spray is enabled for this run");
    }

    if args.mode == RunMode::Manual && args.only.is_empty() {
        ui::warning("Manual mode requires --only with at least one module name");
        ui::kv("Available modules", &ALL_MODULES.join(", "));
        return Ok(());
    }

    if args.mode == RunMode::Semi && args.only.is_empty() {
        ui::info(
            "Semi mode enabled: noisy stages (kerberos, spray, credential, bloodhound) stay skipped unless explicitly selected",
        );
    }

    if (args.ccache.is_some() || existing_ccache.is_some()) && !args.kerberos {
        ui::info(
            "Kerberos ticket cache detected, but -k/--kerberos not set (using password/hash paths only)",
        );
    }

    // Clock sync — do this first so Kerberos works
    if !args.no_clock {
        clock::sync_clock(&args.target, args.non_interactive).await;
    }

    // Setup output directory
    let output_dir = setup_output_dir(&args.target, args.output.as_deref()).await?;

    // State
    let mut discovered_domain = args.domain.clone();
    let mut collected_users: Vec<String> = Vec::new();
    let mut open_ports: Vec<u16> = Vec::new();
    let mut ldap_info = LdapInfo::default();
    let mut module_results: Vec<ModuleResult> = Vec::new();

    let should_run = |module: &str| -> bool {
        let canonical = canonical_module_name(module);
        let selected = args
            .only
            .iter()
            .any(|m| canonical_module_name(m) == canonical);
        match args.mode {
            RunMode::Manual => selected,
            RunMode::Semi => {
                if matches!(
                    canonical.as_str(),
                    "kerberos" | "spray" | "credential" | "bloodhound"
                ) {
                    selected
                } else {
                    args.only.is_empty() || selected
                }
            }
            RunMode::Auto => args.only.is_empty() || selected,
        }
    };

    // ═══════════════════════════════════════════════════════════════════════
    //  STAGE 1: Port Scan
    // ═══════════════════════════════════════════════════════════════════════

    if should_run("scan") {
        match scanner::run(&args.target, args.ports.as_deref(), args.timeout).await {
            Ok(results) => {
                open_ports = results.iter().filter(|r| r.open).map(|r| r.port).collect();
                module_results.push(ModuleResult::new("scan").success(std::time::Duration::ZERO));
            }
            Err(e) => {
                ui::fail(&format!("Port scan failed: {}", e));
            }
        }
    }

    // Target DC validation
    if !open_ports.is_empty() {
        let dc_indicators = [88, 389, 636, 3268];
        let dc_port_count = dc_indicators.iter().filter(|p| open_ports.contains(p)).count();
        if dc_port_count == 0 && !open_ports.contains(&445) {
            ui::warning("Target does not appear to be a domain controller (no Kerberos, LDAP, or SMB ports detected)");
            ui::info("If intentional, ignore this warning. Otherwise verify the target IP with --dc <ip>");
        } else if dc_port_count == 0 {
            ui::info("Note: no LDAP/Kerberos ports open — target may be a member server rather than a DC");
        }
    }

    if discovered_domain.is_none() {
        if let Some(hostname) = dns::discover_domain_from_target(&args.target).await {
            if let Some(domain) = dns::domain_from_hostname(&hostname) {
                ui::success(&format!("Domain auto-discovered via target identity: {}", domain));
                discovered_domain = Some(domain);
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  STAGE 2: DNS Enumeration
    // ═══════════════════════════════════════════════════════════════════════

    if should_run("dns") && open_ports.contains(&53) {
        match dns::run(&args.target, discovered_domain.as_deref()).await {
            Ok((result, domain)) => {
                if discovered_domain.is_none() {
                    if let Some(d) = domain {
                        ui::success(&format!("Domain auto-discovered via DNS: {}", d));
                        discovered_domain = Some(d);
                    }
                }
                module_results.push(result);
            }
            Err(e) => ui::fail(&format!("DNS enumeration failed: {}", e)),
        }
    } else if should_run("dns") {
        ui::stage_skip("DNS", "port 53 not open");
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  STAGE 3: LDAP Fingerprint
    // ═══════════════════════════════════════════════════════════════════════

    if should_run("ldap")
        && (open_ports.contains(&389) || open_ports.contains(&636) || open_ports.contains(&3268))
    {
        let port = if open_ports.contains(&389) {
            389
        } else if open_ports.contains(&636) {
            636
        } else {
            3268
        };

        match ldap::fingerprint(&args.target, port).await {
            Ok((result, info)) => {
                if discovered_domain.is_none() {
                    if let Some(ref d) = info.domain {
                        ui::success(&format!("Domain auto-discovered via LDAP: {}", d));
                        discovered_domain = Some(d.clone());
                    }
                }
                ldap_info = info;
                module_results.push(result);
            }
            Err(e) => ui::fail(&format!("LDAP fingerprint failed: {}", e)),
        }

        // Anonymous bind
        if let Err(e) = ldap::run_anonymous(
            &args.target,
            port,
            ldap_info.naming_context.as_deref(),
        )
        .await
        {
            ui::fail(&format!("LDAP anonymous failed: {}", e));
        }

        // Merge any discovered users
        collected_users.extend(ldap_info.usernames.clone());
    } else if should_run("ldap") {
        ui::stage_skip("LDAP", "no LDAP port open");
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  STAGE 5: Authenticated Modules
    // ═══════════════════════════════════════════════════════════════════════

    if let AuthStrategy::Supplied { method: _ } = auth {
        let username = args.username.as_deref().unwrap_or("");
        let password = args.password.as_deref().unwrap_or("");
        let domain = discovered_domain.as_deref().unwrap_or("");

        if domain.is_empty() {
            ui::warning("No domain discovered — authenticated modules may not work correctly");
            ui::info("Hint: specify with -d <domain> or ensure LDAP port is open for auto-discovery");
        }

        // Authenticated LDAP
        if should_run("ldap-auth")
            && (open_ports.contains(&389) || open_ports.contains(&636))
        {
            let port = if open_ports.contains(&389) { 389 } else { 636 };
            match ldap::run_authenticated(
                &args.target,
                port,
                domain,
                username,
                password,
                args.ntlm.as_deref(),
                ldap_info.naming_context.as_deref(),
                &args.tags,
            )
            .await
            {
                Ok(result) => {
                    collected_users.extend(result.collected_users.clone());
                    module_results.push(result);
                }
                Err(e) => ui::fail(&format!("LDAP auth recon failed: {}", e)),
            }
        }

        // Authenticated SMB
        if should_run("smb-auth") && open_ports.contains(&445) {
            match smb::run_authenticated(
                &args.target,
                domain,
                username,
                password,
                args.ntlm.as_deref(),
                &args.tags,
            )
            .await
            {
                Ok(result) => module_results.push(result),
                Err(e) => ui::fail(&format!("SMB auth failed: {}", e)),
            }
        }

        // WinRM
        if should_run("winrm")
            && (open_ports.contains(&5985) || open_ports.contains(&5986))
        {
            match winrm::run(
                &args.target,
                domain,
                username,
                password,
                args.ntlm.as_deref(),
            )
            .await
            {
                Ok(result) => module_results.push(result),
                Err(e) => ui::fail(&format!("WinRM failed: {}", e)),
            }
        }

        // BloodHound collection
        if should_run("bloodhound") {
            if domain.is_empty() {
                ui::stage_skip("BLOODHOUND", "domain unresolved");
                module_results.push(ModuleResult::new("bloodhound").skipped("domain unresolved"));
            } else {
                match bloodhound::run(
                    &args.target,
                    domain,
                    username,
                    password,
                    args.ntlm.as_deref(),
                    args.kerberos,
                    &args.collection,
                    &output_dir,
                    args.non_interactive,
                )
                .await
                {
                    Ok(result) => module_results.push(result),
                    Err(e) => ui::fail(&format!("BloodHound failed: {}", e)),
                }
            }
        }

    }

    // ═══════════════════════════════════════════════════════════════════════
    //  STAGE 6: Unauthenticated Modules
    // ═══════════════════════════════════════════════════════════════════════

    // RPC
    if should_run("rpc") && open_ports.contains(&135) {
        match rpc::run(&args.target).await {
            Ok(result) => module_results.push(result),
            Err(e) => ui::fail(&format!("RPC enumeration failed: {}", e)),
        }
    }

    // Attack surface
    if should_run("attacks") {
        match attacks::run(&args.target, &open_ports).await {
            Ok(result) => module_results.push(result),
            Err(e) => ui::fail(&format!("Attack surface check failed: {}", e)),
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  STAGE 7: Active Attacks
    // ═══════════════════════════════════════════════════════════════════════

    // Kerberos enumeration
    if should_run("kerberos") && open_ports.contains(&88) {
        match kerberos::run(
            &args.target,
            discovered_domain.as_deref(),
            args.wordlist.as_deref(),
            &collected_users,
            args.non_interactive,
        )
        .await
        {
            Ok(result) => {
                collected_users.extend(result.collected_users.clone());
                module_results.push(result);
            }
            Err(e) => ui::fail(&format!("Kerberos enum failed: {}", e)),
        }
    }

    if should_run("credential") {
        if let Some(domain) = discovered_domain.as_deref() {
            match credential::run(
                &args.target,
                domain,
                args.username.as_deref().unwrap_or(""),
                args.password.as_deref().unwrap_or(""),
                args.ntlm.as_deref(),
                args.kerberos,
                &output_dir,
                &collected_users,
            )
            .await
            {
                Ok(result) => module_results.push(result),
                Err(e) => ui::fail(&format!("Credential attacks failed: {}", e)),
            }
        } else {
            ui::stage_skip("CRED ATTACKS", "domain unresolved");
            module_results.push(
                ModuleResult::new("credential-attacks").skipped("domain unresolved"),
            );
        }
    }

    // Password spray
    if should_run("spray") && !args.spray_passwords.is_empty() {
        // Extract password policy from LDAP results if available
        let password_policy = module_results
            .iter()
            .find_map(|r| r.password_policy.as_ref());

        match spray::run(
            &args.target,
            discovered_domain.as_deref().unwrap_or(""),
            &args.spray_passwords,
            &collected_users,
            args.userlist.as_deref(),
            args.spray_limit,
            args.spray_delay,
            args.non_interactive,
            password_policy,
        )
        .await
        {
            Ok(result) => module_results.push(result),
            Err(e) => ui::fail(&format!("Password spray failed: {}", e)),
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  ATTACK PATH CORRELATION
    // ═══════════════════════════════════════════════════════════════════════

    {
        let all_findings: Vec<&types::Finding> = module_results
            .iter()
            .flat_map(|r| r.findings.iter())
            .collect();

        let has_no_signing = all_findings
            .iter()
            .any(|f| f.id == "SMB-SIGN-001");
        let has_coercion = all_findings
            .iter()
            .any(|f| f.id.starts_with("COERCE-"));
        let has_esc8 = all_findings
            .iter()
            .any(|f| f.id == "ADCS-ESC8");
        let has_maq = all_findings
            .iter()
            .any(|f| f.id == "MAQ-001");
        let has_webdav = all_findings
            .iter()
            .any(|f| f.id == "WEBDAV-001");
        let has_esc1 = all_findings
            .iter()
            .any(|f| f.id == "ADCS-ESC1");

        let mut attack_paths = Vec::new();

        if has_coercion && has_esc8 {
            attack_paths.push("Coercion + ADCS ESC8 → relay NTLM auth to Web Enrollment → domain admin cert");
        }
        if has_coercion && has_no_signing {
            attack_paths.push("Coercion + no SMB signing → relay NTLM to SMB for code execution");
        }
        if has_maq && has_no_signing {
            attack_paths.push("MAQ > 0 + no SMB signing → create machine account + RBCD relay → impersonate any user");
        }
        if has_webdav && has_coercion {
            attack_paths.push("WebDAV + coercion → cross-protocol relay (HTTP→LDAP/SMB)");
        }
        if has_esc1 {
            attack_paths.push("ESC1 template → enroll cert as any user → domain admin via PKINIT");
        }
        if has_maq && has_coercion && has_esc8 {
            attack_paths.push("MAQ + coercion + ESC8 → full relay chain: create machine → coerce DC → relay to ADCS");
        }

        if !attack_paths.is_empty() {
            ui::section("ATTACK PATH CORRELATION");
            for path in &attack_paths {
                ui::warning(path);
            }

            let mut relay_result = ModuleResult::new("relay-map");
            let finding = types::Finding::new(
                "relay-map",
                "RELAY-MAP",
                types::Severity::Critical,
                &format!("{} viable attack path(s) identified", attack_paths.len()),
            )
            .with_description(&attack_paths.join("\n"))
            .with_recommendation(
                "Priority: enforce SMB signing, disable unnecessary coercion services, harden ADCS, set MAQ to 0",
            )
            .with_mitre("T1557.001");
            relay_result.findings.push(finding);
            relay_result = relay_result.success(std::time::Duration::ZERO);
            module_results.push(relay_result);
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  STAGE 8: Reporting
    // ═══════════════════════════════════════════════════════════════════════

    // Deduplicate collected users
    collected_users.sort_by_key(|u| u.to_lowercase());
    collected_users.dedup_by(|a, b| a.to_lowercase() == b.to_lowercase());

    report::generate(
        &args.target,
        discovered_domain.as_deref(),
        &args.mode.to_string(),
        auth_label,
        &open_ports,
        &collected_users,
        &module_results,
        &output_dir,
        &args.report_json,
        &args.report_text,
        &args.manifest_json,
    )
    .await?;

    // Final summary
    let total_duration = run_start.elapsed();
    println!();
    ui::section("RUN COMPLETE");
    ui::kv("Total time", &format!("{:.1}s", total_duration.as_secs_f64()));
    ui::kv("Output", &output_dir);
    ui::kv("Users collected", &collected_users.len().to_string());
    ui::kv(
        "Findings",
        &module_results
            .iter()
            .map(|m| m.findings.len())
            .sum::<usize>()
            .to_string(),
    );
    println!();

    Ok(())
}

// ── Auth strategy ───────────────────────────────────────────────────────────

fn determine_auth_strategy(args: &Args) -> AuthStrategy {
    let has_user = args.username.is_some();
    let has_pass = args.password.is_some();
    let has_ntlm = args.ntlm.is_some();
    let has_kerb = args.kerberos;

    if has_user && has_pass {
        AuthStrategy::Supplied {
            method: AuthMethod::Password,
        }
    } else if has_user && has_ntlm {
        AuthStrategy::Supplied {
            method: AuthMethod::NtlmHash,
        }
    } else if has_user && has_kerb {
        AuthStrategy::Supplied {
            method: AuthMethod::Kerberos,
        }
    } else if has_user || has_pass || has_ntlm {
        ui::warning("Incomplete credentials — authenticated modules will be skipped");
        AuthStrategy::Incomplete
    } else {
        AuthStrategy::AnonymousOnly
    }
}

fn canonical_module_name(name: &str) -> String {
    let name = name.trim();
    if name.eq_ignore_ascii_case("auth-ldap") || name.eq_ignore_ascii_case("ldap-auth") {
        "ldap-auth".to_string()
    } else if name.eq_ignore_ascii_case("credential-attacks")
        || name.eq_ignore_ascii_case("credential")
    {
        "credential".to_string()
    } else {
        name.to_ascii_lowercase()
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

// ── Output directory ────────────────────────────────────────────────────────

async fn setup_output_dir(target: &str, custom: Option<&str>) -> Result<String> {
    let dir = match custom {
        Some(d) => d.to_string(),
        None => {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let sanitized = target.replace('.', "_").replace(':', "_");
            format!("results/{}_{}", sanitized, ts)
        }
    };

    tokio::fs::create_dir_all(&dir).await?;
    ui::kv("Output dir", &dir);
    Ok(dir)
}
