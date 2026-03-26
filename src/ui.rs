use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use colored::Colorize;
use comfy_table::presets::UTF8_FULL_CONDENSED;
use comfy_table::{Attribute, Cell, CellAlignment, Color as TblColor, Table};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};

use crate::types::{Finding, PortResult, RiskScore, Severity};

// ── Verbose flag ───────────────────────────────────────────────────────────

static VERBOSE: AtomicBool = AtomicBool::new(false);

pub fn set_verbose(v: bool) {
    VERBOSE.store(v, Ordering::Relaxed);
}

pub fn is_verbose() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}

/// Print only when -v is set. Prefixed with dim [DBG].
pub fn verbose(msg: &str) {
    if is_verbose() {
        println!("  {} {}", "[DBG]".bright_black(), msg.bright_black());
    }
}

/// Print subprocess output lines when -v is set.
pub fn verbose_output(label: &str, output: &str) {
    if !is_verbose() {
        return;
    }
    for line in output.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            println!(
                "  {} {} {}",
                "[>]".bright_black(),
                format!("{}:", label).bright_black(),
                trimmed.bright_black()
            );
        }
    }
}

// ── Banner ──────────────────────────────────────────────────────────────────

pub fn banner() {
    let art = r#"
      ██████╗ ██╗ ██╗ ██████╗ ██████╗ ██████╗
     ██╔══██╗╚██╗ ██╔╝██╔══██╗██╔═══╝ ██╔═══╝
     ███████║ ╚████╔╝ ██║  ██║█████╗  █████╗
     ██╔══██║  ╚██╔╝  ██║  ██║██╔══╝  ██╔══╝
     ██║  ██║   ██║   ██████╔╝██████╗ ██████╗
     ╚═╝  ╚═╝   ╚═╝   ╚═════╝ ╚═════╝ ╚═════╝
"#;
    println!("{}", art.bright_red());
    println!(
        "     {}  {}",
        "Active Directory Recon Engine".bright_white().bold(),
        "v2.0.0".bright_black()
    );
    println!(
        "     {}\n",
        "─────────────────────────────────────────"
            .bright_black()
    );
}

// ── Target info box ─────────────────────────────────────────────────────────

pub fn target_box(target: &str, domain: Option<&str>, user: Option<&str>, mode: &str) {
    let border = "│".bright_black();
    let top = format!(
        "  {}",
        "┌─ Target ──────────────────────────────────────┐".bright_black()
    );
    let bot = format!(
        "  {}",
        "└───────────────────────────────────────────────┘".bright_black()
    );

    println!("{}", top);
    println!(
        "  {} {:<10} {:>33} {}",
        border,
        "Host".bright_cyan(),
        target.bright_white().bold(),
        border
    );
    if let Some(d) = domain {
        println!(
            "  {} {:<10} {:>33} {}",
            border,
            "Domain".bright_cyan(),
            d.bright_white().bold(),
            border
        );
    }
    if let Some(u) = user {
        println!(
            "  {} {:<10} {:>33} {}",
            border,
            "User".bright_cyan(),
            u.bright_white(),
            border
        );
    }
    println!(
        "  {} {:<10} {:>33} {}",
        border,
        "Mode".bright_cyan(),
        mode.bright_yellow(),
        border
    );
    println!("{}\n", bot);
}

// ── Section headers ─────────────────────────────────────────────────────────

pub fn section(name: &str) {
    println!();
    let line = "━".repeat(50 - name.len().min(40));
    println!(
        "  {} {} {}",
        "▸".bright_red().bold(),
        name.bright_red().bold(),
        line.bright_black()
    );
}

// ── Status messages ─────────────────────────────────────────────────────────

pub fn success(msg: &str) {
    println!("  {} {}", "[+]".green().bold(), msg);
}

pub fn info(msg: &str) {
    println!("  {} {}", "[*]".blue().bold(), msg);
}

pub fn warning(msg: &str) {
    println!("  {} {}", "[!]".yellow().bold(), msg);
}

pub fn fail(msg: &str) {
    println!("  {} {}", "[-]".red().bold(), msg);
}

// ── Key-value output ────────────────────────────────────────────────────────

pub fn kv(key: &str, value: &str) {
    let val = compact_value(value, 90);
    println!(
        "    {}: {}",
        key.bright_cyan(),
        val.white()
    );
}

#[allow(dead_code)]
pub fn kv_indent(key: &str, value: &str, indent: usize) {
    let pad = " ".repeat(indent);
    let val = compact_value(value, 90 - indent);
    println!(
        "{}{}: {}",
        pad,
        key.bright_cyan(),
        val.white()
    );
}

fn compact_value(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let clipped: String = s.chars().take(max.saturating_sub(8)).collect();
        format!("{} {}", clipped, "<snip>".bright_black())
    }
}

// ── Spinners ────────────────────────────────────────────────────────────────

static TICK_CHARS: &str = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏";

pub fn spinner(prefix: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::with_template("  {spinner:.red.bold} {prefix:.bold} {msg}")
            .unwrap()
            .tick_chars(TICK_CHARS),
    );
    pb.set_prefix(prefix.to_string());
    pb.enable_steady_tick(Duration::from_millis(80));
    pb
}

#[allow(dead_code)]
pub fn spinner_in(mp: &MultiProgress, prefix: &str) -> ProgressBar {
    let pb = mp.add(ProgressBar::new_spinner());
    pb.set_style(
        ProgressStyle::with_template("  {spinner:.red.bold} {prefix:.bold} {msg}")
            .unwrap()
            .tick_chars(TICK_CHARS),
    );
    pb.set_prefix(prefix.to_string());
    pb.enable_steady_tick(Duration::from_millis(80));
    pb
}

pub fn progress_bar(total: u64, prefix: &str) -> ProgressBar {
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::with_template(
            "  {prefix:.bold} [{bar:30.red/bright_black}] {pos}/{len} {msg} ({elapsed})",
        )
        .unwrap()
        .progress_chars("━╸─"),
    );
    pb.set_prefix(prefix.to_string());
    pb
}

pub fn finish_spinner(pb: &ProgressBar, msg: &str) {
    pb.set_style(
        ProgressStyle::with_template("  {prefix:.bold} {msg}")
            .unwrap(),
    );
    pb.finish_with_message(format!("{}", msg.green()));
}

pub fn finish_spinner_warn(pb: &ProgressBar, msg: &str) {
    pb.set_style(
        ProgressStyle::with_template("  {prefix:.bold} {msg}")
            .unwrap(),
    );
    pb.finish_with_message(format!("{}", msg.yellow()));
}

pub fn finish_spinner_fail(pb: &ProgressBar, msg: &str) {
    pb.set_style(
        ProgressStyle::with_template("  {prefix:.bold} {msg}")
            .unwrap(),
    );
    pb.finish_with_message(format!("{}", msg.red()));
}

// ── Port table ──────────────────────────────────────────────────────────────

pub fn port_table(results: &[PortResult]) {
    let open: Vec<&PortResult> = results.iter().filter(|r| r.open).collect();
    if open.is_empty() {
        warning("No open ports found");
        return;
    }

    let mut table = Table::new();
    table.load_preset(UTF8_FULL_CONDENSED);
    table.set_header(vec![
        Cell::new("Port")
            .add_attribute(Attribute::Bold)
            .fg(TblColor::White),
        Cell::new("State")
            .add_attribute(Attribute::Bold)
            .fg(TblColor::White),
        Cell::new("Service")
            .add_attribute(Attribute::Bold)
            .fg(TblColor::White),
    ]);

    for r in &open {
        table.add_row(vec![
            Cell::new(r.port)
                .set_alignment(CellAlignment::Right)
                .fg(TblColor::Cyan),
            Cell::new("open").fg(TblColor::Green),
            Cell::new(&r.service).fg(TblColor::White),
        ]);
    }

    // Indent the table
    for line in table.to_string().lines() {
        println!("  {}", line);
    }
}

// ── Findings table ──────────────────────────────────────────────────────────

pub fn findings_summary(findings: &[Finding]) {
    if findings.is_empty() {
        info("No findings to report");
        return;
    }

    let mut sorted = findings.to_vec();
    sorted.sort_by(|a, b| b.severity.cmp(&a.severity));

    let mut table = Table::new();
    table.load_preset(UTF8_FULL_CONDENSED);
    table.set_header(vec![
        Cell::new("Sev")
            .add_attribute(Attribute::Bold)
            .fg(TblColor::White),
        Cell::new("ID")
            .add_attribute(Attribute::Bold)
            .fg(TblColor::White),
        Cell::new("Title")
            .add_attribute(Attribute::Bold)
            .fg(TblColor::White),
        Cell::new("Module")
            .add_attribute(Attribute::Bold)
            .fg(TblColor::White),
    ]);

    for f in &sorted {
        let sev_color = match f.severity {
            Severity::Critical => TblColor::Red,
            Severity::High => TblColor::DarkRed,
            Severity::Medium => TblColor::Yellow,
            Severity::Low => TblColor::Cyan,
            Severity::Info => TblColor::White,
        };

        let title_trunc = if f.title.len() > 52 {
            format!("{}...", &f.title[..49])
        } else {
            f.title.clone()
        };

        table.add_row(vec![
            Cell::new(f.severity.label())
                .fg(sev_color)
                .add_attribute(Attribute::Bold),
            Cell::new(&f.id).fg(TblColor::DarkGrey),
            Cell::new(&title_trunc),
            Cell::new(&f.module).fg(TblColor::DarkGrey),
        ]);
    }

    for line in table.to_string().lines() {
        println!("  {}", line);
    }
}

// ── Risk score display ──────────────────────────────────────────────────────

pub fn risk_score_display(score: &RiskScore) {
    section("RISK ASSESSMENT");
    println!();

    let rating_color = match score.rating() {
        "HARDENED" => "green",
        "LOW RISK" => "cyan",
        "MODERATE RISK" => "yellow",
        "HIGH RISK" => "red",
        _ => "bright_red",
    };

    let rating_str = score.rating();
    let colored_rating = match rating_color {
        "green" => rating_str.green().bold().to_string(),
        "cyan" => rating_str.cyan().bold().to_string(),
        "yellow" => rating_str.yellow().bold().to_string(),
        "red" => rating_str.red().bold().to_string(),
        _ => rating_str.bright_red().bold().to_string(),
    };

    println!("  {} {}", "Rating:".bright_white().bold(), colored_rating);
    println!(
        "  {} {}",
        "Score:".bright_white().bold(),
        format!("{}", score.total).bright_white()
    );
    println!();

    if score.critical > 0 {
        println!(
            "    {} {} critical",
            "●".bright_red(),
            score.critical
        );
    }
    if score.high > 0 {
        println!("    {} {} high", "●".red(), score.high);
    }
    if score.medium > 0 {
        println!("    {} {} medium", "●".yellow(), score.medium);
    }
    if score.low > 0 {
        println!("    {} {} low", "●".cyan(), score.low);
    }
    if score.info > 0 {
        println!("    {} {} info", "●".white(), score.info);
    }
}

// ── Entry points ────────────────────────────────────────────────────────────

pub fn entry_points(open_ports: &[u16]) {
    if open_ports.is_empty() {
        return;
    }

    println!();
    info("Attack surface entry points:");

    let mut hints = Vec::new();
    for &p in open_ports {
        match p {
            88 => hints.push("  ├─ Kerberos (88) → user enumeration, AS-REP roasting, Kerberoasting"),
            135 => hints.push("  ├─ RPC (135) → endpoint enumeration, coercion attacks"),
            389 => hints.push("  ├─ LDAP (389) → anonymous bind, domain enumeration"),
            445 => hints.push("  ├─ SMB (445) → null session, share enumeration, relay"),
            636 => hints.push("  ├─ LDAPS (636) → channel binding check"),
            5985 => hints.push("  ├─ WinRM (5985) → credential validation, lateral movement"),
            80 | 8080 => hints.push("  ├─ HTTP → AD CS Web Enrollment, NTLM relay (ESC8)"),
            443 | 8443 => hints.push("  ├─ HTTPS → AD CS Web Enrollment"),
            _ => {}
        }
    }

    for (i, h) in hints.iter().enumerate() {
        if i == hints.len() - 1 {
            // Replace ├─ with └─ for last item
            println!("{}", h.replace("├─", "└─").bright_black());
        } else {
            println!("{}", h.bright_black());
        }
    }
}

// ── Stage summary line ──────────────────────────────────────────────────────

pub fn stage_done(name: &str, detail: &str, elapsed: &str) {
    println!(
        "  {} {} {} {}",
        "✓".green().bold(),
        name.bright_white().bold(),
        detail.bright_black(),
        format!("({})", elapsed).bright_black()
    );
}

pub fn stage_skip(name: &str, reason: &str) {
    println!(
        "  {} {} {}",
        "○".bright_black(),
        name.bright_black(),
        format!("— {}", reason).bright_black()
    );
}
