use anyhow::Result;
use chrono::Utc;
use std::path::{Path, PathBuf};

use crate::types::{Finding, ModuleResult, RiskScore, RunReport, Severity};
use crate::ui;

/// Generate all report outputs.
pub async fn generate(
    target: &str,
    domain: Option<&str>,
    mode: &str,
    auth_method: &str,
    open_ports: &[u16],
    collected_users: &[String],
    modules: &[ModuleResult],
    output_dir: &str,
    report_json: &str,
    report_text: &str,
    manifest_json: &str,
) -> Result<()> {
    ui::section("REPORT GENERATION");
    let spin = ui::spinner("REPORT");

    // Collect all findings
    let mut all_findings: Vec<Finding> = Vec::new();
    for m in modules {
        all_findings.extend(m.findings.clone());
    }
    all_findings.sort_by(|a, b| b.severity.cmp(&a.severity));

    let risk_score = RiskScore::from_findings(&all_findings);

    // Build report
    let report = RunReport {
        tool: "aydee".to_string(),
        version: "2.0.0".to_string(),
        target: target.to_string(),
        domain: domain.map(|s| s.to_string()),
        mode: mode.to_string(),
        auth_method: auth_method.to_string(),
        start_time: Utc::now().to_rfc3339(),
        duration_ms: modules.iter().map(|m| m.duration_ms).sum(),
        open_ports: open_ports.to_vec(),
        collected_users: collected_users.to_vec(),
        modules: modules.to_vec(),
        findings: all_findings.clone(),
        risk_score: risk_score.clone(),
    };

    // JSON report
    spin.set_message("writing JSON report...");
    let json_path = resolve_output_path(output_dir, report_json);
    let json = serde_json::to_string_pretty(&report)?;
    write_output_file(&json_path, &json).await?;

    // Text summary
    spin.set_message("writing text summary...");
    let text_path = resolve_output_path(output_dir, report_text);
    let text = generate_text_summary(&report);
    write_output_file(&text_path, &text).await?;

    // HTML report
    spin.set_message("writing HTML report...");
    let html_path = Path::new(output_dir).join("aydee_report.html");
    let html = generate_html_report(&report);
    write_output_file(&html_path, &html).await?;

    // Workspace manifest
    spin.set_message("writing manifest...");
    let manifest_path = resolve_output_path(output_dir, manifest_json);
    let manifest = generate_manifest(output_dir).await?;
    write_output_file(&manifest_path, &manifest).await?;

    ui::finish_spinner(&spin, "reports generated");
    ui::kv("JSON", &json_path.display().to_string());
    ui::kv("Text", &text_path.display().to_string());
    ui::kv("HTML", &html_path.display().to_string());
    ui::kv("Manifest", &manifest_path.display().to_string());

    // Display risk score and findings summary
    ui::risk_score_display(&risk_score);
    println!();
    ui::section("FINDINGS SUMMARY");
    ui::findings_summary(&all_findings);

    Ok(())
}

fn resolve_output_path(output_dir: &str, spec: &str) -> PathBuf {
    let path = PathBuf::from(spec);
    if path.is_absolute() {
        path
    } else {
        Path::new(output_dir).join(path)
    }
}

async fn write_output_file(path: &Path, contents: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(path, contents).await?;
    Ok(())
}

// ── Text report ─────────────────────────────────────────────────────────────

fn generate_text_summary(report: &RunReport) -> String {
    let mut out = String::new();

    out.push_str("════════════════════════════════════════════════════════\n");
    out.push_str("  AyDee 2 — Active Directory Recon Report\n");
    out.push_str("════════════════════════════════════════════════════════\n\n");

    out.push_str(&format!("Target:     {}\n", report.target));
    out.push_str(&format!(
        "Domain:     {}\n",
        report.domain.as_deref().unwrap_or("unknown")
    ));
    out.push_str(&format!("Mode:       {}\n", report.mode));
    out.push_str(&format!("Auth:       {}\n", report.auth_method));
    out.push_str(&format!("Time:       {}\n", report.start_time));
    out.push_str(&format!("Duration:   {}ms\n\n", report.duration_ms));

    out.push_str(&format!(
        "Open Ports: {}\n",
        report
            .open_ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    ));
    out.push_str(&format!("Users:      {} collected\n\n", report.collected_users.len()));

    // Risk score
    out.push_str(&format!(
        "Risk Rating: {} (score: {})\n",
        report.risk_score.rating(),
        report.risk_score.total
    ));
    out.push_str(&format!(
        "  Critical: {}  High: {}  Medium: {}  Low: {}  Info: {}\n\n",
        report.risk_score.critical,
        report.risk_score.high,
        report.risk_score.medium,
        report.risk_score.low,
        report.risk_score.info,
    ));

    // Findings
    out.push_str("──────────────────────────────────────────────────────\n");
    out.push_str("  FINDINGS\n");
    out.push_str("──────────────────────────────────────────────────────\n\n");

    for f in &report.findings {
        out.push_str(&format!("[{}] {} ({})\n", f.severity, f.title, f.id));
        if !f.description.is_empty() {
            out.push_str(&format!("  Description: {}\n", f.description));
        }
        if !f.evidence.is_empty() {
            out.push_str(&format!("  Evidence: {}\n", f.evidence.join("; ")));
        }
        if !f.recommendation.is_empty() {
            out.push_str(&format!("  Recommendation: {}\n", f.recommendation));
        }
        if let Some(ref mitre) = f.mitre {
            out.push_str(&format!("  MITRE ATT&CK: {}\n", mitre));
        }
        out.push('\n');
    }

    // Modules
    out.push_str("──────────────────────────────────────────────────────\n");
    out.push_str("  MODULE RESULTS\n");
    out.push_str("──────────────────────────────────────────────────────\n\n");

    for m in &report.modules {
        let status = match &m.status {
            crate::types::ModuleStatus::Complete => "COMPLETE".to_string(),
            crate::types::ModuleStatus::Failed(e) => format!("FAILED: {}", e),
            crate::types::ModuleStatus::Skipped(r) => format!("SKIPPED: {}", r),
            crate::types::ModuleStatus::Running => "RUNNING".to_string(),
            crate::types::ModuleStatus::Pending => "PENDING".to_string(),
        };
        out.push_str(&format!(
            "  {:<25} {} ({}ms, {} findings)\n",
            m.name,
            status,
            m.duration_ms,
            m.findings.len()
        ));
    }

    out
}

// ── HTML report ─────────────────────────────────────────────────────────────

fn generate_html_report(report: &RunReport) -> String {
    let mut html = String::new();

    html.push_str(r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AyDee 2 — AD Recon Report</title>
<style>
:root {
    --bg: #0d1117;
    --surface: #161b22;
    --border: #30363d;
    --text: #e6edf3;
    --muted: #8b949e;
    --red: #f85149;
    --orange: #d29922;
    --yellow: #e3b341;
    --green: #3fb950;
    --blue: #58a6ff;
    --purple: #bc8cff;
    --cyan: #39d353;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
    font-family: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace;
    background: var(--bg);
    color: var(--text);
    line-height: 1.6;
    padding: 2rem;
}
.container { max-width: 1100px; margin: 0 auto; }
h1 {
    color: var(--red);
    font-size: 1.8rem;
    border-bottom: 2px solid var(--red);
    padding-bottom: 0.5rem;
    margin-bottom: 1rem;
}
h2 {
    color: var(--blue);
    font-size: 1.2rem;
    margin-top: 2rem;
    margin-bottom: 0.5rem;
    border-bottom: 1px solid var(--border);
    padding-bottom: 0.3rem;
}
.meta-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
    gap: 1rem;
    margin: 1rem 0;
}
.meta-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 1rem;
}
.meta-card .label { color: var(--muted); font-size: 0.8rem; text-transform: uppercase; }
.meta-card .value { color: var(--text); font-size: 1.1rem; font-weight: bold; }
.risk-badge {
    display: inline-block;
    padding: 0.3rem 1rem;
    border-radius: 20px;
    font-weight: bold;
    font-size: 1rem;
}
.risk-critical { background: var(--red); color: #fff; }
.risk-high { background: #b33; color: #fff; }
.risk-moderate { background: var(--orange); color: #000; }
.risk-low { background: var(--blue); color: #fff; }
.risk-hardened { background: var(--green); color: #000; }
.severity-bar {
    display: flex;
    gap: 1rem;
    margin: 1rem 0;
    flex-wrap: wrap;
}
.sev-count {
    padding: 0.3rem 0.8rem;
    border-radius: 4px;
    font-weight: bold;
    font-size: 0.9rem;
}
.sev-critical { background: rgba(248,81,73,0.2); color: var(--red); border: 1px solid var(--red); }
.sev-high { background: rgba(210,153,34,0.2); color: var(--orange); border: 1px solid var(--orange); }
.sev-medium { background: rgba(227,179,65,0.2); color: var(--yellow); border: 1px solid var(--yellow); }
.sev-low { background: rgba(88,166,255,0.2); color: var(--blue); border: 1px solid var(--blue); }
.sev-info { background: rgba(139,148,158,0.2); color: var(--muted); border: 1px solid var(--muted); }
table {
    width: 100%;
    border-collapse: collapse;
    margin: 1rem 0;
    font-size: 0.9rem;
}
th {
    background: var(--surface);
    color: var(--muted);
    text-align: left;
    padding: 0.6rem 0.8rem;
    border-bottom: 2px solid var(--border);
    text-transform: uppercase;
    font-size: 0.75rem;
    letter-spacing: 0.05em;
}
td {
    padding: 0.5rem 0.8rem;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
}
tr:hover { background: rgba(255,255,255,0.03); }
.finding-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 1rem;
    margin: 0.8rem 0;
    border-left: 4px solid var(--muted);
}
.finding-card.critical { border-left-color: var(--red); }
.finding-card.high { border-left-color: var(--orange); }
.finding-card.medium { border-left-color: var(--yellow); }
.finding-card.low { border-left-color: var(--blue); }
.finding-title { font-weight: bold; margin-bottom: 0.3rem; }
.finding-meta { color: var(--muted); font-size: 0.8rem; margin-bottom: 0.5rem; }
.finding-desc { margin-bottom: 0.5rem; }
.finding-evidence {
    background: var(--bg);
    padding: 0.5rem;
    border-radius: 4px;
    font-size: 0.85rem;
    margin: 0.3rem 0;
    overflow-x: auto;
}
.finding-rec { color: var(--green); font-size: 0.9rem; }
.ports-list { display: flex; flex-wrap: wrap; gap: 0.5rem; }
.port-badge {
    background: var(--surface);
    border: 1px solid var(--border);
    padding: 0.2rem 0.6rem;
    border-radius: 4px;
    font-size: 0.85rem;
}
.port-badge.open { border-color: var(--green); color: var(--green); }
footer {
    margin-top: 3rem;
    padding-top: 1rem;
    border-top: 1px solid var(--border);
    color: var(--muted);
    font-size: 0.8rem;
    text-align: center;
}
</style>
</head>
<body>
<div class="container">
"#);

    // Header
    html.push_str("<h1>AyDee 2 — AD Recon Report</h1>\n");

    // Meta cards
    html.push_str("<div class=\"meta-grid\">\n");
    meta_card(&mut html, "Target", &report.target);
    meta_card(&mut html, "Domain", report.domain.as_deref().unwrap_or("unknown"));
    meta_card(&mut html, "Mode", &report.mode);
    meta_card(&mut html, "Auth", &report.auth_method);
    meta_card(&mut html, "Duration", &format!("{}ms", report.duration_ms));
    meta_card(&mut html, "Users", &format!("{} collected", report.collected_users.len()));
    html.push_str("</div>\n");

    // Risk score
    html.push_str("<h2>Risk Assessment</h2>\n");
    let risk_class = match report.risk_score.rating() {
        "CRITICAL RISK" => "risk-critical",
        "HIGH RISK" => "risk-high",
        "MODERATE RISK" => "risk-moderate",
        "LOW RISK" => "risk-low",
        _ => "risk-hardened",
    };
    html.push_str(&format!(
        "<span class=\"risk-badge {}\">{} (score: {})</span>\n",
        risk_class,
        report.risk_score.rating(),
        report.risk_score.total
    ));

    html.push_str("<div class=\"severity-bar\">\n");
    if report.risk_score.critical > 0 {
        html.push_str(&format!(
            "<span class=\"sev-count sev-critical\">{} Critical</span>\n",
            report.risk_score.critical
        ));
    }
    if report.risk_score.high > 0 {
        html.push_str(&format!(
            "<span class=\"sev-count sev-high\">{} High</span>\n",
            report.risk_score.high
        ));
    }
    if report.risk_score.medium > 0 {
        html.push_str(&format!(
            "<span class=\"sev-count sev-medium\">{} Medium</span>\n",
            report.risk_score.medium
        ));
    }
    if report.risk_score.low > 0 {
        html.push_str(&format!(
            "<span class=\"sev-count sev-low\">{} Low</span>\n",
            report.risk_score.low
        ));
    }
    if report.risk_score.info > 0 {
        html.push_str(&format!(
            "<span class=\"sev-count sev-info\">{} Info</span>\n",
            report.risk_score.info
        ));
    }
    html.push_str("</div>\n");

    // Open ports
    html.push_str("<h2>Open Ports</h2>\n");
    html.push_str("<div class=\"ports-list\">\n");
    for port in &report.open_ports {
        html.push_str(&format!(
            "<span class=\"port-badge open\">{} ({})</span>\n",
            port,
            crate::types::service_name(*port)
        ));
    }
    html.push_str("</div>\n");

    // Findings
    html.push_str("<h2>Findings</h2>\n");
    for f in &report.findings {
        let sev_class = match f.severity {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "",
        };

        html.push_str(&format!("<div class=\"finding-card {}\">\n", sev_class));
        html.push_str(&format!(
            "<div class=\"finding-title\">[{}] {}</div>\n",
            html_escape(f.severity.label()),
            html_escape(&f.title)
        ));
        html.push_str(&format!(
            "<div class=\"finding-meta\">{} | {}{}</div>\n",
            html_escape(&f.id),
            html_escape(&f.module),
            f.mitre
                .as_ref()
                .map(|m| format!(" | MITRE: {}", html_escape(m)))
                .unwrap_or_default()
        ));

        if !f.description.is_empty() {
            html.push_str(&format!(
                "<div class=\"finding-desc\">{}</div>\n",
                html_escape(&f.description)
            ));
        }

        if !f.evidence.is_empty() {
            html.push_str("<div class=\"finding-evidence\">\n");
            for e in &f.evidence {
                html.push_str(&format!("{}<br>\n", html_escape(e)));
            }
            html.push_str("</div>\n");
        }

        if !f.recommendation.is_empty() {
            html.push_str(&format!(
                "<div class=\"finding-rec\">Recommendation: {}</div>\n",
                html_escape(&f.recommendation)
            ));
        }

        html.push_str("</div>\n");
    }

    // Module results
    html.push_str("<h2>Module Results</h2>\n");
    html.push_str("<table>\n<tr><th>Module</th><th>Status</th><th>Duration</th><th>Findings</th></tr>\n");
    for m in &report.modules {
        let status = match &m.status {
            crate::types::ModuleStatus::Complete => "Complete".to_string(),
            crate::types::ModuleStatus::Failed(e) => format!("Failed: {}", e),
            crate::types::ModuleStatus::Skipped(r) => format!("Skipped: {}", r),
            crate::types::ModuleStatus::Running => "Running".to_string(),
            crate::types::ModuleStatus::Pending => "Pending".to_string(),
        };
        html.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}ms</td><td>{}</td></tr>\n",
            html_escape(&m.name),
            html_escape(&status),
            m.duration_ms,
            m.findings.len()
        ));
    }
    html.push_str("</table>\n");

    // Footer
    html.push_str(&format!(
        "<footer>Generated by AyDee 2.0.0 at {}</footer>\n",
        report.start_time
    ));

    html.push_str("</div>\n</body>\n</html>");

    html
}

fn meta_card(html: &mut String, label: &str, value: &str) {
    html.push_str(&format!(
        "<div class=\"meta-card\"><div class=\"label\">{}</div><div class=\"value\">{}</div></div>\n",
        html_escape(label),
        html_escape(value)
    ));
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

// ── Manifest ────────────────────────────────────────────────────────────────

async fn generate_manifest(output_dir: &str) -> Result<String> {
    let mut artifacts = Vec::new();

    fn walk_dir_sync(dir: &Path, artifacts: &mut Vec<serde_json::Value>) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk_dir_sync(&path, artifacts);
                } else if let Ok(meta) = entry.metadata() {
                    artifacts.push(serde_json::json!({
                        "path": path.display().to_string(),
                        "size": meta.len(),
                    }));
                }
            }
        }
    }

    walk_dir_sync(Path::new(output_dir), &mut artifacts);

    let manifest = serde_json::json!({
        "tool": "aydee",
        "version": "2.0.0",
        "output_dir": output_dir,
        "artifact_count": artifacts.len(),
        "artifacts": artifacts,
    });

    Ok(serde_json::to_string_pretty(&manifest)?)
}
