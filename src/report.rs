use anyhow::Result;
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::auth_recon::AuthFinding;

#[derive(Debug, Clone, Serialize)]
pub struct ModuleReport {
    pub name: String,
    pub status: String,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArtifactRecord {
    pub path: String,
    pub size_bytes: u64,
    pub modified_unix: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RunReport {
    pub target: String,
    pub domain: Option<String>,
    pub mode: String,
    pub results_dir: String,
    pub selected_modules: Vec<String>,
    pub selected_tags: Vec<String>,
    pub open_ports: Vec<u16>,
    pub usernames_collected: Vec<String>,
    pub authenticated_findings: Vec<AuthFinding>,
    pub modules: Vec<ModuleReport>,
    pub started_unix: u64,
    pub duration_secs: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct WorkspaceManifest {
    pub target: String,
    pub domain: Option<String>,
    pub results_dir: String,
    pub generated_unix: u64,
    pub reports: Vec<String>,
    pub modules: Vec<ModuleReport>,
    pub artifacts: Vec<ArtifactRecord>,
}

pub fn write_json(path: &str, report: &RunReport) -> Result<()> {
    let data = serde_json::to_string_pretty(report)?;
    fs::write(path, data)?;
    Ok(())
}

pub fn write_text(path: &str, report: &RunReport) -> Result<()> {
    fs::write(path, render_text_summary(report))?;
    Ok(())
}

pub fn write_workspace_manifest(path: &str, manifest: &WorkspaceManifest) -> Result<()> {
    let data = serde_json::to_string_pretty(manifest)?;
    fs::write(path, data)?;
    Ok(())
}

pub fn collect_artifacts(base_dir: &Path) -> Result<Vec<ArtifactRecord>> {
    let mut artifacts = Vec::new();
    let mut pending = vec![PathBuf::from(base_dir)];

    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            let metadata = entry.metadata()?;
            if metadata.is_dir() {
                pending.push(path);
                continue;
            }
            if !metadata.is_file() {
                continue;
            }

            let rel = path
                .strip_prefix(base_dir)
                .unwrap_or(&path)
                .display()
                .to_string();
            let modified_unix = metadata
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs());

            artifacts.push(ArtifactRecord {
                path: rel,
                size_bytes: metadata.len(),
                modified_unix,
            });
        }
    }

    artifacts.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(artifacts)
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn render_text_summary(report: &RunReport) -> String {
    let mut out = String::new();

    out.push_str("AyDee Run Summary\n");
    out.push_str("=================\n\n");
    out.push_str(&format!("Target: {}\n", report.target));
    out.push_str(&format!(
        "Domain: {}\n",
        report.domain.as_deref().unwrap_or("<unresolved>")
    ));
    out.push_str(&format!("Mode: {}\n", report.mode));
    out.push_str(&format!("Results Dir: {}\n", report.results_dir));
    out.push_str(&format!("Started: {}\n", report.started_unix));
    out.push_str(&format!("Duration: {:.2}s\n\n", report.duration_secs));

    out.push_str("Open Ports\n");
    out.push_str("----------\n");
    if report.open_ports.is_empty() {
        out.push_str("None\n\n");
    } else {
        out.push_str(
            &report
                .open_ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", "),
        );
        out.push_str("\n\n");
    }

    out.push_str("Modules\n");
    out.push_str("-------\n");
    if report.modules.is_empty() {
        out.push_str("No module records\n\n");
    } else {
        for module in &report.modules {
            out.push_str(&format!(
                "- {} [{}]",
                module.name,
                module.status.to_ascii_uppercase()
            ));
            if let Some(detail) = &module.detail {
                out.push_str(&format!(": {}", detail));
            }
            out.push('\n');
        }
        out.push('\n');
    }

    out.push_str("Collected Usernames\n");
    out.push_str("-------------------\n");
    if report.usernames_collected.is_empty() {
        out.push_str("None\n\n");
    } else {
        out.push_str(&format!("{}\n\n", report.usernames_collected.join(", ")));
    }

    out.push_str("Findings\n");
    out.push_str("--------\n");
    if report.authenticated_findings.is_empty() {
        out.push_str("None\n");
    } else {
        for finding in &report.authenticated_findings {
            out.push_str(&format!(
                "- {} [{}] {}\n",
                finding.id,
                finding.severity.to_ascii_uppercase(),
                finding.title
            ));
            out.push_str(&format!("  Evidence: {}\n", finding.evidence));
            out.push_str(&format!("  Recommendation: {}\n", finding.recommendation));
        }
    }

    out
}
