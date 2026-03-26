use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::{Duration, Instant};

// ── Severity ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    #[allow(dead_code)]
    pub fn score(self) -> u8 {
        match self {
            Self::Info => 0,
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
            Self::Critical => 4,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ── Finding ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub evidence: Vec<String>,
    pub recommendation: String,
    pub mitre: Option<String>,
    pub module: String,
}

impl Finding {
    pub fn new(module: &str, id: &str, severity: Severity, title: &str) -> Self {
        Self {
            id: id.to_string(),
            severity,
            title: title.to_string(),
            description: String::new(),
            evidence: Vec::new(),
            recommendation: String::new(),
            mitre: None,
            module: module.to_string(),
        }
    }

    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = desc.to_string();
        self
    }

    pub fn with_evidence(mut self, evidence: &str) -> Self {
        self.evidence.push(evidence.to_string());
        self
    }

    pub fn with_recommendation(mut self, rec: &str) -> Self {
        self.recommendation = rec.to_string();
        self
    }

    pub fn with_mitre(mut self, technique: &str) -> Self {
        self.mitre = Some(technique.to_string());
        self
    }
}

// ── Port scanning ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortResult {
    pub port: u16,
    pub open: bool,
    pub service: String,
    pub banner: Option<String>,
}

pub fn service_name(port: u16) -> &'static str {
    match port {
        53 => "DNS",
        80 => "HTTP",
        88 => "Kerberos",
        135 => "RPC/MSRPC",
        139 => "NetBIOS-SSN",
        389 => "LDAP",
        443 => "HTTPS",
        445 => "SMB",
        464 => "Kpasswd",
        593 => "RPC-HTTP",
        636 => "LDAPS",
        3268 => "Global Catalog",
        3269 => "Global Catalog SSL",
        5985 => "WinRM HTTP",
        5986 => "WinRM HTTPS",
        8080 => "HTTP-Proxy",
        8443 => "HTTPS-Alt",
        9389 => "ADWS",
        _ => "unknown",
    }
}

// ── Module execution ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleResult {
    pub name: String,
    pub status: ModuleStatus,
    pub duration_ms: u64,
    pub findings: Vec<Finding>,
    pub collected_users: Vec<String>,
}

impl ModuleResult {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            status: ModuleStatus::Pending,
            duration_ms: 0,
            findings: Vec::new(),
            collected_users: Vec::new(),
        }
    }

    pub fn success(mut self, duration: Duration) -> Self {
        self.status = ModuleStatus::Complete;
        self.duration_ms = duration.as_millis() as u64;
        self
    }

    pub fn skipped(mut self, reason: &str) -> Self {
        self.status = ModuleStatus::Skipped(reason.to_string());
        self
    }

    pub fn failed(mut self, err: &str, duration: Duration) -> Self {
        self.status = ModuleStatus::Failed(err.to_string());
        self.duration_ms = duration.as_millis() as u64;
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ModuleStatus {
    Pending,
    Running,
    Complete,
    Failed(String),
    Skipped(String),
}

// ── Auth ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum AuthMethod {
    Password,
    NtlmHash,
    Kerberos,
}

#[derive(Debug, Clone)]
pub enum AuthStrategy {
    Supplied {
        method: AuthMethod,
    },
    AnonymousOnly,
    Incomplete,
}

// ── Run modes ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum RunMode {
    /// Full pipeline — all non-invasive modules
    Auto,
    /// Conservative — skips noisy stages unless explicitly enabled
    Semi,
    /// Only run modules specified with --only
    Manual,
}

impl fmt::Display for RunMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auto => write!(f, "auto"),
            Self::Semi => write!(f, "semi"),
            Self::Manual => write!(f, "manual"),
        }
    }
}

// ── LDAP info ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct LdapInfo {
    pub domain: Option<String>,
    pub dns_hostname: Option<String>,
    pub functional_level: Option<String>,
    pub naming_context: Option<String>,
    pub usernames: Vec<String>,
}

// ── RPC endpoint ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RpcEndpoint {
    pub protocol: String,
    pub endpoint: String,
    pub annotation: String,
}

// ── Run report ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunReport {
    pub tool: String,
    pub version: String,
    pub target: String,
    pub domain: Option<String>,
    pub mode: String,
    pub auth_method: String,
    pub start_time: String,
    pub duration_ms: u64,
    pub open_ports: Vec<u16>,
    pub collected_users: Vec<String>,
    pub modules: Vec<ModuleResult>,
    pub findings: Vec<Finding>,
    pub risk_score: RiskScore,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    pub total: u32,
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub info: u32,
}

impl RiskScore {
    pub fn from_findings(findings: &[Finding]) -> Self {
        let mut score = Self {
            total: 0,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0,
        };
        for f in findings {
            match f.severity {
                Severity::Critical => {
                    score.critical += 1;
                    score.total += 10;
                }
                Severity::High => {
                    score.high += 1;
                    score.total += 5;
                }
                Severity::Medium => {
                    score.medium += 1;
                    score.total += 3;
                }
                Severity::Low => {
                    score.low += 1;
                    score.total += 1;
                }
                Severity::Info => {
                    score.info += 1;
                }
            }
        }
        score
    }

    pub fn rating(&self) -> &'static str {
        match self.total {
            0 => "HARDENED",
            1..=5 => "LOW RISK",
            6..=15 => "MODERATE RISK",
            16..=30 => "HIGH RISK",
            _ => "CRITICAL RISK",
        }
    }
}

// ── Timer helper ────────────────────────────────────────────────────────────

pub struct StageTimer {
    start: Instant,
}

impl StageTimer {
    pub fn start() -> Self {
        Self {
            start: Instant::now(),
        }
    }

    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    pub fn elapsed_pretty(&self) -> String {
        let d = self.start.elapsed();
        if d.as_secs() > 0 {
            format!("{:.1}s", d.as_secs_f64())
        } else {
            format!("{}ms", d.as_millis())
        }
    }
}
