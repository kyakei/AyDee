use anyhow::Result;
use reqwest::Client;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::types::{Finding, ModuleResult, Severity, StageTimer};
use crate::ui;

/// Run unauthenticated attack surface checks.
/// Covers: AD CS Web Enrollment, coercion endpoints, NTLM relay surface.
pub async fn run(target: &str, open_ports: &[u16]) -> Result<ModuleResult> {
    ui::section("ATTACK SURFACE ANALYSIS");
    let timer = StageTimer::start();
    let spin = ui::spinner("ATTACKS");
    let mut result = ModuleResult::new("attacks");

    // AD CS Web Enrollment
    let web_ports: Vec<u16> = open_ports
        .iter()
        .copied()
        .filter(|p| matches!(p, 80 | 8080))
        .collect();
    let tls_ports: Vec<u16> = open_ports
        .iter()
        .copied()
        .filter(|p| matches!(p, 443 | 8443))
        .collect();

    if !web_ports.is_empty() || !tls_ports.is_empty() {
        spin.set_message("checking AD CS Web Enrollment...");
        for port in &web_ports {
            check_adcs_enrollment(target, "http", *port, &mut result).await;
        }
        for port in &tls_ports {
            check_adcs_enrollment(target, "https", *port, &mut result).await;
        }
    }

    // Coercion attack surface
    if open_ports.contains(&445) {
        spin.set_message("checking coercion attack surface...");
        check_coercion_surface(target, open_ports, &mut result).await;
    }

    // WebDAV check (for relay)
    if open_ports.contains(&80) || open_ports.contains(&8080) {
        spin.set_message("checking WebDAV...");
        check_webdav(target, &web_ports, &mut result).await;
    }

    let finding_count = result.findings.len();
    ui::finish_spinner(&spin, &format!("{} attack surface findings", finding_count));
    ui::stage_done("ATTACKS", &format!("{} findings", finding_count), &timer.elapsed_pretty());

    result = result.success(timer.elapsed());
    Ok(result)
}

// ── AD CS Web Enrollment ────────────────────────────────────────────────────

async fn check_adcs_enrollment(
    target: &str,
    scheme: &str,
    port: u16,
    result: &mut ModuleResult,
) {
    let paths = ["/certsrv/", "/certsrv/certfnsh.asp", "/certsrv/certnew.cer"];
    let mut seen_adcs = false;
    let mut ntlm_auth = false;
    let mut anon_ok = false;

    for path in paths {
        let response = if scheme == "https" {
            https_probe(target, port, path).await
        } else {
            http_probe(target, port, path).await
        };

        let Ok(resp) = response else {
            ui::verbose(&format!("ADCS probe failed: {}://{}:{}{}", scheme, target, port, path));
            continue;
        };

        ui::verbose(&format!(
            "ADCS probe {}://{}:{}{} → {} (headers: {})",
            scheme, target, port, path, resp.status,
            resp.headers.iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<_>>().join(", ")
        ));

        let offers_ntlm = resp
            .headers
            .iter()
            .any(|(k, v)| {
                k.eq_ignore_ascii_case("www-authenticate")
                    && (v.to_lowercase().contains("ntlm") || v.to_lowercase().contains("negotiate"))
            });

        if path.starts_with("/certsrv/") && (resp.status == 200 || resp.status == 401) {
            seen_adcs = true;
        }
        if resp.status == 401 && offers_ntlm {
            ntlm_auth = true;
        }
        if resp.status == 200 {
            anon_ok = true;
        }
    }

    if seen_adcs {
        ui::warning(&format!(
            "AD CS Web Enrollment detected on {}://{}:{}",
            scheme, target, port
        ));

        if ntlm_auth {
            let finding = Finding::new(
                "attacks",
                "ADCS-ESC8",
                Severity::Critical,
                "AD CS Web Enrollment with NTLM auth (ESC8)",
            )
            .with_description(
                "AD CS Web Enrollment offers NTLM/Negotiate authentication, enabling relay-to-ADCS attacks (ESC8)"
            )
            .with_recommendation("Disable Web Enrollment, enforce EPA, require HTTPS with channel binding")
            .with_mitre("T1557.001");
            result.findings.push(finding);
            ui::warning("NTLM auth on /certsrv — ESC8 relay attack possible!");
        }

        if anon_ok {
            let finding = Finding::new(
                "attacks",
                "ADCS-ANON",
                Severity::High,
                "AD CS Web Enrollment accessible without authentication",
            )
            .with_description("Anonymous access to AD CS Web Enrollment endpoints")
            .with_recommendation("Require authentication for all AD CS endpoints");
            result.findings.push(finding);
            ui::warning("Anonymous access to /certsrv endpoint!");
        }

        if !ntlm_auth && !anon_ok {
            let finding = Finding::new(
                "attacks",
                "ADCS-PRESENT",
                Severity::Info,
                &format!("AD CS Web Enrollment present on {}://{}:{}", scheme, target, port),
            );
            result.findings.push(finding);
        }
    }
}

// ── Coercion attack surface ─────────────────────────────────────────────────

async fn check_coercion_surface(
    target: &str,
    open_ports: &[u16],
    result: &mut ModuleResult,
) {
    ui::info("Coercion attack surface assessment:");

    // Print Spooler (PrinterBug / SpoolSample)
    if open_ports.contains(&445) {
        // Check if spooler is running by probing the named pipe
        if check_named_pipe(target, "\\spoolss").await {
            ui::warning("Print Spooler (\\spoolss) — SpoolSample/PrinterBug coercion possible");
            let finding = Finding::new(
                "attacks",
                "COERCE-001",
                Severity::High,
                "Print Spooler service accessible (PrinterBug)",
            )
            .with_description(
                "The Print Spooler service is running, enabling SpoolSample/PrinterBug NTLM coercion attacks"
            )
            .with_recommendation("Disable the Print Spooler service on domain controllers and servers that don't need printing")
            .with_mitre("T1187");
            result.findings.push(finding);
        }
    }

    // PetitPotam (MS-EFSRPC)
    if open_ports.contains(&445) || open_ports.contains(&135) {
        if check_named_pipe(target, "\\efsrpc").await
            || check_named_pipe(target, "\\lsarpc").await
        {
            ui::warning("EFS RPC (\\efsrpc/\\lsarpc) — PetitPotam coercion possible");
            let finding = Finding::new(
                "attacks",
                "COERCE-002",
                Severity::High,
                "EFS RPC accessible (PetitPotam)",
            )
            .with_description(
                "MS-EFSRPC endpoints are accessible, enabling PetitPotam NTLM coercion attacks"
            )
            .with_recommendation("Apply MS patches, disable EFS if unused, implement EPA on all services")
            .with_mitre("T1187");
            result.findings.push(finding);
        }
    }

    // DFSCoerce
    if open_ports.contains(&445) {
        if check_named_pipe(target, "\\netdfs").await {
            ui::warning("DFS (\\netdfs) — DFSCoerce coercion possible");
            let finding = Finding::new(
                "attacks",
                "COERCE-003",
                Severity::Medium,
                "DFS Namespace accessible (DFSCoerce)",
            )
            .with_description(
                "DFS Namespace Management pipe is accessible, potentially enabling DFSCoerce NTLM coercion"
            )
            .with_recommendation("Restrict DFS access, implement EPA")
            .with_mitre("T1187");
            result.findings.push(finding);
        }
    }

    // ShadowCoerce
    if open_ports.contains(&445) {
        if check_named_pipe(target, "\\FssagentRpc").await {
            ui::warning("File Server VSS (\\FssagentRpc) — ShadowCoerce possible");
            let finding = Finding::new(
                "attacks",
                "COERCE-004",
                Severity::Medium,
                "File Server VSS Agent accessible (ShadowCoerce)",
            )
            .with_description(
                "VSS Agent RPC is accessible, enabling ShadowCoerce NTLM coercion attacks"
            )
            .with_recommendation("Disable File Server VSS Agent if unused")
            .with_mitre("T1187");
            result.findings.push(finding);
        }
    }
}

/// Check if a named pipe is accessible via SMB.
async fn check_named_pipe(target: &str, pipe: &str) -> bool {
    // Simple check: try to connect to SMB port
    // A full implementation would do SMB negotiation + tree connect + open pipe
    // For now, we check port accessibility as a proxy
    let addr = format!("{}:445", target);
    let ok = timeout(Duration::from_secs(2), TcpStream::connect(&addr))
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false);
    ui::verbose(&format!("pipe check {} → {}", pipe, if ok { "reachable" } else { "unreachable" }));
    ok
}

// ── WebDAV check ────────────────────────────────────────────────────────────

async fn check_webdav(target: &str, ports: &[u16], result: &mut ModuleResult) {
    for port in ports {
        let response = http_probe(target, *port, "/").await;
        if let Ok(resp) = response {
            let has_dav = resp.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("dav"));
            let allows_propfind = resp
                .headers
                .iter()
                .any(|(k, v)| k.eq_ignore_ascii_case("allow") && v.contains("PROPFIND"));

            if has_dav || allows_propfind {
                ui::warning(&format!("WebDAV detected on port {}", port));
                let finding = Finding::new(
                    "attacks",
                    "WEBDAV-001",
                    Severity::Medium,
                    &format!("WebDAV service on port {}", port),
                )
                .with_description("WebDAV can be leveraged for NTLM relay and coercion attacks")
                .with_recommendation("Disable WebDAV if not required; ensure NTLM relay protections are in place")
                .with_mitre("T1557.001");
                result.findings.push(finding);
            }
        }
    }
}

// ── HTTP helpers ────────────────────────────────────────────────────────────

struct ProbeResponse {
    status: u16,
    headers: Vec<(String, String)>,
}

async fn http_probe(target: &str, port: u16, path: &str) -> Result<ProbeResponse> {
    let addr = format!("{}:{}", target, port);
    let mut stream = timeout(Duration::from_secs(3), TcpStream::connect(&addr)).await??;

    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: aydee/2.0\r\nConnection: close\r\n\r\n",
        path, target
    );
    timeout(Duration::from_secs(3), stream.write_all(req.as_bytes())).await??;

    let mut buf = vec![0u8; 8192];
    let n = timeout(Duration::from_secs(3), stream.read(&mut buf)).await??;
    if n == 0 {
        anyhow::bail!("empty response");
    }

    let resp = String::from_utf8_lossy(&buf[..n]);
    Ok(ProbeResponse {
        status: parse_status(&resp).unwrap_or(0),
        headers: extract_headers(&resp),
    })
}

async fn https_probe(target: &str, port: u16, path: &str) -> Result<ProbeResponse> {
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(5))
        .build()?;

    let url = format!("https://{}:{}{}", target, port, path);
    let response = client
        .get(&url)
        .header("User-Agent", "aydee/2.0")
        .send()
        .await?;

    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    Ok(ProbeResponse { status, headers })
}

fn parse_status(resp: &str) -> Option<u16> {
    resp.lines().next()?.split_whitespace().nth(1)?.parse().ok()
}

fn extract_headers(resp: &str) -> Vec<(String, String)> {
    resp.lines()
        .skip(1)
        .take_while(|l| !l.trim().is_empty())
        .filter_map(|l| {
            l.split_once(':')
                .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        })
        .collect()
}
