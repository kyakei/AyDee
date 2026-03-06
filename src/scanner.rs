use anyhow::Result;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

use crate::output;

/// Default AD-related ports to scan
const DEFAULT_PORTS: &[u16] = &[
    80,    // HTTP (AD CS web enrollment / NTLM over HTTP)
    53,    // DNS
    88,    // Kerberos
    443,   // HTTPS (AD CS web enrollment)
    135,   // MSRPC
    139,   // NetBIOS
    389,   // LDAP
    445,   // SMB
    464,   // Kerberos kpasswd
    593,   // HTTP RPC
    636,   // LDAPS
    3268,  // Global Catalog
    3269,  // Global Catalog SSL
    5985,  // WinRM HTTP
    5986,  // WinRM HTTPS
    8080,  // Alternate HTTP
    8443,  // Alternate HTTPS
    9389,  // AD Web Services
];

/// Well-known AD service names by port
pub fn service_name(port: u16) -> &'static str {
    match port {
        80 => "HTTP",
        53 => "DNS",
        88 => "Kerberos",
        443 => "HTTPS",
        135 => "MSRPC",
        139 => "NetBIOS-SSN",
        389 => "LDAP",
        445 => "SMB",
        464 => "Kpasswd",
        593 => "HTTP-RPC",
        636 => "LDAPS",
        3268 => "Global Catalog",
        3269 => "Global Catalog SSL",
        5985 => "WinRM HTTP",
        5986 => "WinRM HTTPS",
        8080 => "HTTP-alt",
        8443 => "HTTPS-alt",
        9389 => "AD Web Services",
        _ => "unknown",
    }
}

/// Result of scanning a single port
#[derive(Debug, Clone)]
pub struct PortResult {
    pub port: u16,
    pub open: bool,
    pub service: String,
}

/// Parse a port specification string
/// Supports: "80", "80,443", "80-100", "80,443,8000-8100", "-" (all ports)
pub fn parse_ports(spec: &str) -> Result<Vec<u16>> {
    let spec = spec.trim();
    if spec == "-" {
        return Ok((1..=65535).collect());
    }

    let mut ports = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if part.contains('-') {
            let range: Vec<&str> = part.split('-').collect();
            if range.len() != 2 {
                anyhow::bail!("Invalid port range: {}", part);
            }
            let start: u16 = range[0]
                .trim()
                .parse()
                .map_err(|_| anyhow::anyhow!("Invalid start port in range: {}", part))?;
            let end: u16 = range[1]
                .trim()
                .parse()
                .map_err(|_| anyhow::anyhow!("Invalid end port in range: {}", part))?;
            if start > end {
                anyhow::bail!("Invalid port range (start > end): {}", part);
            }
            ports.extend(start..=end);
        } else {
            let port: u16 = part
                .parse()
                .map_err(|_| anyhow::anyhow!("Invalid port value: {}", part))?;
            ports.push(port);
        }
    }

    if ports.is_empty() {
        anyhow::bail!("No valid ports provided in --ports specification");
    }

    Ok(ports)
}

/// Scan a single port via TCP connect
async fn scan_port(ip: &str, port: u16, timeout_secs: u64) -> PortResult {
    let addr: SocketAddr = format!("{}:{}", ip, port).parse().unwrap();
    let is_open = timeout(
        Duration::from_secs(timeout_secs),
        TcpStream::connect(&addr),
    )
    .await
    .map(|r| r.is_ok())
    .unwrap_or(false);

    PortResult {
        port,
        open: is_open,
        service: service_name(port).to_string(),
    }
}

/// Run a port scan against the target
pub async fn run(ip: &str, custom_ports: Option<&str>, timeout_secs: u64) -> Result<Vec<PortResult>> {
    let ports = match custom_ports {
        Some(spec) => parse_ports(spec)?,
        None => DEFAULT_PORTS.to_vec(),
    };

    output::section("PORT SCAN");
    output::info(&format!(
        "Scanning {} ports on {}",
        ports.len(),
        ip
    ));

    let semaphore = std::sync::Arc::new(Semaphore::new(200)); // max 200 concurrent connections
    let mut handles = Vec::new();

    for port in &ports {
        let sem = semaphore.clone();
        let ip = ip.to_string();
        let port = *port;
        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            scan_port(&ip, port, timeout_secs).await
        });
        handles.push(handle);
    }

    let mut results = Vec::new();
    for handle in handles {
        results.push(handle.await?);
    }

    // Sort by port number
    results.sort_by_key(|r| r.port);

    // Print results
    let mut open_count = 0;
    let mut closed_count = 0;

    println!();
    for result in &results {
        if result.open {
            output::port_open(result.port, &result.service);
            open_count += 1;
        } else {
            // Only show closed ports when scanning small port sets
            if ports.len() <= 20 {
                output::port_closed(result.port, &result.service);
            }
            closed_count += 1;
        }
    }

    output::summary(open_count, closed_count);

    Ok(results)
}
