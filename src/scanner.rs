use anyhow::Result;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

use crate::types::{service_name, PortResult, StageTimer};
use crate::ui;

/// Default AD-related ports
const DEFAULT_PORTS: &[u16] = &[
    53, 80, 88, 135, 139, 389, 443, 445, 464, 593, 636, 3268, 3269, 5985, 5986, 8080, 8443, 9389,
];

const MAX_CONCURRENT: usize = 256;

/// Run a port scan against the target.
pub async fn run(
    target: &str,
    port_spec: Option<&str>,
    timeout_secs: u64,
) -> Result<Vec<PortResult>> {
    ui::section("PORT SCAN");

    let ports = match port_spec {
        Some(spec) => parse_ports(spec)?,
        None => DEFAULT_PORTS.to_vec(),
    };

    let timer = StageTimer::start();
    let pb = ui::progress_bar(ports.len() as u64, "SCAN");

    let sem = std::sync::Arc::new(Semaphore::new(MAX_CONCURRENT));
    let mut handles = Vec::new();

    for port in &ports {
        let target = target.to_string();
        let port = *port;
        let sem = sem.clone();
        let pb = pb.clone();

        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            let open = scan_port(&target, port, timeout_secs).await;
            pb.inc(1);
            if open {
                pb.set_message(format!("{}/{} open", port, service_name(port)));
            }
            PortResult {
                port,
                open,
                service: service_name(port).to_string(),
                banner: None,
            }
        }));
    }

    let mut results = Vec::new();
    for handle in handles {
        if let Ok(r) = handle.await {
            results.push(r);
        }
    }

    results.sort_by_key(|r| r.port);
    let open_count = results.iter().filter(|r| r.open).count();

    pb.finish_and_clear();

    // Display results
    ui::port_table(&results);
    println!();
    ui::stage_done(
        "PORT SCAN",
        &format!("{}/{} ports open", open_count, ports.len()),
        &timer.elapsed_pretty(),
    );

    // Show entry points
    let open_ports: Vec<u16> = results.iter().filter(|r| r.open).map(|r| r.port).collect();
    ui::entry_points(&open_ports);

    Ok(results)
}

async fn scan_port(target: &str, port: u16, timeout_secs: u64) -> bool {
    let addr = format!("{}:{}", target, port);
    timeout(Duration::from_secs(timeout_secs), TcpStream::connect(&addr))
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false)
}

fn parse_ports(spec: &str) -> Result<Vec<u16>> {
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
        if let Some((start, end)) = part.split_once('-') {
            let s: u16 = start
                .trim()
                .parse()
                .map_err(|_| anyhow::anyhow!("Invalid start port in range: {}", part))?;
            let e: u16 = end
                .trim()
                .parse()
                .map_err(|_| anyhow::anyhow!("Invalid end port in range: {}", part))?;
            if s > e {
                anyhow::bail!("Invalid port range (start > end): {}", part);
            }
            ports.extend(s..=e);
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

    ports.sort();
    ports.dedup();
    Ok(ports)
}

#[cfg(test)]
mod tests {
    use super::parse_ports;

    #[test]
    fn parses_all_ports_marker() {
        let ports = parse_ports("-").expect("all ports spec should parse");
        assert_eq!(ports.first(), Some(&1));
        assert_eq!(ports.last(), Some(&65535));
        assert_eq!(ports.len(), 65535);
    }

    #[test]
    fn rejects_invalid_range() {
        let err = parse_ports("100-80").expect_err("reversed range should fail");
        assert!(err.to_string().contains("start > end"));
    }
}
