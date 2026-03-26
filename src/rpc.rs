use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

use crate::types::{Finding, ModuleResult, RpcEndpoint, Severity, StageTimer};
use crate::ui;

/// Known RPC interface UUIDs for risk assessment.
const RISK_KEYWORDS: &[(&str, &str, &str)] = &[
    ("spoolss", "Print Spooler", "PrinterBug/SpoolSample coercion — T1187"),
    ("efsrpc", "EFS RPC", "PetitPotam coercion — T1187"),
    ("lsarpc", "LSA RPC", "LSA enumeration / DFSCoerce — T1087"),
    ("samr", "SAM RPC", "User/group enumeration — T1087"),
    ("netlogon", "Netlogon", "ZeroLogon (CVE-2020-1472) — T1068"),
    ("drsuapi", "DRS/Replication", "DCSync potential — T1003.006"),
    ("dfsnm", "DFS Namespace", "DFSCoerce potential — T1187"),
];

/// Run RPC endpoint enumeration via port 135.
pub async fn run(target: &str) -> Result<ModuleResult> {
    ui::section("RPC ENUMERATION");
    let timer = StageTimer::start();
    let spin = ui::spinner("RPC");
    let mut result = ModuleResult::new("rpc");

    spin.set_message("connecting to endpoint mapper...");
    let endpoints = enumerate_endpoints(target).await;

    match endpoints {
        Ok(eps) => {
            if eps.is_empty() {
                ui::info("No RPC endpoints enumerated");
            } else {
                ui::success(&format!("{} RPC endpoints found", eps.len()));
                println!();

                // Build a nice table
                let mut table = comfy_table::Table::new();
                table.load_preset(comfy_table::presets::UTF8_FULL_CONDENSED);
                table.set_header(vec![
                    comfy_table::Cell::new("Protocol")
                        .add_attribute(comfy_table::Attribute::Bold)
                        .fg(comfy_table::Color::White),
                    comfy_table::Cell::new("Endpoint")
                        .add_attribute(comfy_table::Attribute::Bold)
                        .fg(comfy_table::Color::White),
                    comfy_table::Cell::new("Annotation")
                        .add_attribute(comfy_table::Attribute::Bold)
                        .fg(comfy_table::Color::White),
                ]);

                for ep in &eps {
                    table.add_row(vec![
                        comfy_table::Cell::new(&ep.protocol).fg(comfy_table::Color::Cyan),
                        comfy_table::Cell::new(&ep.endpoint),
                        comfy_table::Cell::new(&ep.annotation).fg(comfy_table::Color::DarkGrey),
                    ]);
                }

                for line in table.to_string().lines() {
                    println!("  {}", line);
                }

                // Check for risky endpoints
                print_risk_hints(&eps, &mut result);

                if eps.len() >= 40 {
                    ui::warning(&format!(
                        "Large RPC surface ({} endpoints) — prioritize review",
                        eps.len()
                    ));
                }
            }
        }
        Err(e) => {
            ui::fail(&format!("RPC enumeration failed: {}", e));
        }
    }

    ui::finish_spinner(&spin, "endpoint enumeration complete");
    ui::stage_done("RPC", "done", &timer.elapsed_pretty());

    result = result.success(timer.elapsed());
    Ok(result)
}

fn print_risk_hints(endpoints: &[RpcEndpoint], result: &mut ModuleResult) {
    let mut hits = Vec::new();

    for ep in endpoints {
        let joined = format!(
            "{} {} {}",
            ep.protocol.to_ascii_lowercase(),
            ep.endpoint.to_ascii_lowercase(),
            ep.annotation.to_ascii_lowercase()
        );

        for (keyword, name, desc) in RISK_KEYWORDS {
            if joined.contains(keyword) {
                hits.push((*name, *desc, ep.endpoint.clone()));
            }
        }
    }

    // Deduplicate by name
    hits.sort_by_key(|(name, _, _)| name.to_string());
    hits.dedup_by_key(|(name, _, _)| name.to_string());

    if !hits.is_empty() {
        println!();
        ui::warning("Sensitive RPC services detected:");
        for (name, desc, endpoint) in &hits {
            ui::kv(&format!("  {} ({})", name, endpoint), desc);
        }

        // Create findings for coercion-relevant services
        for (name, _, _) in &hits {
            if *name == "Print Spooler" || *name == "EFS RPC" || *name == "DFS Namespace" {
                let finding = Finding::new(
                    "rpc",
                    "RPC-001",
                    Severity::Medium,
                    &format!("{} service exposed — coercion attack surface", name),
                )
                .with_description(&format!(
                    "The {} service is accessible, which may enable NTLM authentication coercion attacks",
                    name
                ))
                .with_recommendation("Disable unnecessary services (e.g., Print Spooler on DCs); implement EPA")
                .with_mitre("T1187");
                result.findings.push(finding);
            }
        }
    }
}

// ── DCE/RPC protocol implementation ─────────────────────────────────────────

async fn enumerate_endpoints(target: &str) -> Result<Vec<RpcEndpoint>> {
    let addr = format!("{}:135", target);
    let mut stream = timeout(Duration::from_secs(5), TcpStream::connect(&addr)).await??;

    // Step 1: RPC Bind to endpoint mapper
    let bind = build_rpc_bind();
    stream.write_all(&bind).await?;

    let mut buf = vec![0u8; 4096];
    let n = timeout(Duration::from_secs(5), stream.read(&mut buf)).await??;
    ui::verbose(&format!("RPC bind response: {} bytes, type={}", n, if n >= 3 { buf[2] } else { 0 }));
    if n < 24 {
        anyhow::bail!("RPC bind response too short");
    }
    if buf[2] != 12 {
        anyhow::bail!("Did not receive RPC bind_ack");
    }

    // Step 2: EPM lookup
    let lookup = build_epm_lookup();
    stream.write_all(&lookup).await?;

    let mut endpoints = Vec::new();
    let mut buf = vec![0u8; 65536];
    let n = match timeout(Duration::from_secs(3), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => n,
        _ => return Ok(endpoints),
    };

    if let Some(eps) = parse_epm_response(&buf[..n]) {
        endpoints.extend(eps);
    }

    Ok(endpoints)
}

fn build_rpc_bind() -> Vec<u8> {
    let mut pkt = Vec::new();

    // Common header
    pkt.push(5);    // Version major
    pkt.push(0);    // Version minor
    pkt.push(11);   // Packet type: bind
    pkt.push(0x03); // Flags: first + last

    // Data representation (little-endian, ASCII, IEEE)
    pkt.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]);

    // Fragment length placeholder
    let frag_pos = pkt.len();
    pkt.extend_from_slice(&[0; 2]);
    pkt.extend_from_slice(&0u16.to_le_bytes()); // Auth length
    pkt.extend_from_slice(&1u32.to_le_bytes()); // Call ID

    // Bind fields
    pkt.extend_from_slice(&5840u16.to_le_bytes()); // Max xmit frag
    pkt.extend_from_slice(&5840u16.to_le_bytes()); // Max recv frag
    pkt.extend_from_slice(&0u32.to_le_bytes());    // Assoc group

    // 1 context
    pkt.push(1);
    pkt.extend_from_slice(&[0; 3]);

    // Context 0
    pkt.extend_from_slice(&0u16.to_le_bytes()); // Context ID
    pkt.push(1);                                 // Num transfer syntaxes
    pkt.push(0);

    // EPM interface UUID
    pkt.extend_from_slice(&[
        0x08, 0x83, 0xaf, 0xe1, 0x1f, 0x5d, 0xc9, 0x11, 0x91, 0xa4, 0x08, 0x00, 0x2b, 0x14,
        0xa0, 0xfa,
    ]);
    pkt.extend_from_slice(&3u16.to_le_bytes());
    pkt.extend_from_slice(&0u16.to_le_bytes());

    // NDR transfer syntax
    pkt.extend_from_slice(&[
        0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10,
        0x48, 0x60,
    ]);
    pkt.extend_from_slice(&2u16.to_le_bytes());
    pkt.extend_from_slice(&0u16.to_le_bytes());

    let frag_len = pkt.len() as u16;
    pkt[frag_pos] = (frag_len & 0xff) as u8;
    pkt[frag_pos + 1] = ((frag_len >> 8) & 0xff) as u8;

    pkt
}

fn build_epm_lookup() -> Vec<u8> {
    let mut pkt = Vec::new();

    pkt.push(5);
    pkt.push(0);
    pkt.push(0); // request
    pkt.push(0x03);
    pkt.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]);

    let frag_pos = pkt.len();
    pkt.extend_from_slice(&[0; 2]);
    pkt.extend_from_slice(&0u16.to_le_bytes());
    pkt.extend_from_slice(&2u32.to_le_bytes()); // Call ID

    // Request fields
    pkt.extend_from_slice(&0u32.to_le_bytes()); // Alloc hint
    pkt.extend_from_slice(&0u16.to_le_bytes()); // Context ID
    pkt.extend_from_slice(&2u16.to_le_bytes()); // Opnum: ept_lookup

    // ept_lookup params
    pkt.extend_from_slice(&0u32.to_le_bytes()); // inquiry_type
    pkt.extend_from_slice(&0u32.to_le_bytes()); // object
    pkt.extend_from_slice(&0u32.to_le_bytes()); // interface_id
    pkt.extend_from_slice(&0u32.to_le_bytes()); // vers_option
    pkt.extend_from_slice(&[0; 20]);            // entry_handle
    pkt.extend_from_slice(&100u32.to_le_bytes()); // max_ents

    let frag_len = pkt.len() as u16;
    pkt[frag_pos] = (frag_len & 0xff) as u8;
    pkt[frag_pos + 1] = ((frag_len >> 8) & 0xff) as u8;

    pkt
}

fn parse_epm_response(data: &[u8]) -> Option<Vec<RpcEndpoint>> {
    if data.len() < 28 {
        return None;
    }

    let body = &data[24..];
    if body.len() < 24 {
        return None;
    }

    let num_ents = u32::from_le_bytes([body[20], body[21], body[22], body[23]]) as usize;
    if num_ents == 0 {
        return Some(Vec::new());
    }

    let mut endpoints = Vec::new();
    let mut pos = 28;

    for _ in 0..num_ents.min(100) {
        if pos + 16 >= body.len() {
            break;
        }
        pos += 16; // Skip UUID

        if pos + 12 > body.len() {
            break;
        }
        let _max = u32::from_le_bytes([body[pos], body[pos + 1], body[pos + 2], body[pos + 3]]);
        pos += 4;
        let _off = u32::from_le_bytes([body[pos], body[pos + 1], body[pos + 2], body[pos + 3]]);
        pos += 4;
        let actual = u32::from_le_bytes([body[pos], body[pos + 1], body[pos + 2], body[pos + 3]]) as usize;
        pos += 4;

        if pos + actual > body.len() {
            break;
        }
        let annotation = String::from_utf8_lossy(&body[pos..pos + actual])
            .trim_end_matches('\0')
            .to_string();
        pos += actual;
        pos = (pos + 3) & !3;

        if pos + 4 > body.len() {
            break;
        }
        let tower_len = u32::from_le_bytes([body[pos], body[pos + 1], body[pos + 2], body[pos + 3]]) as usize;
        pos += 4;

        if pos + 4 > body.len() {
            break;
        }
        let _actual_tower = u32::from_le_bytes([body[pos], body[pos + 1], body[pos + 2], body[pos + 3]]);
        pos += 4;

        if pos + tower_len > body.len() {
            pos += tower_len.min(body.len() - pos);
            continue;
        }

        let tower_data = &body[pos..pos + tower_len];
        pos += tower_len;

        if let Some((proto, endpoint)) = parse_tower(tower_data) {
            endpoints.push(RpcEndpoint {
                protocol: proto,
                endpoint,
                annotation: if annotation.is_empty() {
                    "(none)".to_string()
                } else {
                    annotation
                },
            });
        }
    }

    Some(endpoints)
}

fn parse_tower(data: &[u8]) -> Option<(String, String)> {
    if data.len() < 2 {
        return None;
    }

    let num_floors = u16::from_le_bytes([data[0], data[1]]) as usize;
    let mut pos = 2;
    let mut protocol = String::new();
    let mut endpoint = String::new();

    for i in 0..num_floors {
        if pos + 2 > data.len() {
            break;
        }
        let lhs_len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if pos + lhs_len > data.len() {
            break;
        }
        let lhs = &data[pos..pos + lhs_len];
        pos += lhs_len;

        if pos + 2 > data.len() {
            break;
        }
        let rhs_len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if pos + rhs_len > data.len() {
            break;
        }
        let rhs = &data[pos..pos + rhs_len];
        pos += rhs_len;

        match i {
            2 => {
                if !lhs.is_empty() {
                    match lhs[0] {
                        0x07 => protocol = "tcp".to_string(),
                        0x08 => protocol = "udp".to_string(),
                        0x09 => protocol = "ip".to_string(),
                        0x0f => protocol = "ncacn_np".to_string(),
                        0x10 => protocol = "ncacn_nb".to_string(),
                        0x1f => protocol = "ncacn_http".to_string(),
                        _ => protocol = format!("0x{:02x}", lhs[0]),
                    }
                }
                if protocol == "ncacn_np" {
                    endpoint = String::from_utf8_lossy(rhs).trim_end_matches('\0').to_string();
                } else if rhs.len() >= 2 {
                    endpoint = u16::from_be_bytes([rhs[0], rhs[1]]).to_string();
                }
            }
            3 => {
                if protocol.is_empty() && !lhs.is_empty() {
                    if lhs[0] == 0x07 {
                        protocol = "tcp".to_string();
                        if rhs.len() >= 2 {
                            endpoint = u16::from_be_bytes([rhs[0], rhs[1]]).to_string();
                        }
                    }
                }
            }
            _ => {}
        }
    }

    if !protocol.is_empty() {
        Some((protocol, endpoint))
    } else {
        None
    }
}
