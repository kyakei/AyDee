use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

use crate::output;

/// Run RPC null session enumeration via MSRPC (port 135)
pub async fn run(target: &str) -> Result<()> {
    output::section("RPC ENUMERATION");
    output::info(&format!("Connecting to {}:135", target));

    // Try to bind to the SAMR endpoint mapper
    let endpoints = enumerate_endpoints(target).await;

    match endpoints {
        Ok(eps) => {
            if eps.is_empty() {
                output::warning("No RPC endpoints enumerated");
            } else {
                output::success(&format!("Found {} RPC endpoints", eps.len()));
                println!();
                for ep in &eps {
                    output::kv(
                        &ep.protocol,
                        &format!("{} — {}", ep.endpoint, ep.annotation),
                    );
                }
                if eps.len() >= 40 {
                    output::warning(&format!(
                        "Large RPC endpoint surface detected ({} endpoints) — prioritize review",
                        eps.len()
                    ));
                }
                print_risk_endpoint_hints(&eps);
            }
        }
        Err(e) => {
            output::fail(&format!("RPC endpoint enumeration failed: {}", e));
        }
    }

    Ok(())
}

#[derive(Debug)]
struct RpcEndpoint {
    protocol: String,
    endpoint: String,
    annotation: String,
}

fn print_risk_endpoint_hints(endpoints: &[RpcEndpoint]) {
    let mut hits = Vec::new();
    let keywords = ["spoolss", "efsrpc", "lsarpc", "samr", "netlogon"];

    for ep in endpoints {
        let joined = format!(
            "{} {} {}",
            ep.protocol.to_ascii_lowercase(),
            ep.endpoint.to_ascii_lowercase(),
            ep.annotation.to_ascii_lowercase()
        );
        if keywords.iter().any(|k| joined.contains(k)) {
            hits.push(format!("{} ({})", ep.endpoint, ep.protocol));
        }
    }

    if !hits.is_empty() {
        println!();
        output::warning(
            "Potentially sensitive RPC endpoint names detected (presence is indicative, not proof of exploitability)",
        );
        output::kv("Endpoints", &hits.join(", "));
    }
}

/// Enumerate RPC endpoints via the endpoint mapper (port 135)
/// Uses DCE/RPC protocol to query the endpoint mapper
async fn enumerate_endpoints(target: &str) -> Result<Vec<RpcEndpoint>> {
    let addr = format!("{}:135", target);
    let mut stream = timeout(Duration::from_secs(5), TcpStream::connect(&addr)).await??;

    // Step 1: Send RPC Bind request to the endpoint mapper (epmapper)
    let bind = build_rpc_bind();
    stream.write_all(&bind).await?;

    let mut buf = vec![0u8; 4096];
    let n = timeout(Duration::from_secs(5), stream.read(&mut buf)).await??;
    if n < 24 {
        anyhow::bail!("RPC bind response too short");
    }

    // Check for bind_ack (type 12)
    if buf[2] != 12 {
        anyhow::bail!("Did not receive RPC bind_ack");
    }

    // Step 2: Send EPM lookup request
    let lookup = build_epm_lookup();
    stream.write_all(&lookup).await?;

    let mut endpoints = Vec::new();

    // Read first response batch
    let mut buf = vec![0u8; 65536];
    let n = match timeout(Duration::from_secs(3), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => n,
        _ => return Ok(endpoints),
    };

    let data = &buf[..n];

    // Parse the EPM lookup response
    // The response contains tower entries that describe endpoints
    if let Some(eps) = parse_epm_response(data) {
        endpoints.extend(eps);
    }

    Ok(endpoints)
}

/// Build a DCE/RPC Bind request for the Endpoint Mapper interface
fn build_rpc_bind() -> Vec<u8> {
    let mut pkt = Vec::new();

    // Common Header
    pkt.push(5); // Version major
    pkt.push(0); // Version minor
    pkt.push(11); // Packet type: bind
    pkt.push(0x03); // Flags: first + last

    // Data representation (little-endian, ASCII, IEEE float)
    pkt.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]);

    // Fragment length (will fill in later)
    let frag_len_pos = pkt.len();
    pkt.extend_from_slice(&[0; 2]);

    // Auth length
    pkt.extend_from_slice(&0u16.to_le_bytes());

    // Call ID
    pkt.extend_from_slice(&1u32.to_le_bytes());

    // Bind-specific fields
    pkt.extend_from_slice(&5840u16.to_le_bytes()); // Max xmit frag
    pkt.extend_from_slice(&5840u16.to_le_bytes()); // Max recv frag
    pkt.extend_from_slice(&0u32.to_le_bytes()); // Assoc group

    // Context list: 1 context
    pkt.push(1); // Num context items
    pkt.extend_from_slice(&[0; 3]); // Padding

    // Context item 0
    pkt.extend_from_slice(&0u16.to_le_bytes()); // Context ID
    pkt.push(1); // Num transfer syntaxes
    pkt.push(0); // Padding

    // Abstract syntax: EPM interface UUID (e1af8308-5d1f-11c9-91a4-08002b14a0fa v3.0)
    pkt.extend_from_slice(&[
        0x08, 0x83, 0xaf, 0xe1, 0x1f, 0x5d, 0xc9, 0x11, 0x91, 0xa4, 0x08, 0x00, 0x2b, 0x14, 0xa0,
        0xfa,
    ]);
    pkt.extend_from_slice(&3u16.to_le_bytes()); // Version major
    pkt.extend_from_slice(&0u16.to_le_bytes()); // Version minor

    // Transfer syntax: NDR (8a885d04-1ceb-11c9-9fe8-08002b104860 v2.0)
    pkt.extend_from_slice(&[
        0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48,
        0x60,
    ]);
    pkt.extend_from_slice(&2u16.to_le_bytes()); // Version major
    pkt.extend_from_slice(&0u16.to_le_bytes()); // Version minor

    // Fill in fragment length
    let frag_len = pkt.len() as u16;
    pkt[frag_len_pos] = (frag_len & 0xff) as u8;
    pkt[frag_len_pos + 1] = ((frag_len >> 8) & 0xff) as u8;

    pkt
}

/// Build an EPM Lookup request (opnum 2)
fn build_epm_lookup() -> Vec<u8> {
    let mut pkt = Vec::new();

    // Common Header
    pkt.push(5); // Version major
    pkt.push(0); // Version minor
    pkt.push(0); // Packet type: request
    pkt.push(0x03); // Flags: first + last

    // Data representation
    pkt.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]);

    // Fragment length (placeholder)
    let frag_len_pos = pkt.len();
    pkt.extend_from_slice(&[0; 2]);

    // Auth length
    pkt.extend_from_slice(&0u16.to_le_bytes());

    // Call ID
    pkt.extend_from_slice(&2u32.to_le_bytes());

    // Request-specific fields
    pkt.extend_from_slice(&0u32.to_le_bytes()); // Alloc hint
    pkt.extend_from_slice(&0u16.to_le_bytes()); // Context ID
    pkt.extend_from_slice(&2u16.to_le_bytes()); // Opnum: ept_lookup

    // ept_lookup parameters
    pkt.extend_from_slice(&0u32.to_le_bytes()); // inquiry_type: RPC_C_EP_ALL_ELTS
    pkt.extend_from_slice(&0u32.to_le_bytes()); // object (referent ID = 0, NULL)
    pkt.extend_from_slice(&0u32.to_le_bytes()); // interface_id (NULL)
    pkt.extend_from_slice(&0u32.to_le_bytes()); // vers_option
    pkt.extend_from_slice(&[0; 20]); // entry_handle (context handle, all zeros = first call)
    pkt.extend_from_slice(&100u32.to_le_bytes()); // max_ents: request 100 entries

    // Fill in fragment length
    let frag_len = pkt.len() as u16;
    pkt[frag_len_pos] = (frag_len & 0xff) as u8;
    pkt[frag_len_pos + 1] = ((frag_len >> 8) & 0xff) as u8;

    pkt
}

/// Parse EPM lookup response to extract endpoints
fn parse_epm_response(data: &[u8]) -> Option<Vec<RpcEndpoint>> {
    // Minimal parsing of the EPM response
    // The response starts with RPC response header (24 bytes)
    if data.len() < 28 {
        return None;
    }

    // Skip RPC header
    let body = &data[24..];

    // entry_handle (20 bytes) + num_ents (4 bytes)
    if body.len() < 24 {
        return None;
    }
    let num_ents = u32::from_le_bytes([body[20], body[21], body[22], body[23]]) as usize;

    if num_ents == 0 {
        return Some(Vec::new());
    }

    // For simple display, we'll parse what we can from the towers
    // Each entry has: object UUID, annotation, tower
    let mut endpoints = Vec::new();
    let mut pos = 28; // skip handle + num_ents + max_count

    for _ in 0..num_ents.min(50) {
        if pos + 16 >= body.len() {
            break;
        }

        // Object UUID (16 bytes)
        pos += 16;

        // Annotation: max_count (4) + offset (4) + actual_count (4) + string
        if pos + 12 > body.len() {
            break;
        }
        let _max_count =
            u32::from_le_bytes([body[pos], body[pos + 1], body[pos + 2], body[pos + 3]]);
        pos += 4;
        let _offset = u32::from_le_bytes([body[pos], body[pos + 1], body[pos + 2], body[pos + 3]]);
        pos += 4;
        let actual_count =
            u32::from_le_bytes([body[pos], body[pos + 1], body[pos + 2], body[pos + 3]]) as usize;
        pos += 4;

        if pos + actual_count > body.len() {
            break;
        }
        let annotation = String::from_utf8_lossy(&body[pos..pos + actual_count])
            .trim_end_matches('\0')
            .to_string();
        pos += actual_count;

        // Align to 4 bytes
        pos = (pos + 3) & !3;

        // Tower (tower_length (4) + tower data)
        if pos + 4 > body.len() {
            break;
        }
        let tower_len =
            u32::from_le_bytes([body[pos], body[pos + 1], body[pos + 2], body[pos + 3]]) as usize;
        pos += 4;

        // Actual tower_length repeated
        if pos + 4 > body.len() {
            break;
        }
        let _actual_tower_len =
            u32::from_le_bytes([body[pos], body[pos + 1], body[pos + 2], body[pos + 3]]) as usize;
        pos += 4;

        if pos + tower_len > body.len() {
            // try to parse what we have, but skip
            pos += tower_len.min(body.len() - pos);
            continue;
        }

        let tower_data = &body[pos..pos + tower_len];
        pos += tower_len;

        // Parse tower floors for protocol/endpoint info
        if let Some((proto, endpoint)) = parse_tower(tower_data) {
            endpoints.push(RpcEndpoint {
                protocol: proto,
                endpoint,
                annotation: if annotation.is_empty() {
                    "(no annotation)".to_string()
                } else {
                    annotation
                },
            });
        }
    }

    Some(endpoints)
}

/// Parse a tower structure to extract protocol and endpoint
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

        // LHS (left-hand side of floor)
        let lhs_len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if pos + lhs_len > data.len() {
            break;
        }
        let _lhs = &data[pos..pos + lhs_len];
        pos += lhs_len;

        // RHS (right-hand side of floor)
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

        // Floor 3 usually contains protocol ID
        // Floor 4 usually contains port
        // Floor 5 usually contains IP
        match i {
            2 => {
                // Protocol floor
                if !_lhs.is_empty() {
                    match _lhs[0] {
                        0x07 => protocol = "tcp".to_string(),
                        0x08 => protocol = "udp".to_string(),
                        0x09 => protocol = "ip".to_string(),
                        0x0f => protocol = "ncacn_np".to_string(),
                        0x10 => protocol = "ncacn_nb".to_string(),
                        0x1f => protocol = "ncacn_http".to_string(),
                        _ => protocol = format!("proto(0x{:02x})", _lhs[0]),
                    }
                }
                // Port or pipe name
                if protocol == "ncacn_np" {
                    endpoint = String::from_utf8_lossy(rhs)
                        .trim_end_matches('\0')
                        .to_string();
                } else if rhs.len() >= 2 {
                    let port = u16::from_be_bytes([rhs[0], rhs[1]]);
                    endpoint = port.to_string();
                }
            }
            3 => {
                // Sometimes this floor has additional info
                if protocol.is_empty() && !_lhs.is_empty() {
                    match _lhs[0] {
                        0x07 => {
                            protocol = "tcp".to_string();
                            if rhs.len() >= 2 {
                                endpoint = u16::from_be_bytes([rhs[0], rhs[1]]).to_string();
                            }
                        }
                        0x09 => {
                            // IP address floor
                            if rhs.len() >= 4 {
                                endpoint = format!("{}.{}.{}.{}", rhs[0], rhs[1], rhs[2], rhs[3]);
                            }
                        }
                        _ => {}
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
