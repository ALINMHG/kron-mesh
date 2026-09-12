//! Tiny std HTTP/1.1 explorer (no axum / tokio). Bound from the gateway CLI.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::economics::{HARD_CAP, UNITS_PER_COIN};
use crate::explorer::api::ExplorerApi;
use crate::explorer::indexer::{IndexedTransaction, IndexedVertex, NetworkStats, WalletSnapshot};
use crate::explorer::get_kron_asset_metadata;

const UI: &str = include_str!("ui.html");

/// Bind `127.0.0.1:port` and serve the explorer until `stop` is set.
pub fn start_explorer_http(
    api: Arc<Mutex<ExplorerApi>>,
    port: u16,
    stop: Arc<AtomicBool>,
) -> Result<SocketAddr, std::io::Error> {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = TcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;
    let bound = listener.local_addr()?;
    thread::Builder::new()
        .name("kron-explorer-http".into())
        .spawn(move || accept_loop(listener, api, stop))
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    Ok(bound)
}

fn accept_loop(listener: TcpListener, api: Arc<Mutex<ExplorerApi>>, stop: Arc<AtomicBool>) {
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                let api = api.clone();
                thread::spawn(move || {
                    if let Err(e) = handle_client(stream, &api) {
                        eprintln!("[KRON EXPLORER] request error: {e}");
                    }
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(25));
            }
            Err(_) => thread::sleep(Duration::from_millis(50)),
        }
    }
}

fn handle_client(mut stream: TcpStream, api: &Arc<Mutex<ExplorerApi>>) -> std::io::Result<()> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    let mut buf = [0u8; 8192];
    let n = stream.read(&mut buf)?;
    if n == 0 {
        return Ok(());
    }
    let req = String::from_utf8_lossy(&buf[..n]);
    let path = match req.lines().next() {
        Some(line) => {
            let mut parts = line.split_whitespace();
            let method = parts.next().unwrap_or("");
            let path = parts.next().unwrap_or("/");
            if method != "GET" {
                return write_response(&mut stream, 405, "text/plain; charset=utf-8", b"method not allowed");
            }
            path.to_string()
        }
        None => "/".to_string(),
    };
    let path = path.split('?').next().unwrap_or("/");
    dispatch(&mut stream, path, api)
}

fn dispatch(
    stream: &mut TcpStream,
    path: &str,
    api: &Arc<Mutex<ExplorerApi>>,
) -> std::io::Result<()> {
    if path == "/" || path == "/index.html" {
        return write_response(stream, 200, "text/html; charset=utf-8", UI.as_bytes());
    }
    let locked = match api.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    if path == "/api/stats" {
        return json_ok(stream, stats_json(&locked.get_network_stats()));
    }
    if path == "/api/metadata" {
        return json_ok(stream, metadata_json());
    }
    if path == "/api/vertices" || path == "/api/tips" {
        let verts = locked.recent_vertices(32);
        let body = format!(
            "[{}]",
            verts.iter().map(vertex_json).collect::<Vec<_>>().join(",")
        );
        return json_ok(stream, body);
    }
    if path == "/api/txs" {
        let txs = locked.recent_transactions(64);
        return json_ok(stream, txs_json(&txs));
    }
    if let Some(rest) = path.strip_prefix("/api/tx/") {
        let hash = percent_decode(rest);
        return match parse_tx_hash(&hash).and_then(|h| locked.get_transaction_by_hash(h)) {
            Some(tx) => json_ok(stream, tx_json(&tx)),
            None => json_err(stream, 404, "transaction not found"),
        };
    }
    if let Some(rest) = path.strip_prefix("/api/wallet/") {
        let addr = percent_decode(rest);
        let snap = locked.get_wallet_snapshot(addr);
        return json_ok(stream, wallet_json(&snap));
    }
    if let Some(rest) = path.strip_prefix("/api/compose/") {
        let addr = percent_decode(rest);
        let (nonce, p1, p2, balance) = locked.compose_hint(addr);
        let body = format!(
            "{{\"nonce\":{},\"balance\":{},\"parent_1\":{},\"parent_2\":{},\"tips\":[{}]}}",
            nonce,
            balance,
            json_str(&hex::encode(p1)),
            json_str(&hex::encode(p2)),
            locked
                .tips()
                .iter()
                .map(|t| json_str(&hex::encode(t)))
                .collect::<Vec<_>>()
                .join(",")
        );
        return json_ok(stream, body);
    }
    json_err(stream, 404, "not found")
}

fn json_ok(stream: &mut TcpStream, body: String) -> std::io::Result<()> {
    write_response(stream, 200, "application/json; charset=utf-8", body.as_bytes())
}

fn json_err(stream: &mut TcpStream, status: u16, msg: &str) -> std::io::Result<()> {
    write_response(
        stream,
        status,
        "application/json; charset=utf-8",
        format!("{{\"error\":{}}}", json_str(msg)).as_bytes(),
    )
}

fn write_response(
    stream: &mut TcpStream,
    status: u16,
    ctype: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Error",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    Ok(())
}

fn format_units(units: u64) -> String {
    let whole = units / UNITS_PER_COIN;
    let frac = units % UNITS_PER_COIN;
    format!("{whole}.{frac:06}")
}

fn json_str(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 32 => {}
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn metadata_json() -> String {
    let meta = get_kron_asset_metadata();
    format!(
        "{{\"name\":{},\"ticker\":{},\"decimals\":{}}}",
        json_str(meta.name),
        json_str(meta.ticker),
        meta.decimals
    )
}

fn stats_json(s: &NetworkStats) -> String {
    format!(
        "{{\"vertex_count\":{},\"tip_count\":{},\"dag_tx_count\":{},\"tx_count\":{},\"circulating_supply\":{},\"circulating_kron\":{},\"hard_cap\":{},\"hard_cap_kron\":{},\"txs_remaining_until_halving\":{}}}",
        s.vertex_count,
        s.tip_count,
        s.dag_tx_count,
        s.dag_tx_count,
        s.circulating_supply,
        json_str(&format_units(s.circulating_supply)),
        s.hard_cap,
        json_str(&format_units(HARD_CAP)),
        s.txs_remaining_until_halving
    )
}

fn wallet_json(w: &WalletSnapshot) -> String {
    format!(
        "{{\"address\":{},\"balance\":{},\"balance_kron\":{},\"nonce\":{},\"txs\":{}}}",
        json_str(&w.address),
        w.balance,
        json_str(&format_units(w.balance)),
        w.nonce,
        txs_json(&w.txs)
    )
}

fn txs_json(txs: &[IndexedTransaction]) -> String {
    format!("[{}]", txs.iter().map(tx_json).collect::<Vec<_>>().join(","))
}

fn tx_json(tx: &IndexedTransaction) -> String {
    let fs = &tx.fee_split;
    format!(
        "{{\"hash\":{},\"from\":{},\"to\":{},\"amount\":{},\"amount_kron\":{},\"fee\":{},\"fee_kron\":{},\"parent_1\":{},\"parent_2\":{},\"weight\":{},\"is_tip\":{},\"conflicted\":{},\"dag_tx_index\":{},\"fee_split\":{{\"miner_amount\":{},\"relay_amount\":{},\"miner_amount_kron\":{},\"relay_amount_kron\":{},\"miner_address\":{},\"relay_addresses\":[{}]}}}}",
        json_str(&hex::encode(tx.hash)),
        json_str(&tx.from),
        json_str(&tx.to),
        tx.amount,
        json_str(&format_units(tx.amount)),
        tx.fee,
        json_str(&format_units(tx.fee)),
        json_str(&hex::encode(tx.parent_1)),
        json_str(&hex::encode(tx.parent_2)),
        tx.weight,
        tx.is_tip,
        tx.conflicted,
        tx.dag_tx_index,
        fs.miner_amount,
        fs.relay_amount,
        json_str(&format_units(fs.miner_amount)),
        json_str(&format_units(fs.relay_amount)),
        json_str(&fs.miner_address),
        fs.relay_addresses
            .iter()
            .map(|a| json_str(a))
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn vertex_json(v: &IndexedVertex) -> String {
    format!(
        "{{\"hash\":{},\"tx_count\":{},\"subsidy\":{},\"subsidy_kron\":{},\"total_fees\":{},\"miner_share\":{},\"miner_share_kron\":{},\"relay_share\":{},\"relay_share_kron\":{},\"miner\":{},\"txs\":{}}}",
        json_str(&hex::encode(v.hash)),
        v.tx_count,
        v.subsidy,
        json_str(&format_units(v.subsidy)),
        v.total_fees,
        v.miner_share,
        json_str(&format_units(v.miner_share)),
        v.relay_share,
        json_str(&format_units(v.relay_share)),
        json_str(&v.miner),
        txs_json(&v.txs)
    )
}

fn parse_tx_hash(s: &str) -> Option<[u8; 32]> {
    let hex = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(hex).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut h = [0u8; 32];
    h.copy_from_slice(&bytes);
    Some(h)
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(v) = u8::from_str_radix(
                std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("00"),
                16,
            ) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}
