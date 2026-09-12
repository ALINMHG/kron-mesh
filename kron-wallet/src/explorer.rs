//! Poll the local explorer HTTP API (`127.0.0.1:8080` by default).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use serde::Deserialize;

use crate::amount::format_kron_amount;

pub const DEFAULT_EXPLORER: &str = "127.0.0.1:8080";

#[derive(Clone, Debug)]
pub struct ExplorerView {
    pub online: bool,
    pub dag_tx_count: u64,
    pub circulating: String,
    pub balance_text: String,
    pub txs: Vec<HistoryRow>,
}

impl Default for ExplorerView {
    fn default() -> Self {
        Self {
            online: false,
            dag_tx_count: 0,
            circulating: String::new(),
            balance_text: format_kron_amount(0),
            txs: Vec::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct HistoryRow {
    pub from: String,
    pub to: String,
    pub amount: String,
    pub dag_tx_index: u64,
}

#[derive(Deserialize)]
struct StatsJson {
    #[serde(default)]
    dag_tx_count: Option<u64>,
    #[serde(default)]
    tx_count: Option<u64>,
    #[serde(default)]
    circulating_kron: Option<String>,
}

#[derive(Deserialize)]
struct WalletJson {
    #[serde(default)]
    balance: u64,
    #[serde(default)]
    nonce: u64,
    #[serde(default)]
    txs: Vec<TxJson>,
}

#[derive(Clone, Debug)]
pub struct ComposeHint {
    pub nonce: u64,
    pub parent_1: [u8; 32],
    pub parent_2: [u8; 32],
    pub balance: u64,
}

#[derive(Deserialize)]
struct ComposeJson {
    #[serde(default)]
    nonce: u64,
    #[serde(default)]
    balance: u64,
    #[serde(default)]
    parent_1: Option<String>,
    #[serde(default)]
    parent_2: Option<String>,
}

#[derive(Deserialize)]
struct TxJson {
    #[serde(default)]
    from: String,
    #[serde(default)]
    to: String,
    #[serde(default)]
    amount: u64,
    #[serde(default)]
    dag_tx_index: Option<u64>,
}

pub fn explorer_host() -> String {
    std::env::var("KRON_EXPLORER")
        .ok()
        .map(|s| {
            s.trim()
                .trim_start_matches("http://")
                .trim_start_matches("https://")
                .trim_end_matches('/')
                .to_string()
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_EXPLORER.to_string())
}

pub fn fetch_view(address: &str) -> ExplorerView {
    let host = explorer_host();
    let stats = match get_json(&host, "/api/stats") {
        Ok(body) => serde_json::from_str::<StatsJson>(&body).ok(),
        Err(_) => {
            return ExplorerView {
                online: false,
                ..ExplorerView::default()
            };
        }
    };
    let Some(stats) = stats else {
        return ExplorerView {
            online: false,
            ..ExplorerView::default()
        };
    };
    let path = format!("/api/wallet/{}", encode_path(address));
    let wallet = get_json(&host, &path)
        .ok()
        .and_then(|b| serde_json::from_str::<WalletJson>(&b).ok())
        .unwrap_or(WalletJson {
            balance: 0,
            nonce: 0,
            txs: Vec::new(),
        });
    let txs = wallet
        .txs
        .into_iter()
        .rev()
        .take(12)
        .map(|tx| HistoryRow {
            from: tx.from,
            to: tx.to,
            amount: format_kron_amount(tx.amount),
            dag_tx_index: tx.dag_tx_index.unwrap_or(0),
        })
        .collect();
    ExplorerView {
        online: true,
        dag_tx_count: stats.dag_tx_count.or(stats.tx_count).unwrap_or(0),
        circulating: stats.circulating_kron.unwrap_or_default(),
        balance_text: format_kron_amount(wallet.balance),
        txs,
    }
}

fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    let hex = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(hex).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut h = [0u8; 32];
    h.copy_from_slice(&bytes);
    Some(h)
}

/// Fetch parents + nonce so a send can attach to the live Mesh DAG.
pub fn fetch_compose(address: &str) -> Option<ComposeHint> {
    let host = explorer_host();
    let path = format!("/api/compose/{}", encode_path(address));
    let body = get_json(&host, &path).ok()?;
    let parsed: ComposeJson = serde_json::from_str(&body).ok()?;
    let p1 = parsed.parent_1.as_deref().and_then(parse_hex32)?;
    let p2 = parsed.parent_2.as_deref().and_then(parse_hex32)?;
    Some(ComposeHint {
        nonce: parsed.nonce,
        parent_1: p1,
        parent_2: p2,
        balance: parsed.balance,
    })
}

fn encode_path(s: &str) -> String {
    let mut out = String::new();
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' => {
                out.push(*b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn get_json(host: &str, path: &str) -> Result<String, ()> {
    let mut stream = TcpStream::connect(host).map_err(|_| ())?;
    let _ = stream.set_read_timeout(Some(Duration::from_millis(800)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(800)));
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).map_err(|_| ())?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).map_err(|_| ())?;
    let text = String::from_utf8_lossy(&buf);
    let status_ok = text.starts_with("HTTP/1.1 200") || text.starts_with("HTTP/1.0 200");
    if !status_ok {
        return Err(());
    }
    let body = text.split("\r\n\r\n").nth(1).or_else(|| text.split("\n\n").nth(1));
    Ok(body.unwrap_or("").to_string())
}
