//! KRON Mesh node.
//!
//! On a phone (ARM / Termux) this is a full DAG hub: WAL, P2P listen, mesh sync.
//! On x86 Windows it is a **read-only explorer viewer** — it may follow a phone
//! to display http://127.0.0.1:8080 but is not a required bootstrap and does
//! not mint. The network is phones.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use new_blockchain::anti_bot::profile::DeviceClass;
use new_blockchain::crypto::lattice::LatticeKeyPair;
use new_blockchain::dag::DagTransaction;
use new_blockchain::economics::{HARD_CAP, PREMINE, UNITS_PER_COIN};
use new_blockchain::explorer::start_explorer_http;
use new_blockchain::kron::{KronAddress, KronKeypair};
use new_blockchain::p2p::handshake::HandshakeConfig;
use new_blockchain::p2p::mesh::{mesh_sync_connect, HubState, MeshGraph, MeshRole};
use new_blockchain::p2p::peer::PeerRole;
use new_blockchain::p2p::P2pNode;
use new_blockchain::persist::{DagSnapshot, DagStore};
use new_blockchain::types::message::MeshMessage;

const USAGE: &str = "\
KRON Mesh node — phones ARE the network. The PC is an optional explorer.

PHONE (Termux / ARM) — full hub (WAL + P2P + kron-mesh/1). Pair with kron-phone to mine:
  kron-node --port 8000
  kron-node --port 8000 --bootstrap <OTHER_PHONE_IP>:8000

PC (Windows x86) — read-only viewer (default). Does not mint. Offline PC does not
block the mesh. Follow a phone to populate the explorer:
  kron-node --follow <PHONE_IP>:8000 --explorer-port 8080 --read-only

USAGE
  kron-node [options]
  kron-node credit --to kron1... --amount AMOUNT [--data-dir DIR]
  kron-node --print-identity [--data-dir DIR]
  kron-node --help

OPTIONS
  --port PORT                 Listen port (default 8000; phone hub / optional viewer)
  --follow IP:PORT            Pull vertices from a phone (alias: --bootstrap)
  --bootstrap IP:PORT         Another *phone* hub, never a required PC
  --data-dir DIR              Persist identity, WAL, snapshot
  --name NAME                 Label used in logs
  --explorer-port PORT        Local explorer HTTP (default 8080 on PC)
  --read-only                 Viewer mode (default on x86)
  --no-mine                   Explicit: this process never mines
  --print-identity            Create/load identity, print kron1, exit
  --help                      Show this help

Wallet broadcast: KRON_GATEWAY=<PHONE_IP>:8000 (default 127.0.0.1:8000).
Economics: HARD_CAP 24_000_000 KRON, PREMINE=0, fee=0.001 KRON, 0.1 KRON/tx,
80% miner phone / 20% relays, halving every 126_144_000 txs.
";

struct Args {
    port: u16,
    explorer_port: u16,
    data_dir: PathBuf,
    follow: Option<SocketAddr>,
    name: String,
    print_identity: bool,
    read_only: bool,
}

fn is_pc_viewer() -> bool {
    cfg!(any(target_arch = "x86_64", target_arch = "x86"))
}

fn main() {
    if let Err(err) = run() {
        eprintln!("[KRON ERROR] {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    if raw.iter().any(|a| a == "--help" || a == "-h") {
        print!("{USAGE}");
        return Ok(());
    }
    if raw.iter().any(|a| a == "--mine" || a == "--miner-only" || a == "--miner-ui") {
        return Err(
            "mining is phone-only. On Termux run kron-phone (node+miner). This PC is a read-only explorer."
                .into(),
        );
    }
    if raw.first().map(|s| s.as_str()) == Some("send") {
        return run_send(&raw[1..]);
    }
    if raw.first().map(|s| s.as_str()) == Some("credit") {
        return run_credit(&raw[1..]);
    }
    let args = parse_args(&raw)?;
    if args.print_identity {
        let (wallet, created) = load_or_create_identity(&args.data_dir)?;
        println!("[KRON INFO] data-dir {}", args.data_dir.display());
        println!(
            "[KRON INFO] identity {} ({})",
            wallet.address().as_str(),
            if created { "created" } else { "loaded" }
        );
        return Ok(());
    }
    run_gateway(args)
}

fn parse_args(raw: &[String]) -> Result<Args, String> {
    let mut port = 8000u16;
    let mut explorer_port = 8080u16;
    let mut data_dir = None;
    let mut follow = None;
    let pc = is_pc_viewer();
    let mut name = if pc {
        String::from("viewer")
    } else {
        String::from("phone-hub")
    };
    let mut print_identity = false;
    let mut read_only = pc;
    let mut i = 0;
    while i < raw.len() {
        match raw[i].as_str() {
            "--port" => {
                i += 1;
                port = raw
                    .get(i)
                    .ok_or("--port requires a value")?
                    .parse()
                    .map_err(|_| "invalid --port")?;
            }
            "--explorer-port" => {
                i += 1;
                explorer_port = raw
                    .get(i)
                    .ok_or("--explorer-port requires a value")?
                    .parse()
                    .map_err(|_| "invalid --explorer-port")?;
            }
            "--data-dir" => {
                i += 1;
                data_dir = Some(PathBuf::from(raw.get(i).ok_or("--data-dir requires a path")?));
            }
            "--follow" | "--bootstrap" | "--node" => {
                i += 1;
                let v = raw.get(i).ok_or("--follow/--bootstrap requires IP:PORT")?;
                follow = Some(v.parse().map_err(|_| format!("invalid peer '{v}'"))?);
            }
            "--name" => {
                i += 1;
                name = raw.get(i).ok_or("--name requires a value")?.clone();
            }
            "--read-only" | "--no-mine" => read_only = true,
            "--print-identity" => print_identity = true,
            other => return Err(format!("unknown argument: {other}")),
        }
        i += 1;
    }
    if pc {
        read_only = true;
    }
    Ok(Args {
        port,
        explorer_port,
        data_dir: data_dir.unwrap_or_else(|| default_data_dir(port)),
        follow,
        name,
        print_identity,
        read_only,
    })
}

fn default_data_dir(port: u16) -> PathBuf {
    let mut dir = std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    dir.push("KRON");
    dir.push(format!("gateway-{port}"));
    dir
}

fn run_gateway(args: Args) -> Result<(), String> {
    let (wallet, created) = load_or_create_identity(&args.data_dir)?;
    let identity = wallet.lattice().clone();
    let store = DagStore::open(&args.data_dir).map_err(|e| e.to_string())?;
    let (dag, snap) = store.load().map_err(|e| e.to_string())?;
    let faucet = snap.faucet.clone();

    let role_label = if args.read_only {
        "VIEWER"
    } else {
        "HUB"
    };
    println!(
        "[KRON {role_label}] {} identity {} ({}) data-dir {}",
        args.name,
        wallet.address().as_str(),
        if created { "created" } else { "loaded" },
        args.data_dir.display()
    );
    println!(
        "[KRON {role_label}] DAG vertices={} tips={} txs={} supply={} HARD_CAP={} PREMINE={}",
        dag.vertex_count(),
        dag.tips().len(),
        dag.dag_tx_count,
        dag.current_supply,
        HARD_CAP,
        PREMINE
    );
    if args.read_only {
        println!(
            "[KRON VIEWER] read-only explorer — phones are the network; this PC is optional"
        );
    }

    let (p2p_role, class) = if args.read_only {
        (PeerRole::CoreValidator, DeviceClass::PersonalComputer)
    } else {
        (PeerRole::EdgeMiner, DeviceClass::LegacyMobile)
    };
    let hs = HandshakeConfig::honest(identity, p2p_role, class, false);
    let bind = SocketAddr::from(([0, 0, 0, 0], args.port));
    let p2p = P2pNode::bind_on(hs, bind).map_err(|e| format!("P2P bind failed: {e}"))?;
    println!(
        "[KRON {role_label}] listen {} (0.0.0.0:{}) kron-mesh/1",
        p2p.addr, args.port
    );

    if let Some(peer) = args.follow {
        match p2p.connect(peer) {
            Ok(info) => println!(
                "[KRON {role_label}] following {peer} authenticity={}",
                info.score.authenticity
            ),
            Err(e) => eprintln!("[KRON {role_label}] follow {peer} failed: {e}"),
        }
    } else if args.read_only {
        println!("[KRON VIEWER] no --follow <PHONE_IP>:8000 — explorer stays empty until a phone is followed");
    }

    if !args.read_only {
        for tx in dag.transactions_in_order() {
            if !tx.is_genesis() {
                let _ = p2p.broadcast(MeshMessage::Vertex(tx));
            }
        }
    }

    let hub = HubState::new(dag);
    hub.set_store(store);
    {
        let dag = hub.lock_dag();
        hub.api().sync_from_dag(&dag);
        let _ = faucet;
    }
    p2p.attach_graph(hub.clone());

    let stop = Arc::new(AtomicBool::new(false));
    install_ctrl_c(stop.clone());
    let explorer_addr = start_explorer_http(hub.explorer_api(), args.explorer_port, stop.clone())
        .map_err(|e| format!("explorer bind: {e}"))?;
    println!("[KRON {role_label}] explorer http://{explorer_addr}");

    if let Some(peer) = args.follow {
        match mesh_sync_connect(peer, hub.clone(), MeshRole::Hub) {
            Ok(()) => println!(
                "[KRON {role_label}] mesh sync with {peer} vertices={}",
                hub.lock_dag().vertex_count()
            ),
            Err(e) => eprintln!("[KRON {role_label}] mesh sync {peer} failed: {e}"),
        }
        let hub_bg = hub.clone();
        let stop_bg = stop.clone();
        thread::spawn(move || {
            while !stop_bg.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(500));
                let _ = mesh_sync_connect(peer, hub_bg.clone(), MeshRole::Hub);
            }
        });
    }

    let p2p = Arc::new(p2p);
    let gossip_out = !args.read_only;

    while !stop.load(Ordering::SeqCst) {
        for (_from, msg) in p2p.take_delivered_from() {
            let MeshMessage::Vertex(tx) = msg;
            if let Err(e) = ingest_hub(&hub, &p2p, tx, gossip_out) {
                eprintln!("[KRON {role_label}] drop vertex: {e}");
            }
        }
        thread::sleep(Duration::from_millis(40));
    }
    p2p.shutdown();
    hub.persist_snapshot();
    println!("[KRON {role_label}] shutdown");
    Ok(())
}

fn ingest_hub(
    hub: &HubState,
    p2p: &P2pNode,
    tx: DagTransaction,
    gossip: bool,
) -> Result<(), String> {
    let new = hub.ingest(tx.clone())?;
    if new && gossip {
        let _ = p2p.broadcast(MeshMessage::Vertex(tx));
    }
    Ok(())
}

fn run_send(_raw: &[String]) -> Result<(), String> {
    Err(
        "kron-node does not send. Phones attach vertices (Termux kron-phone)."
            .into(),
    )
}

fn run_credit(raw: &[String]) -> Result<(), String> {
    let (to, amount, _port, data_dir) = parse_money_cmd(raw)?;
    let store = DagStore::open(&data_dir).map_err(|e| e.to_string())?;
    let (mut dag, mut snap) = store.load().map_err(|e| e.to_string())?;
    let units = parse_kron_amount(&amount)?;
    let addr = *to.as_bytes();
    dag.credit_account(addr, units);
    let entry = snap.faucet.entry(addr).or_insert(0);
    *entry = entry.saturating_add(units);
    store
        .write_snapshot(&DagSnapshot::from_dag_with_faucet(&dag, snap.faucet))
        .map_err(|e| e.to_string())?;
    println!(
        "[KRON] credited {} with {} (faucet; not minted supply; apply this on the phone hub data-dir)",
        to.as_str(),
        units
    );
    Ok(())
}

fn parse_money_cmd(raw: &[String]) -> Result<(KronAddress, String, u16, PathBuf), String> {
    let mut to = None;
    let mut amount = None;
    let mut port = 8000u16;
    let mut data_dir = None;
    let mut i = 0;
    while i < raw.len() {
        match raw[i].as_str() {
            "--to" => {
                i += 1;
                let v = raw.get(i).ok_or("--to requires kron1...")?;
                to = Some(KronAddress::parse(v).map_err(|e| e.to_string())?);
            }
            "--amount" => {
                i += 1;
                amount = Some(raw.get(i).ok_or("--amount requires a value")?.clone());
            }
            "--port" => {
                i += 1;
                port = raw.get(i).ok_or("--port requires a value")?.parse().map_err(|_| "invalid --port")?;
            }
            "--data-dir" => {
                i += 1;
                data_dir = Some(PathBuf::from(raw.get(i).ok_or("--data-dir requires a path")?));
            }
            other => return Err(format!("unknown argument: {other}")),
        }
        i += 1;
    }
    Ok((
        to.ok_or("--to kron1... is required")?,
        amount.ok_or("--amount is required")?,
        port,
        data_dir.unwrap_or_else(|| default_data_dir(port)),
    ))
}

fn parse_kron_amount(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("amount is empty".into());
    }
    let (whole, frac) = match s.split_once('.') {
        Some((w, f)) => (w, f),
        None => (s, ""),
    };
    let whole: u64 = if whole.is_empty() {
        0
    } else {
        whole.parse().map_err(|_| "invalid amount")?
    };
    let mut frac_digits = frac.chars().filter(|c| c.is_ascii_digit()).collect::<String>();
    if frac_digits.len() > 6 {
        return Err("amount has more than 6 decimals".into());
    }
    while frac_digits.len() < 6 {
        frac_digits.push('0');
    }
    let frac: u64 = if frac_digits.is_empty() {
        0
    } else {
        frac_digits.parse().map_err(|_| "invalid amount")?
    };
    whole
        .checked_mul(UNITS_PER_COIN)
        .and_then(|w| w.checked_add(frac))
        .ok_or_else(|| "amount overflow".into())
}

fn load_or_create_identity(dir: &Path) -> Result<(KronKeypair, bool), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("create data-dir {}: {e}", dir.display()))?;
    let seed_path = dir.join("identity.seed");
    if seed_path.exists() {
        let raw = std::fs::read_to_string(&seed_path)
            .map_err(|e| format!("read {}: {e}", seed_path.display()))?;
        let hex_str = raw
            .lines()
            .find(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
            .unwrap_or("")
            .trim();
        let bytes = hex::decode(hex_str).map_err(|e| format!("identity.seed hex: {e}"))?;
        if bytes.len() != 32 {
            return Err("identity.seed must be 32 bytes (64 hex chars)".into());
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        return Ok((KronKeypair::from_lattice(LatticeKeyPair::from_seed(seed)), false));
    }
    let mut seed = [0u8; 32];
    {
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut seed);
    }
    let wallet = KronKeypair::from_lattice(LatticeKeyPair::from_seed(seed));
    let body = format!(
        "# KRON gateway ML-DSA-44 seed (keep private)\n{}\n",
        hex::encode(seed)
    );
    std::fs::write(&seed_path, body).map_err(|e| format!("write {}: {e}", seed_path.display()))?;
    let _ = std::fs::write(dir.join("address.txt"), format!("{}\n", wallet.address()));
    Ok((wallet, true))
}

fn install_ctrl_c(stop: Arc<AtomicBool>) {
    let _ = stop;
}
