//! KRON Mesh node.
//!
//! * **Listen `0.0.0.0` without `--follow`** — public hub/relay (x86 Linux VPS
//!   is OK). `--hub` is an alias. Never mines. Phones
//!   `--bootstrap <VPS_PUBLIC_IP>:8000`.
//! * **ARM / Termux** — full DAG hub (WAL + P2P). Pair with `kron-phone` to mine.
//! * **Windows / `--follow` / `--read-only`** — read-only explorer viewer.
//!   Does not mint. The home PC is not the mesh identity.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use new_blockchain::anti_bot::profile::DeviceClass;
use new_blockchain::crypto::lattice::LatticeKeyPair;
use new_blockchain::dag::DagTransaction;
use new_blockchain::economics::{HARD_CAP, PREMINE, UNITS_PER_COIN};
use new_blockchain::kron::cli::{
    decide_node_run_mode, is_phone_mine_cli_token, looks_like_kron1, parse_kron1_arg,
    parse_node_cli, sanitize_cli_value, split_eq_flag, take_cli_value, unknown_argument,
    CREDIT_FLAGS, NODE_MINE_REFUSAL, NodeRunMode,
};
use new_blockchain::kron::{
    default_public_ipv4, is_self_hub_target, resolve_bootstrap, resolve_bootstrap_optional,
    DEFAULT_BOOTSTRAP, DEFAULT_EXPLORER_URL,
};
use new_blockchain::kron::{KronAddress, KronKeypair};
use new_blockchain::p2p::handshake::HandshakeConfig;
use new_blockchain::p2p::mesh::{HubState, MeshGraph};
use new_blockchain::p2p::overlay::NodeOverlayId;
use new_blockchain::p2p::peer::PeerRole;
use new_blockchain::p2p::spawn_peer_link;
use new_blockchain::explorer::start_explorer_http_advertised;
use new_blockchain::listen::{
    advertised_public_ipv4, detect_lan_ipv4, format_lan_address_line, format_p2p_listen_line,
    format_public_explorer_url, is_addr_in_use, log_port_in_use,
};
use new_blockchain::p2p::{NetworkError, P2pNode};
use new_blockchain::persist::{DagSnapshot, DagStore};
use new_blockchain::types::message::MeshMessage;
use new_blockchain::{kron_elog, kron_log};

const USAGE: &str = "\
KRON Mesh node — phones mine. A paid VPS listens; phones connect inbound.

VPS (x86 Linux OK) — gossip relay + explorer. Never mines. No --follow:
  kron-node --port 8000 --explorer-port 8080 --data-dir /var/lib/kron
  # --hub is an optional alias of the same mode; do not require it
  # ufw allow 8000 && ufw allow 8080
  # phones: kron-phone --mine --reward-address kron1...   (dials this hub by default)
  # browser: http://144.91.105.244:8080
  # tmux: tmux attach -t kron   OR   tmux new -s kron2
  #        tmux kill-session -t kron && tmux new -s kron

PHONE (Termux / ARM) — full hub (WAL + P2P + kron-mesh/1). Pair with kron-phone to mine:
  kron-node --port 8000
  kron-node --port 8000 --bootstrap 144.91.105.244:8000

PC (Windows) — read-only viewer. Does not mint. Requires --follow:
  kron-node --follow 144.91.105.244:8000 --explorer-port 8080 --read-only
  # or --follow <PHONE_LAN_IP>:8000
  # public explorer: http://144.91.105.244:8080

USAGE
  kron-node [options]
  kron-node credit --to kron1... --amount AMOUNT [--data-dir DIR]
  kron-node --print-identity [--data-dir DIR]
  kron-node --help

OPTIONS
  --hub                       Public gossip relay (VPS). Alias of: listen, no --follow
  --port PORT                 Listen port (default 8000). Binds 0.0.0.0
  --follow IP:PORT            Viewer pull (alias: --bootstrap). Optional on --hub
  --bootstrap IP:PORT         VPS or another hub (also KRON_BOOTSTRAP / bootstrap.txt)
  --public-ip IPV4            Printed explorer / wait-for-phones host
  --data-dir DIR              Persist identity, WAL, snapshot
  --name NAME                 Label used in logs
  --explorer-port PORT        Explorer HTTP (default 8080, binds 0.0.0.0)
  --read-only                 Viewer mode (home PC; use with --follow)
  --no-mine                   Explicit: this process never mines (hub still relays)
  --no-discovery              Disable LAN UDP beacons (default off on --hub / viewer)
  --print-identity            Create/load identity, print kron1 + Mesh ID, exit
  --help                      Show this help

Mining flags (--mine, --reward-address, --miner-address, positional kron1...)
are rejected here. Use Termux: kron-phone --mine --reward-address kron1...

Wallet broadcast: KRON_GATEWAY=144.91.105.244:8000 (default 127.0.0.1:8000).
Economics: HARD_CAP 24_000_000 KRON, PREMINE=0, fee=0.001 KRON, 0.1 KRON/tx,
80% miner phone / 20% relays, halving every 126_144_000 txs.
";

struct Args {
    port: u16,
    explorer_port: u16,
    data_dir: PathBuf,
    follow: Vec<SocketAddr>,
    name: String,
    print_identity: bool,
    /// Home-PC viewer: no gossip fan-out.
    viewer: bool,
    /// Paid VPS / public relay: gossip + WAL, never mines.
    public_hub: bool,
    /// Host printed in explorer / wait-for-phones lines (never 0.0.0.0).
    public_ip: Ipv4Addr,
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
    if raw.first().map(|s| s.as_str()) == Some("send") {
        return run_send(&raw[1..]);
    }
    if raw.first().map(|s| s.as_str()) == Some("credit") {
        return run_credit(&raw[1..]);
    }
    if raw.iter().any(|a| is_phone_mine_cli_token(a)) {
        return Err(NODE_MINE_REFUSAL.into());
    }
    let args = parse_args(&raw)?;
    if args.print_identity {
        let (wallet, created) = load_or_create_identity(&args.data_dir)?;
        let overlay = NodeOverlayId::from_pubkey(wallet.public_key());
        println!("[KRON INFO] data-dir {}", args.data_dir.display());
        println!(
            "[KRON INFO] identity {} ({})",
            wallet.address().as_str(),
            if created { "created" } else { "loaded" }
        );
        println!("[KRON INFO] Mesh ID: {}", overlay.to_ula());
        return Ok(());
    }
    run_gateway(args)
}

fn parse_args(raw: &[String]) -> Result<Args, String> {
    let parsed = parse_node_cli(raw)?;
    let mode = decide_node_run_mode(
        parsed.public_hub,
        parsed.read_only,
        parsed.follow.is_some(),
        is_pc_viewer(),
    );
    let public_hub = mode == NodeRunMode::PublicHub;
    let viewer = mode == NodeRunMode::Viewer;
    let name = parsed.name.unwrap_or_else(|| {
        if public_hub {
            String::from("vps-hub")
        } else if viewer {
            String::from("viewer")
        } else {
            String::from("phone-hub")
        }
    });
    let data_dir = parsed
        .data_dir
        .unwrap_or_else(|| default_data_dir(parsed.port));
    // VPS hub is the public entry — do not dial itself. Phones/viewers default to it.
    let follow = if public_hub {
        resolve_bootstrap_optional(parsed.follow, &data_dir)?
    } else {
        resolve_bootstrap(parsed.follow, &data_dir)?
    };
    let public_ip = advertised_public_ipv4(parsed.public_ip, default_public_ipv4());
    Ok(Args {
        port: parsed.port,
        explorer_port: parsed.explorer_port,
        data_dir,
        follow,
        name,
        print_identity: parsed.print_identity,
        viewer,
        public_hub,
        public_ip,
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

    let role_label = if args.public_hub {
        "KRON HUB"
    } else if args.viewer {
        "KRON VIEWER"
    } else {
        "KRON NODE"
    };
    kron_log(
        role_label,
        format!(
            "{} identity {} ({}) data-dir {}",
            args.name,
            wallet.address().as_str(),
            if created { "created" } else { "loaded" },
            args.data_dir.display()
        ),
    );
    kron_log(
        role_label,
        format!(
            "DAG vertices={} tips={} txs={} supply={} HARD_CAP={} PREMINE={}",
            dag.vertex_count(),
            dag.tips().len(),
            dag.dag_tx_count,
            dag.current_supply,
            HARD_CAP,
            PREMINE
        ),
    );
    let overlay = NodeOverlayId::from_pubkey(wallet.public_key());
    let explorer_url = format_public_explorer_url(args.public_ip, args.explorer_port);
    if args.public_hub {
        kron_log(
            role_label,
            "public hub — gossip relay + explorer; this process never mines",
        );
        kron_log(
            role_label,
            format!(
                "waiting for phones to connect to {}:{}",
                args.public_ip, args.port
            ),
        );
        kron_log(
            role_label,
            format!("phones dial {DEFAULT_BOOTSTRAP} (no --bootstrap required)"),
        );
        kron_log(role_label, DEFAULT_EXPLORER_URL);
    } else if args.viewer {
        kron_log(
            role_label,
            "read-only explorer — phones mine; this PC is optional",
        );
    }

    let (p2p_role, class) = if args.public_hub || args.viewer {
        (PeerRole::CoreValidator, DeviceClass::PersonalComputer)
    } else {
        (PeerRole::EdgeMiner, DeviceClass::LegacyMobile)
    };
    let hs = HandshakeConfig::honest(identity, p2p_role, class, false);
    let bind = SocketAddr::from(([0, 0, 0, 0], args.port));
    let p2p = match P2pNode::bind_on(hs, bind) {
        Ok(p2p) => p2p,
        Err(NetworkError::Io(e)) if is_addr_in_use(&e) => {
            log_port_in_use(role_label, "P2P", args.port, "--port", Some(&e));
            return Err("P2P port already in use".into());
        }
        Err(e) => return Err(format!("P2P bind failed: {e}")),
    };
    let lan = detect_lan_ipv4();
    kron_log(role_label, format_p2p_listen_line(args.port));
    kron_log(role_label, format!("Mesh ID: {}", overlay.to_ula()));
    kron_log(role_label, wallet.address().as_str());
    kron_log(role_label, format_lan_address_line(lan, args.port));
    if args.public_hub {
        kron_log("KRON EXPLORER", &explorer_url);
    }

    let gossip_out = args.public_hub || !args.viewer;
    if gossip_out {
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
    let advertised = if args.public_hub {
        Some(args.public_ip)
    } else {
        None
    };
    let explorer_addr = match start_explorer_http_advertised(
        hub.explorer_api(),
        args.explorer_port,
        stop.clone(),
        advertised,
    ) {
        Ok(addr) => addr,
        Err(e) if is_addr_in_use(&e) => return Err("explorer port already in use".into()),
        Err(e) => return Err(format!("explorer bind: {e}")),
    };

    let p2p = Arc::new(p2p);
    let mut followed = 0usize;
    for peer in &args.follow {
        if is_self_hub_target(*peer, args.port, Some(args.public_ip), lan) {
            kron_log(
                role_label,
                format!("skip self-dial {peer} (this process is the hub)"),
            );
            continue;
        }
        kron_log(
            role_label,
            format!("following {peer} (gossip client in background)"),
        );
        spawn_peer_link(p2p.clone(), hub.clone(), *peer, stop.clone(), "follow");
        followed = followed.saturating_add(1);
    }
    if followed == 0 && args.viewer {
        kron_log(
            role_label,
            format!("no --follow — open {explorer_url} or --follow {DEFAULT_BOOTSTRAP}"),
        );
    }
    let mut last_hb = Instant::now();
    while !stop.load(Ordering::SeqCst) {
        for (_from, msg) in p2p.take_delivered_from() {
            let MeshMessage::Vertex(tx) = msg;
            if let Err(e) = ingest_hub(&hub, &p2p, tx, gossip_out) {
                kron_elog(role_label, format!("drop vertex: {e}"));
            }
        }
        if last_hb.elapsed() >= Duration::from_secs(5) {
            let dag = hub.lock_dag();
            let explorer = if args.public_hub {
                explorer_url.clone()
            } else {
                match lan {
                    Some(ip) => format!("http://{ip}:{}", explorer_addr.port()),
                    None => format!("http://127.0.0.1:{}", explorer_addr.port()),
                }
            };
            kron_log(
                role_label,
                format!(
                    "up explorer={explorer} vertices={} tips={}",
                    dag.vertex_count(),
                    dag.tips().len()
                ),
            );
            last_hb = Instant::now();
        }
        std::thread::sleep(Duration::from_millis(40));
    }
    p2p.shutdown();
    hub.persist_snapshot();
    kron_log(role_label, "shutdown");
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
        let token = sanitize_cli_value(&raw[i]);
        let (flag, inline) = split_eq_flag(&token);
        if !flag.starts_with('-') && looks_like_kron1(flag) {
            to = Some(parse_kron1_arg(flag)?);
            i += 1;
            continue;
        }
        match flag {
            "--to" => {
                to = Some(parse_kron1_arg(&take_cli_value(
                    inline,
                    raw,
                    &mut i,
                    "--to",
                )?)?);
            }
            "--amount" => {
                amount = Some(take_cli_value(inline, raw, &mut i, "--amount")?);
            }
            "--port" => {
                port = take_cli_value(inline, raw, &mut i, "--port")?
                    .parse()
                    .map_err(|_| "invalid --port")?;
            }
            "--data-dir" => {
                data_dir = Some(PathBuf::from(take_cli_value(
                    inline,
                    raw,
                    &mut i,
                    "--data-dir",
                )?));
            }
            other => return Err(unknown_argument(other, CREDIT_FLAGS)),
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
