//! Termux phone client: in-process DAG hub + miner menu.
//!
//! On a phone (Linux aarch64 / Termux) the node and miner run in the same
//! process. On this Windows x86 box the menu and wallet generate still work;
//! the mine option is refused by the runtime enforcer.

use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use new_blockchain::anti_bot::profile::DeviceClass;
use new_blockchain::crypto::mobile_only::enforce_real_mobile;
use new_blockchain::dag::AttachingDevice;
use new_blockchain::economics::UNITS_PER_COIN;
use new_blockchain::persist::{DagSnapshot, DagStore};
use new_blockchain::explorer::start_explorer_http;
use new_blockchain::kron::cli::{
    is_incomplete_kron1, looks_like_kron1, parse_kron1_arg, parse_menu_reward_input, parse_phone_cli,
    sanitize_cli_value, split_eq_flag, take_cli_value, unknown_argument, CREDIT_FLAGS, PhoneCli,
};
use new_blockchain::kron::{is_self_hub_target, resolve_phone_bootstrap};
use new_blockchain::listen::{
    detect_lan_ipv4, format_lan_address_line, format_p2p_listen_line, is_addr_in_use,
    log_port_in_use, port_auto_candidates,
};
use new_blockchain::kron::{
    generate_recovery_wallet, load_mnemonic, load_phone_wallet, miner_tick, phone_wallet_exists,
    save_phone_wallet, KronAddress, KronKeypair, MinerTickStatus,
};
use new_blockchain::{kron_elog, kron_log};
use new_blockchain::p2p::handshake::HandshakeConfig;
use new_blockchain::p2p::mesh::{HubState, MeshGraph};
use new_blockchain::p2p::overlay::NodeOverlayId;
use new_blockchain::p2p::peer::PeerRole;
use new_blockchain::p2p::{
    spawn_hub_dial, spawn_lan_discovery, DiscoveryConfig, NetworkError, P2pNode,
};
use new_blockchain::types::message::MeshMessage;

const USAGE: &str = "\
KRON Mesh Termux client — phones ARE the network (node + miner, no PC required)

USAGE
  kron-phone
  kron-phone --generate-wallet [--data-dir DIR]
  kron-phone --mine --reward-address kron1... [--port PORT] [--port-auto] [--explorer-port PORT]
  kron-phone --mine --miner-address kron1...
  kron-phone --mine kron1...
  kron-phone --hub [--port PORT]
  kron-phone --mine --reward-address kron1... --no-discovery
  kron-phone --mine --reward-address kron1... --no-bootstrap
  kron-phone credit --to kron1... --amount AMOUNT [--data-dir DIR]
  kron-phone --show-mnemonic [--data-dir DIR]
  kron-phone --help

Same Wi‑Fi: two phones `--mine` find each other (UDP beacon on port+1). No PHONE_IP.
Internet: after listen, retries bootstrap.txt / KRON_BOOTSTRAP (default 144.91.105.244:8000).
  ./kron-phone --mine --reward-address kron1...
  ./kron-phone --mine --reward-address kron1... --no-bootstrap

Mining binds P2P 0.0.0.0:8000 (all interfaces) and explorer 0.0.0.0:8080.
Mesh ID is an fd00::/8 overlay id (not a public IP). LAN IPv4 is only for a PC explorer.
PC viewer (optional): kron-node --follow <PHONE_OR_VPS_IP>:8000 --explorer-port 8080 --read-only

Interactive menu (no flags):
  1) Generate KRON address + 24-word passphrase (wallet only — does not listen)
  2) Mine — prompt for a kron1 address; binds P2P :8000 + explorer :8080 once

On x86/Windows, option 2 / --mine / --hub are refused.
";

type Cli = PhoneCli;

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
    if raw.first().map(|s| s.as_str()) == Some("credit") {
        return run_credit(&raw[1..]);
    }
    let cli = parse_phone_cli(&raw)?;
    if cli.generate {
        return generate_wallet(&cli.data_dir);
    }
    if cli.show_mnemonic {
        return reveal_mnemonic(&cli.data_dir);
    }
    if cli.hub_only {
        return start_hub_only(&cli);
    }
    if cli.mine {
        let reward = match cli.reward.clone() {
            Some(addr) => addr,
            None if cli.prompt_mine => prompt_reward_address()?,
            None => {
                return Err(String::from(
                    "--mine requires --reward-address kron1... (or --miner-address / positional kron1...)",
                ))
            }
        };
        return start_node_and_mine(&cli, reward);
    }
    interactive_menu(&cli)
}

fn prompt_reward_address() -> Result<KronAddress, String> {
    loop {
        print!("Enter KRON wallet address (kron1...): ");
        let _ = io::stdout().flush();
        let mut addr = String::new();
        let n = io::stdin()
            .read_line(&mut addr)
            .map_err(|e| format!("stdin: {e}"))?;
        if n == 0 {
            return Err("stdin closed".into());
        }
        // Termux wraps ~63-char addresses; keep reading continuation lines.
        for _ in 0..4 {
            if !is_incomplete_kron1(&addr) {
                break;
            }
            let mut more = String::new();
            let n = io::stdin()
                .read_line(&mut more)
                .map_err(|e| format!("stdin: {e}"))?;
            if n == 0 || more.trim().is_empty() {
                break;
            }
            addr.push_str(&more);
        }
        match parse_menu_reward_input(&addr) {
            Ok(reward) => return Ok(reward),
            Err(e) if e == "empty address" => {
                kron_elog("KRON NODE", "empty address");
            }
            Err(e) => {
                kron_elog("KRON NODE", e);
            }
        }
    }
}

fn interactive_menu(cli: &Cli) -> Result<(), String> {
    loop {
        println!();
        kron_log(
            "KRON NODE",
            "KRON Mesh (Termux) — phones are the network; PC explorer is optional",
        );
        kron_log(
            "KRON NODE",
            "1) Generate KRON address (wallet only — does not start the node or bind :8000)",
        );
        kron_log(
            "KRON NODE",
            "2) Mine — enter a kron1 reward address; this process binds :8000 once and stays up",
        );
        println!("q) Quit");
        print!("> ");
        let _ = io::stdout().flush();
        let mut line = String::new();
        io::stdin()
            .read_line(&mut line)
            .map_err(|e| format!("stdin: {e}"))?;
        let choice = line.trim();
        match choice {
            "1" => {
                generate_wallet(&cli.data_dir)?;
                kron_log(
                    "KRON NODE",
                    "wallet only — not listening. Choose 2 or --mine to bind :8000",
                );
            }
            "2" => {
                let reward = prompt_reward_address()?;
                start_node_and_mine(cli, reward)?;
                return Ok(());
            }
            "q" | "Q" => return Ok(()),
            other => {
                if let Ok(reward) = parse_menu_reward_input(other) {
                    start_node_and_mine(cli, reward)?;
                    return Ok(());
                }
                println!("Choose 1, 2, or q. Paste a kron1... address to mine.");
            }
        }
    }
}

fn generate_wallet(dir: &Path) -> Result<(), String> {
    if phone_wallet_exists(dir) {
        let wallet = load_phone_wallet(dir)?;
        println!("[KRON PHONE] wallet already saved in {}", dir.display());
        println!("Address = {}", wallet.address().as_str());
        println!("Recovery phrase is not stored on disk. Write it down when generated.");
        println!("Wallet only — this did not start a node (no P2P listen on :8000).");
        return Ok(());
    }
    let (wallet, phrase, entropy) = generate_recovery_wallet();
    save_phone_wallet(dir, &entropy, &phrase, &wallet.address())?;
    println!("Address = {}", wallet.address().as_str());
    println!();
    println!("Write these 24 words down and keep them offline. They will not be shown again.");
    println!("{phrase}");
    println!();
    println!("Saved in {}", dir.display());
    println!("Wallet only — this did not start a node (no P2P listen on :8000).");
    println!("To mine: choose 2, or ./kron-phone --mine --reward-address {}", wallet.address().as_str());
    Ok(())
}

fn reveal_mnemonic(dir: &Path) -> Result<(), String> {
    let phrase = load_mnemonic(dir)?;
    let wallet = load_phone_wallet(dir)?;
    println!("Address = {}", wallet.address().as_str());
    println!("{phrase}");
    println!("(legacy file only — new wallets do not store the 24 words)");
    Ok(())
}

fn refuse_mine_on_pc() -> Result<(), String> {
    if cfg!(any(target_arch = "x86_64", target_arch = "x86")) {
        eprintln!("[KRON MINER] rejected: phone-only mesh attach (x86 host)");
        eprintln!("[KRON MINER] The library compiles here; this binary must not mine.");
        eprintln!("[KRON MINER] Use Termux on Android (aarch64):");
        eprintln!("  pkg install rust git");
        eprintln!("  cargo build --release -p new-blockchain");
        eprintln!("  ./target/release/kron-phone --mine --reward-address kron1...");
        return Err("mining is phone-only".into());
    }
    if cfg!(windows) {
        return Err("this Windows binary cannot attest as a phone".into());
    }
    if let Err(e) = enforce_real_mobile() {
        return Err(e.to_string());
    }
    Ok(())
}

fn start_hub_only(cli: &Cli) -> Result<(), String> {
    refuse_mine_on_pc().map_err(|_| {
        "this PC is not the network. Use Termux kron-phone --hub on a phone, or kron-node --follow <PHONE_IP>:8000 --read-only"
            .to_string()
    })?;
    let wallet = if phone_wallet_exists(&cli.data_dir) {
        load_phone_wallet(&cli.data_dir)?
    } else {
        let (w, phrase, entropy) = generate_recovery_wallet();
        save_phone_wallet(&cli.data_dir, &entropy, &phrase, &w.address())?;
        kron_log(
            "KRON NODE",
            format!("created hub identity {}", w.address().as_str()),
        );
        kron_log("KRON NODE", "Write these 24 words down:");
        kron_log("KRON NODE", &phrase);
        w
    };
    kron_log(
        "KRON NODE",
        format!(
            "hub-only (no miner) — other phones bootstrap this IP:{}",
            cli.port
        ),
    );
    run_combined_node(cli, wallet, None)
}

fn start_node_and_mine(cli: &Cli, reward: KronAddress) -> Result<(), String> {
    refuse_mine_on_pc()?;
    if !cli.phone && !cfg!(any(target_os = "android", target_os = "linux")) {
        return Err("kron-phone mining is intended for Termux / Linux ARM".into());
    }

    let wallet = if phone_wallet_exists(&cli.data_dir) {
        load_phone_wallet(&cli.data_dir)?
    } else {
        let (w, phrase, entropy) = generate_recovery_wallet();
        save_phone_wallet(&cli.data_dir, &entropy, &phrase, &w.address())?;
        kron_log(
            "KRON NODE",
            format!("created signing wallet {}", w.address().as_str()),
        );
        kron_log("KRON NODE", "Write these 24 words down:");
        kron_log("KRON NODE", &phrase);
        w
    };

    run_combined_node(cli, wallet, Some(reward))
}

fn bind_phone_p2p(cli: &Cli, hs: HandshakeConfig) -> Result<(P2pNode, u16), String> {
    let mut last_in_use: Option<(u16, std::io::Error)> = None;
    for port in port_auto_candidates(cli.port, cli.port_auto) {
        let bind = SocketAddr::from(([0, 0, 0, 0], port));
        match P2pNode::bind_on(hs.clone(), bind) {
            Ok(p2p) => {
                if port != cli.port {
                    kron_log(
                        "KRON NODE",
                        format!("P2P bound port {port} (--port-auto; {} was in use)", cli.port),
                    );
                }
                return Ok((p2p, port));
            }
            Err(NetworkError::Io(e)) if is_addr_in_use(&e) => {
                last_in_use = Some((port, e));
            }
            Err(e) => return Err(format!("P2P bind failed: {e}")),
        }
    }
    let (port, err) = match last_in_use {
        Some(pair) => pair,
        None => (cli.port, std::io::Error::from(std::io::ErrorKind::AddrInUse)),
    };
    log_port_in_use("KRON NODE", "P2P", port, "--port", Some(&err));
    Err("P2P port already in use".into())
}

fn run_combined_node(
    cli: &Cli,
    wallet: KronKeypair,
    reward: Option<KronAddress>,
) -> Result<(), String> {
    let store = DagStore::open(&cli.data_dir).map_err(|e| e.to_string())?;
    let (mut dag, _snap) = store.load().map_err(|e| e.to_string())?;
    if dag.ensure_genesis() {
        kron_log("KRON NODE", "created local genesis (empty DAG)");
    }
    let hub = HubState::new(dag);
    hub.set_store(store);
    {
        let dag = hub.lock_dag();
        hub.api().sync_from_dag(&dag);
    }
    hub.persist_snapshot();

    let hs = HandshakeConfig::honest(
        wallet.lattice().clone(),
        PeerRole::EdgeMiner,
        DeviceClass::LegacyMobile,
        false,
    );
    let (p2p, listen_port) = bind_phone_p2p(cli, hs)?;
    let lan = detect_lan_ipv4();
    let overlay = NodeOverlayId::from_pubkey(wallet.public_key());
    kron_log("KRON NODE", format_p2p_listen_line(listen_port));
    kron_log("KRON NODE", format!("Mesh ID: {}", overlay.to_ula()));
    kron_log("KRON NODE", wallet.address().as_str());
    kron_log("KRON NODE", format_lan_address_line(lan, listen_port));
    p2p.attach_graph(hub.clone());

    let stop = Arc::new(AtomicBool::new(false));
    let p2p = Arc::new(p2p);
    let hubs = resolve_phone_bootstrap(cli.bootstrap, cli.no_bootstrap, &cli.data_dir)?;
    let prefix = if reward.is_some() {
        "KRON MINER"
    } else {
        "KRON NODE"
    };
    let mut dial: Vec<SocketAddr> = Vec::new();
    for peer in hubs {
        if is_self_hub_target(peer, listen_port, None, lan) {
            kron_log(
                "KRON NODE",
                format!("skip self-dial {peer} (this process is already listening)"),
            );
        } else {
            dial.push(peer);
        }
    }
    if !dial.is_empty() {
        spawn_hub_dial(p2p.clone(), hub.clone(), dial, stop.clone(), prefix);
    }

    let explorer_port = cli.explorer_port.unwrap_or(8080);
    match start_explorer_http(hub.explorer_api(), explorer_port, stop.clone()) {
        Ok(_) => {}
        Err(e) if is_addr_in_use(&e) => {}
        Err(e) => kron_elog("KRON EXPLORER", format!("bind failed: {e}")),
    }
    let p2p_loop = p2p.clone();
    let hub_loop = hub.clone();
    let stop_loop = stop.clone();
    thread::spawn(move || {
        while !stop_loop.load(Ordering::SeqCst) {
            for (_from, msg) in p2p_loop.take_delivered_from() {
                let MeshMessage::Vertex(tx) = msg;
                if let Err(e) = hub_loop.ingest(tx) {
                    kron_elog("KRON NODE", format!("drop vertex: {e}"));
                }
            }
            thread::sleep(Duration::from_millis(40));
        }
    });

    if let Some(reward) = reward {
        kron_log("KRON MINER", format!("Miner address = {}", reward.as_str()));
        kron_log("KRON MINER", "Mining started");
        let miner_wallet = wallet.clone();
        let miner_hub = hub.clone();
        let miner_p2p = p2p.clone();
        let miner_stop = stop.clone();
        thread::Builder::new()
            .name("kron-miner".into())
            .spawn(move || {
                if let Err(e) = mine_loop(miner_wallet, reward, miner_hub, miner_p2p, miner_stop) {
                    kron_elog("KRON MINER", e);
                }
            })
            .map_err(|e| format!("miner thread: {e}"))?;
    } else {
        let hint = match lan {
            Some(ip) => format!("{ip}:{listen_port}"),
            None => format!("<this-phone-WiFi-IP>:{listen_port}"),
        };
        kron_log(
            "KRON NODE",
            format!("hub running — LAN discovery on :{}; or --bootstrap {hint}", listen_port.saturating_add(1)),
        );
    }

    if !cli.no_discovery {
        match spawn_lan_discovery(
            DiscoveryConfig {
                overlay,
                kron1: wallet.address().as_str().to_string(),
                p2p_port: listen_port,
                lan,
            },
            p2p.clone(),
            hub.clone(),
            stop.clone(),
        ) {
            Ok(()) => kron_log(
                "KRON NODE",
                format!(
                    "LAN discovery beacon :{}",
                    listen_port.saturating_add(1)
                ),
            ),
            Err(e) => kron_elog("KRON NODE", format!("LAN discovery disabled: {e}")),
        }
    }

    let mut last_hb = Instant::now();
    while !stop.load(Ordering::SeqCst) {
        if last_hb.elapsed() >= Duration::from_secs(5) {
            let dag = hub.lock_dag();
            let lan_s = match lan {
                Some(ip) => format!("{ip}:{listen_port}"),
                None => format!("0.0.0.0:{listen_port} (all interfaces)"),
            };
            kron_log(
                "KRON NODE",
                format!(
                    "up lan={lan_s} vertices={} tips={} supply={}",
                    dag.vertex_count(),
                    dag.tips().len(),
                    dag.current_supply
                ),
            );
            last_hb = Instant::now();
        }
        thread::sleep(Duration::from_millis(200));
    }
    p2p.shutdown();
    hub.persist_snapshot();
    Ok(())
}

fn run_credit(raw: &[String]) -> Result<(), String> {
    let mut to = None;
    let mut amount = None;
    let mut data_dir = PathBuf::from("kron-phone");
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
            "--data-dir" => {
                data_dir = PathBuf::from(take_cli_value(inline, raw, &mut i, "--data-dir")?);
            }
            other => return Err(unknown_argument(other, CREDIT_FLAGS)),
        }
        i += 1;
    }
    let to = to.ok_or("--to kron1... is required")?;
    let amount = amount.ok_or("--amount is required")?;
    let units = parse_kron_amount(&amount)?;
    let store = DagStore::open(&data_dir).map_err(|e| e.to_string())?;
    let (mut dag, mut snap) = store.load().map_err(|e| e.to_string())?;
    let addr = *to.as_bytes();
    dag.credit_account(addr, units);
    let entry = snap.faucet.entry(addr).or_insert(0);
    *entry = entry.saturating_add(units);
    store
        .write_snapshot(&DagSnapshot::from_dag_with_faucet(&dag, snap.faucet))
        .map_err(|e| e.to_string())?;
    println!(
        "[KRON PHONE] credited {} with {} (faucet; not minted supply)",
        to.as_str(),
        units
    );
    Ok(())
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

fn mine_loop(
    wallet: KronKeypair,
    reward: KronAddress,
    hub: Arc<HubState>,
    p2p: Arc<P2pNode>,
    stop: Arc<AtomicBool>,
) -> Result<(), String> {
    let dest = *reward.as_bytes();
    let mut attached = 0u64;
    let mut last_hb = Instant::now()
        .checked_sub(Duration::from_secs(3))
        .unwrap_or_else(Instant::now);
    while !stop.load(Ordering::SeqCst) {
        let tick = {
            let mut dag = hub.lock_dag();
            miner_tick(&wallet, &mut dag, dest, AttachingDevice::Miner)
        };
        if tick.genesis_created {
            kron_log("KRON MINER", "created local genesis (empty DAG)");
            {
                let dag = hub.lock_dag();
                hub.api().sync_from_dag(&dag);
            }
            hub.persist_snapshot();
        }
        if tick.faucet_credited > 0 {
            kron_log(
                "KRON MINER",
                format!(
                    "bootstrap dust {} so the first share can attach (not minted supply)",
                    tick.faucet_credited
                ),
            );
            hub.persist_snapshot();
        }
        if let Some(tx) = tick.tx {
            attached = attached.saturating_add(1);
            kron_log(
                "KRON MINER",
                format!(
                    "share #{} id={} tips={} vertices={} supply={}",
                    attached,
                    hex::encode(tx.id),
                    tick.tips,
                    tick.vertices,
                    tick.supply
                ),
            );
            hub.record_attached(&tx);
            let _ = p2p.broadcast(MeshMessage::Vertex(tx));
        } else if last_hb.elapsed() >= Duration::from_secs(2)
            || !matches!(tick.status, MinerTickStatus::Attached)
        {
            if last_hb.elapsed() >= Duration::from_secs(2)
                || matches!(
                    tick.status,
                    MinerTickStatus::ComposeFailed | MinerTickStatus::AttachFailed
                )
            {
                kron_log(
                    "KRON MINER",
                    format!(
                        "{} tips={} vertices={} supply={} balance={}{}",
                        tick.status.as_str(),
                        tick.tips,
                        tick.vertices,
                        tick.supply,
                        tick.balance,
                        tick.error
                            .as_deref()
                            .map(|e| format!(" err={e}"))
                            .unwrap_or_default()
                    ),
                );
                last_hb = Instant::now();
            }
        }
        thread::sleep(Duration::from_millis(400));
    }
    hub.persist_snapshot();
    kron_log("KRON MINER", format!("shutdown attached={attached}"));
    Ok(())
}
