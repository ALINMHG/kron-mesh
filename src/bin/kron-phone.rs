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
use std::time::Duration;

use new_blockchain::anti_bot::profile::DeviceClass;
use new_blockchain::crypto::mobile_only::enforce_real_mobile;
use new_blockchain::dag::AttachingDevice;
use new_blockchain::economics::{FIXED_TRANSACTION_FEE, UNITS_PER_COIN};
use new_blockchain::persist::{DagSnapshot, DagStore};
use new_blockchain::explorer::start_explorer_http;
use new_blockchain::kron::{
    generate_recovery_wallet, load_mnemonic, load_phone_wallet, phone_wallet_exists,
    save_phone_wallet, KronAddress, KronKeypair,
};
use new_blockchain::p2p::handshake::HandshakeConfig;
use new_blockchain::p2p::mesh::{mesh_sync_connect, HubState, MeshGraph, MeshRole};
use new_blockchain::p2p::peer::PeerRole;
use new_blockchain::p2p::P2pNode;
use new_blockchain::types::message::MeshMessage;

const USAGE: &str = "\
KRON Mesh Termux client — phones ARE the network (node + miner, no PC required)

USAGE
  kron-phone
  kron-phone --generate-wallet [--data-dir DIR]
  kron-phone --mine --reward-address kron1... [--port PORT] [--explorer-port PORT]
  kron-phone --hub [--port PORT] [--bootstrap <PHONE_IP>:8000]
  kron-phone credit --to kron1... --amount AMOUNT [--data-dir DIR]
  kron-phone --show-mnemonic [--data-dir DIR]
  kron-phone --help

Two phones on LAN (no Windows process):
  ./kron-phone --mine --reward-address kron1... --port 8000
  ./kron-phone --mine --reward-address kron1... --port 8000 --bootstrap <PHONE1_IP>:8000

Optional phone explorer: add --explorer-port 8080
PC viewer (optional): kron-node --follow <PHONE_IP>:8000 --explorer-port 8080 --read-only

Interactive menu (no flags):
  1) Generate KRON address + 24-word passphrase (write it down; not reprinted later)
  2) Mine to a kron1 address; this phone's node stays running (the network)

On x86/Windows, option 2 / --mine / --hub are refused.
";

struct Cli {
    generate: bool,
    mine: bool,
    hub_only: bool,
    show_mnemonic: bool,
    reward: Option<KronAddress>,
    port: u16,
    explorer_port: Option<u16>,
    data_dir: PathBuf,
    bootstrap: Option<SocketAddr>,
    phone: bool,
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
    if raw.first().map(|s| s.as_str()) == Some("credit") {
        return run_credit(&raw[1..]);
    }
    let cli = parse_cli(&raw)?;
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
        let reward = cli
            .reward
            .clone()
            .ok_or_else(|| String::from("--mine requires --reward-address kron1..."))?;
        return start_node_and_mine(&cli, reward);
    }
    interactive_menu(&cli)
}

fn parse_cli(raw: &[String]) -> Result<Cli, String> {
    let mut generate = false;
    let mut mine = false;
    let mut hub_only = false;
    let mut show_mnemonic = false;
    let mut reward = None;
    let mut port = 8000u16;
    let mut explorer_port = None;
    let mut data_dir = None;
    let mut bootstrap = None;
    let mut phone = false;
    let mut i = 0;
    while i < raw.len() {
        match raw[i].as_str() {
            "--generate-wallet" => generate = true,
            "--mine" => mine = true,
            "--hub" | "--node-only" => hub_only = true,
            "--show-mnemonic" => show_mnemonic = true,
            "--phone" => phone = true,
            "--reward-address" | "--miner-address" => {
                i += 1;
                let v = raw
                    .get(i)
                    .ok_or_else(|| String::from("--reward-address requires kron1..."))?;
                reward = Some(KronAddress::parse(v).map_err(|e| e.to_string())?);
            }
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
                explorer_port = Some(
                    raw.get(i)
                        .ok_or("--explorer-port requires a value")?
                        .parse()
                        .map_err(|_| "invalid --explorer-port")?,
                );
            }
            "--data-dir" => {
                i += 1;
                data_dir = Some(PathBuf::from(
                    raw.get(i).ok_or("--data-dir requires a path")?,
                ));
            }
            "--bootstrap" | "--node" => {
                i += 1;
                let v = raw.get(i).ok_or("--bootstrap requires IP:PORT")?;
                bootstrap = Some(v.parse().map_err(|_| format!("invalid --bootstrap '{v}'"))?);
            }
            "--no-mine" => {}
            other => return Err(format!("unknown argument: {other}")),
        }
        i += 1;
    }
    Ok(Cli {
        generate,
        mine,
        hub_only,
        show_mnemonic,
        reward,
        port,
        explorer_port,
        data_dir: data_dir.unwrap_or_else(|| PathBuf::from("kron-phone")),
        bootstrap,
        phone,
    })
}

fn interactive_menu(cli: &Cli) -> Result<(), String> {
    loop {
        println!();
        println!("KRON Mesh (Termux) — phones are the network; PC explorer is optional");
        println!("1) Generate KRON address (show kron1... and save BIP39 passphrase — write it down)");
        println!("2) Mine — enter a kron1 reward address; this phone's node stays running");
        println!("q) Quit");
        print!("> ");
        let _ = io::stdout().flush();
        let mut line = String::new();
        io::stdin()
            .read_line(&mut line)
            .map_err(|e| format!("stdin: {e}"))?;
        match line.trim() {
            "1" => generate_wallet(&cli.data_dir)?,
            "2" => {
                print!("Enter KRON wallet address (kron1...): ");
                let _ = io::stdout().flush();
                let mut addr = String::new();
                io::stdin()
                    .read_line(&mut addr)
                    .map_err(|e| format!("stdin: {e}"))?;
                let addr = addr.trim();
                if addr.is_empty() {
                    eprintln!("[KRON PHONE] empty address");
                    continue;
                }
                let reward = KronAddress::parse(addr).map_err(|e| e.to_string())?;
                start_node_and_mine(cli, reward)?;
                return Ok(());
            }
            "q" | "Q" => return Ok(()),
            _ => println!("Choose 1, 2, or q."),
        }
    }
}

fn generate_wallet(dir: &Path) -> Result<(), String> {
    if phone_wallet_exists(dir) {
        let wallet = load_phone_wallet(dir)?;
        println!("[KRON PHONE] wallet already saved in {}", dir.display());
        println!("Address = {}", wallet.address().as_str());
        println!("Recovery phrase is not printed again. Use --show-mnemonic if you need it.");
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
    Ok(())
}

fn reveal_mnemonic(dir: &Path) -> Result<(), String> {
    let phrase = load_mnemonic(dir)?;
    let wallet = load_phone_wallet(dir)?;
    println!("Address = {}", wallet.address().as_str());
    println!("{phrase}");
    Ok(())
}

fn refuse_mine_on_pc() -> Result<(), String> {
    if cfg!(any(target_arch = "x86_64", target_arch = "x86")) {
        eprintln!("[KRON MINER] rejected: phone-only mesh attach (x86 host)");
        eprintln!("[KRON MINER] The library compiles here; this binary must not mine.");
        eprintln!("[KRON MINER] Use Termux on Android (aarch64):");
        eprintln!("  pkg install rust git");
        eprintln!("  cargo build --release --bin kron-phone");
        eprintln!("  ./target/release/kron-phone");
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
        println!("[KRON PHONE] created hub identity {}", w.address().as_str());
        println!("Write these 24 words down:");
        println!("{phrase}");
        w
    };
    println!("[KRON PHONE] hub-only (no miner) — other phones bootstrap this IP:{}", cli.port);
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
        println!("[KRON PHONE] created signing wallet {}", w.address().as_str());
        println!("Write these 24 words down:");
        println!("{phrase}");
        w
    };

    println!("Miner address = {}", reward.as_str());
    run_combined_node(cli, wallet, Some(reward))
}

fn run_combined_node(
    cli: &Cli,
    wallet: KronKeypair,
    reward: Option<KronAddress>,
) -> Result<(), String> {
    let store = DagStore::open(&cli.data_dir).map_err(|e| e.to_string())?;
    let (dag, _snap) = store.load().map_err(|e| e.to_string())?;
    let hub = HubState::new(dag);
    hub.set_store(store);
    {
        let dag = hub.lock_dag();
        hub.api().sync_from_dag(&dag);
    }

    let hs = HandshakeConfig::honest(
        wallet.lattice().clone(),
        PeerRole::EdgeMiner,
        DeviceClass::LegacyMobile,
        false,
    );
    let bind = SocketAddr::from(([0, 0, 0, 0], cli.port));
    let p2p = P2pNode::bind_on(hs, bind).map_err(|e| format!("P2P bind failed: {e}"))?;
    println!(
        "[KRON PHONE] Node listening {} (0.0.0.0:{}) kron-mesh/1",
        p2p.addr, cli.port
    );
    p2p.attach_graph(hub.clone());

    if let Some(peer) = cli.bootstrap {
        match p2p.connect(peer) {
            Ok(info) => println!(
                "[KRON PHONE] connected to {peer} authenticity={}",
                info.score.authenticity
            ),
            Err(e) => eprintln!("[KRON PHONE] bootstrap {peer} failed: {e}"),
        }
        match mesh_sync_connect(peer, hub.clone(), MeshRole::Hub) {
            Ok(()) => println!(
                "[KRON PHONE] mesh sync vertices={}",
                hub.lock_dag().vertex_count()
            ),
            Err(e) => eprintln!("[KRON PHONE] mesh sync {peer} failed: {e}"),
        }
    }

    let stop = Arc::new(AtomicBool::new(false));
    if let Some(port) = cli.explorer_port {
        match start_explorer_http(hub.explorer_api(), port, stop.clone()) {
            Ok(addr) => println!("[KRON PHONE] explorer http://{addr}"),
            Err(e) => eprintln!("[KRON PHONE] explorer bind failed: {e}"),
        }
    }

    let p2p = Arc::new(p2p);
    let p2p_loop = p2p.clone();
    let hub_loop = hub.clone();
    let stop_loop = stop.clone();
    thread::spawn(move || {
        while !stop_loop.load(Ordering::SeqCst) {
            for (_from, msg) in p2p_loop.take_delivered_from() {
                let MeshMessage::Vertex(tx) = msg;
                if let Err(e) = hub_loop.ingest(tx) {
                    eprintln!("[KRON PHONE] drop vertex: {e}");
                }
            }
            thread::sleep(Duration::from_millis(40));
        }
    });

    if let Some(reward) = reward {
        println!(
            "[KRON PHONE] mining to {} — node stays up in this process",
            reward.as_str()
        );
        mine_loop(wallet, reward, hub, p2p, stop)
    } else {
        println!("[KRON PHONE] hub running — second phone: --bootstrap <THIS_IP>:{}", cli.port);
        while !stop.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(200));
        }
        p2p.shutdown();
        hub.persist_snapshot();
        Ok(())
    }
}

fn run_credit(raw: &[String]) -> Result<(), String> {
    let mut to = None;
    let mut amount = None;
    let mut data_dir = PathBuf::from("kron-phone");
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
            "--data-dir" => {
                i += 1;
                data_dir = PathBuf::from(raw.get(i).ok_or("--data-dir requires a path")?);
            }
            other => return Err(format!("unknown argument: {other}")),
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
    let mut attached = 0u64;
    while !stop.load(Ordering::SeqCst) {
        {
            let mut dag = hub.lock_dag();
            let sender = *wallet.address().as_bytes();
            let dest = *reward.as_bytes();
            let bal = dag.balance(&sender);
            if bal >= FIXED_TRANSACTION_FEE.saturating_add(1) {
                match dag.compose_and_sign(&wallet, dest, 1) {
                    Ok(tx) => match dag.attach_and_verify_for(tx.clone(), AttachingDevice::Miner) {
                        Ok(()) => {
                            attached = attached.saturating_add(1);
                            println!(
                                "[KRON MINER] attached local vertex #{} id={} supply={}",
                                attached,
                                hex::encode(tx.id),
                                dag.current_supply
                            );
                            drop(dag);
                            hub.record_attached(&tx);
                            let _ = p2p.broadcast(MeshMessage::Vertex(tx));
                        }
                        Err(e) => eprintln!("[KRON MINER] local attach failed: {e}"),
                    },
                    Err(e) => eprintln!("[KRON MINER] compose failed: {e}"),
                }
            }
        }
        thread::sleep(Duration::from_millis(400));
    }
    p2p.shutdown();
    hub.persist_snapshot();
    println!("[KRON MINER] shutdown attached={attached}");
    Ok(())
}
