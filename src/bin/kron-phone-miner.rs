//! Termux / Linux phone miner. Attaches and gossips DAG vertices.
//!
//! Attestation is **simulated** today. This binary is the only allowed host that
//! may set `DeviceClass::LegacyMobile` via the explicit `--phone` flag.
//! A Windows-built binary must not claim a phone class.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use new_blockchain::anti_bot::profile::DeviceClass;
use new_blockchain::crypto::lattice::LatticeKeyPair;
use new_blockchain::crypto::mobile_only::enforce_real_mobile;
use new_blockchain::dag::{AttachingDevice, KronDAG};
use new_blockchain::economics::FIXED_TRANSACTION_FEE;
use new_blockchain::kron::cli::{
    looks_like_kron1, parse_kron1_arg, sanitize_cli_value, split_eq_flag, take_cli_value,
    unknown_argument, PHONE_MINER_FLAGS,
};
use new_blockchain::kron::{KronAddress, KronKeypair};
use new_blockchain::p2p::handshake::HandshakeConfig;
use new_blockchain::p2p::peer::PeerRole;
use new_blockchain::p2p::P2pNode;
use new_blockchain::types::message::MeshMessage;

const USAGE: &str = "\
KRON phone miner (Termux / Linux) — attach DAG vertices, not ACS blocks

USAGE
  kron-phone-miner --phone --reward-address kron1... [--node IP:PORT]
  kron-phone-miner --phone --miner-address kron1...
  kron-phone-miner --phone --mine kron1...
  kron-phone-miner --phone kron1...

OPTIONS
  --phone                     Required. Interim flag: this process attests as LegacyMobile.
  --node IP:PORT              Gateway to attach to (default 127.0.0.1:8000)
  --bootstrap IP:PORT         Alias of --node
  --reward-address kron1...   Destination for self-attached mesh txs
  --miner-address kron1...    Alias of --reward-address
  --mine                      Optional; a following kron1... is the reward address
  --data-dir DIR              Local signing identity (default kron-phone-miner)
  --help                      Show this help

Phone and PC must be on the same LAN. The gateway listens on 0.0.0.0:8000.

  pkg install rust git
  cargo build --release --bin kron-phone-miner
  ./target/release/kron-phone-miner --phone --node <PC_LAN_IP>:8000 --reward-address kron1...
";

struct Cli {
    node: SocketAddr,
    reward: KronAddress,
    data_dir: PathBuf,
    phone: bool,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("[KRON ERROR] {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = parse_cli()?;

    if cfg!(any(target_arch = "x86_64", target_arch = "x86")) {
        eprintln!("[KRON MINER] rejected: phone-only mesh attach (x86 host)");
        eprintln!("[KRON MINER] The library compiles here; this binary must not mine.");
        std::process::exit(1);
    }

    if let Err(e) = enforce_real_mobile() {
        eprintln!("[KRON MINER] rejected: {e}");
        std::process::exit(1);
    }

    if cfg!(windows) {
        eprintln!("[KRON MINER] rejected: phone-only mesh attach");
        eprintln!(
            "[KRON MINER] This Windows binary cannot attest as a phone. Use Termux on Android:"
        );
        eprintln!("  pkg install rust git");
        eprintln!("  cargo build --release --bin kron-phone-miner");
        eprintln!(
            "  ./target/release/kron-phone-miner --phone --node <PC_LAN_IP>:8000 --reward-address kron1..."
        );
        std::process::exit(1);
    }

    if !cfg!(any(target_os = "android", target_os = "linux")) {
        return Err("kron-phone-miner is intended for Termux / Linux ARM".into());
    }

    if !args.phone {
        return Err(
            "pass --phone to attest as LegacyMobile (Termux interim class; future Android app should use Play Integrity / TEE)"
                .into(),
        );
    }

    let (wallet, created) = load_or_create_identity(&args.data_dir)?;
    let identity = wallet.lattice().clone();

    println!("Miner address = {}", args.reward.as_str());
    println!(
        "[KRON MINER] signing identity {} ({}) data-dir {}",
        wallet.address().as_str(),
        if created { "created" } else { "loaded" },
        args.data_dir.display()
    );
    println!("[KRON MINER] class=legacy-mobile — attaching DAG vertices (not ACS epochs)");
    println!(
        "[KRON MINER] attestation is simulated; a future Android app should use SafetyNet / Play Integrity / TEE"
    );

    let hs = HandshakeConfig::honest(
        identity,
        PeerRole::EdgeMiner,
        DeviceClass::LegacyMobile,
        true,
    );
    let p2p = P2pNode::bind(hs).map_err(|e| format!("miner P2P bind failed: {e}"))?;
    println!(
        "[KRON MINER] local overlay {} — attaching to gateway {}",
        p2p.addr, args.node
    );

    let stop = Arc::new(AtomicBool::new(false));
    install_ctrl_c(stop.clone());
    attach_to_node(&p2p, args.node, &stop)?;

    let p2p = Arc::new(p2p);
    let dag = Arc::new(Mutex::new(KronDAG::with_genesis()));
    mesh_loop(wallet, args.reward, dag, p2p, stop)
}

fn mesh_loop(
    wallet: KronKeypair,
    reward: KronAddress,
    dag: Arc<Mutex<KronDAG>>,
    p2p: Arc<P2pNode>,
    stop: Arc<AtomicBool>,
) -> Result<(), String> {
    let mut attached = 0u64;
    while !stop.load(Ordering::SeqCst) {
        for (_from, msg) in p2p.take_delivered_from() {
            let MeshMessage::Vertex(tx) = msg;
            let mut dag = dag.lock().map_err(|e| e.to_string())?;
            if dag.contains(&tx.id) {
                continue;
            }
            match dag.attach_and_verify_for(tx.clone(), AttachingDevice::Miner) {
                Ok(()) => {
                    attached = attached.saturating_add(1);
                    println!(
                        "[KRON MINER] validated vertex {} tips={} txs={}",
                        hex::encode(tx.id),
                        dag.tips().len(),
                        dag.dag_tx_count
                    );
                    let _ = p2p.broadcast(MeshMessage::Vertex(tx));
                }
                Err(e) => eprintln!("[KRON MINER] reject vertex: {e}"),
            }
        }

        if let Ok(mut dag) = dag.lock() {
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
    println!("[KRON MINER] shutdown attached={attached}");
    Ok(())
}

fn parse_cli() -> Result<Cli, String> {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    if raw.iter().any(|a| a == "--help" || a == "-h") {
        print!("{USAGE}");
        std::process::exit(0);
    }
    let mut node = None;
    let mut reward = None;
    let mut data_dir = None;
    let mut phone = false;
    let mut i = 0;
    while i < raw.len() {
        let token = sanitize_cli_value(&raw[i]);
        let (flag, inline) = split_eq_flag(&token);
        if !flag.starts_with('-') && looks_like_kron1(flag) {
            reward = Some(parse_kron1_arg(flag)?);
            i += 1;
            continue;
        }
        match flag {
            "--phone" => phone = true,
            "--mine" => {
                if let Some(v) = inline {
                    if !sanitize_cli_value(v).is_empty() {
                        reward = Some(parse_kron1_arg(v)?);
                    }
                }
            }
            "--node" | "--bootstrap" => {
                let v = take_cli_value(inline, &raw, &mut i, "--node")?;
                node = Some(
                    v.parse::<SocketAddr>()
                        .map_err(|_| format!("invalid --node '{v}'"))?,
                );
            }
            "--reward-address" | "--miner-address" => {
                let v = take_cli_value(inline, &raw, &mut i, "--reward-address")
                    .map_err(|_| String::from("--reward-address requires kron1..."))?;
                if v.starts_with('-') && !looks_like_kron1(&v) {
                    return Err(String::from("--reward-address requires kron1..."));
                }
                reward = Some(parse_kron1_arg(&v)?);
            }
            "--data-dir" => {
                data_dir = Some(PathBuf::from(take_cli_value(
                    inline,
                    &raw,
                    &mut i,
                    "--data-dir",
                )?));
            }
            other => return Err(unknown_argument(other, PHONE_MINER_FLAGS)),
        }
        i += 1;
    }
    Ok(Cli {
        node: node.unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 8000))),
        reward: reward.ok_or_else(|| String::from("--reward-address kron1... is required"))?,
        data_dir: data_dir.unwrap_or_else(|| PathBuf::from("kron-phone-miner")),
        phone,
    })
}

fn attach_to_node(p2p: &P2pNode, dest: SocketAddr, stop: &Arc<AtomicBool>) -> Result<(), String> {
    let mut last_err = String::new();
    for attempt in 1..=90 {
        if stop.load(Ordering::SeqCst) {
            return Err("stopped before attaching to gateway".into());
        }
        match p2p.connect(dest) {
            Ok(info) => {
                println!(
                    "[KRON MINER] attached to {dest} role={:?} authenticity={}",
                    info.peer.role, info.score.authenticity
                );
                return Ok(());
            }
            Err(e) => {
                last_err = e.to_string();
                println!(
                    "[KRON MINER] waiting for gateway at {dest} (try {attempt}/90): {last_err}"
                );
                thread::sleep(Duration::from_secs(1));
            }
        }
    }
    Err(format!(
        "could not attach to gateway at {dest}: {last_err}. Start kron-node first (listens 0.0.0.0:8000)."
    ))
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
        "# KRON phone-miner ML-DSA-44 seed (keep private)\n{}\n",
        hex::encode(seed)
    );
    std::fs::write(&seed_path, body).map_err(|e| format!("write {}: {e}", seed_path.display()))?;
    let _ = std::fs::write(dir.join("address.txt"), format!("{}\n", wallet.address()));
    Ok((wallet, true))
}

fn install_ctrl_c(stop: Arc<AtomicBool>) {
    let _ = stop;
}
