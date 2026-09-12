//! LAN UDP beacons so phones on the same Wi‑Fi find each other without typing
//! a `192.168` address. Internet-wide reach still needs `--bootstrap` / a VPS.

use std::collections::HashSet;
use std::io::{self, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::listen::is_usable_lan_ipv4;
use crate::p2p::error::NetworkError;
use crate::p2p::mesh::{mesh_sync_connect, MeshGraph, MeshRole};
use crate::p2p::node::P2pNode;
use crate::p2p::overlay::NodeOverlayId;
use crate::{kron_elog, kron_log};

/// Retry outbound hub dial when the VPS is down or refusing.
const HUB_RETRY: Duration = Duration::from_secs(8);

/// Beacon magic (`KRON` discovery v1).
pub const DISCOVERY_MAGIC: &[u8; 4] = b"KRD1";
pub const DISCOVERY_VERSION: u8 = 1;
const MAX_KRON1_PREFIX: usize = 80;
const ANNOUNCE_EVERY: Duration = Duration::from_secs(3);

/// UDP listen port = P2P port + 1 (8000 → 8001).
pub fn beacon_port(p2p_port: u16) -> u16 {
    p2p_port.saturating_add(1)
}

/// One LAN announcement: overlay id, TCP P2P port, `kron1` prefix for logs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LanBeacon {
    pub overlay_id: NodeOverlayId,
    pub p2p_port: u16,
    pub kron1_prefix: String,
}

/// Peer learned from a UDP beacon. TCP target uses the datagram source IP.
#[derive(Clone, Debug)]
pub struct DiscoveredPeer {
    pub overlay_id: NodeOverlayId,
    pub p2p_addr: SocketAddr,
    pub kron1_prefix: String,
}

pub fn encode_beacon(b: &LanBeacon) -> Vec<u8> {
    let prefix = truncate_prefix(&b.kron1_prefix);
    let mut out = Vec::with_capacity(4 + 1 + 16 + 2 + 1 + prefix.len());
    out.extend_from_slice(DISCOVERY_MAGIC);
    out.push(DISCOVERY_VERSION);
    out.extend_from_slice(b.overlay_id.as_bytes());
    out.extend_from_slice(&b.p2p_port.to_le_bytes());
    out.push(prefix.len() as u8);
    out.extend_from_slice(prefix.as_bytes());
    out
}

pub fn decode_beacon(bytes: &[u8]) -> Option<LanBeacon> {
    if bytes.len() < 4 + 1 + 16 + 2 + 1 {
        return None;
    }
    if bytes[0..4] != DISCOVERY_MAGIC[..] || bytes[4] != DISCOVERY_VERSION {
        return None;
    }
    let mut overlay = [0u8; 16];
    overlay.copy_from_slice(&bytes[5..21]);
    let p2p_port = u16::from_le_bytes(bytes[21..23].try_into().ok()?);
    let n = bytes[23] as usize;
    if bytes.len() != 24 + n || n > MAX_KRON1_PREFIX {
        return None;
    }
    let kron1_prefix = String::from_utf8_lossy(&bytes[24..24 + n]).into_owned();
    Some(LanBeacon {
        overlay_id: NodeOverlayId::from_bytes(overlay),
        p2p_port,
        kron1_prefix,
    })
}

fn truncate_prefix(s: &str) -> String {
    let mut out = String::new();
    for ch in s.chars() {
        if out.len() + ch.len_utf8() > MAX_KRON1_PREFIX {
            break;
        }
        out.push(ch);
    }
    out
}

/// UDP socket used for beacons (broadcast + optional unicast in tests).
pub struct LanBeaconSocket {
    sock: UdpSocket,
}

impl LanBeaconSocket {
    pub fn bind(addr: SocketAddr) -> io::Result<Self> {
        let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_reuse_address(true)?;
        socket.set_broadcast(true)?;
        socket.bind(&SockAddr::from(addr))?;
        socket.set_nonblocking(true)?;
        Ok(Self { sock: socket.into() })
    }

    pub fn send_to(&self, beacon: &LanBeacon, dest: SocketAddr) -> io::Result<()> {
        let bytes = encode_beacon(beacon);
        self.sock.send_to(&bytes, dest)?;
        Ok(())
    }

    pub fn recv(&self) -> io::Result<Option<(LanBeacon, SocketAddr)>> {
        let mut buf = [0u8; 256];
        match self.sock.recv_from(&mut buf) {
            Ok((n, from)) => Ok(decode_beacon(&buf[..n]).map(|b| (b, from))),
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }
}

/// Typical home-LAN broadcast targets for `p2p_port + 1`.
pub fn broadcast_targets(beacon: u16, lan: Option<Ipv4Addr>) -> Vec<SocketAddr> {
    let mut out = vec![SocketAddr::from((Ipv4Addr::BROADCAST, beacon))];
    if let Some(ip) = lan {
        let o = ip.octets();
        let subnet = Ipv4Addr::new(o[0], o[1], o[2], 255);
        let dest = SocketAddr::from((subnet, beacon));
        if !out.contains(&dest) {
            out.push(dest);
        }
    }
    out
}

pub struct DiscoveryConfig {
    pub overlay: NodeOverlayId,
    pub kron1: String,
    pub p2p_port: u16,
    pub lan: Option<Ipv4Addr>,
}

/// Announce on the LAN and auto-connect TCP P2P + mesh sync to new overlays.
pub fn spawn_lan_discovery(
    cfg: DiscoveryConfig,
    p2p: Arc<P2pNode>,
    graph: Arc<dyn MeshGraph>,
    stop: Arc<AtomicBool>,
) -> io::Result<()> {
    let port = beacon_port(cfg.p2p_port);
    let sock = LanBeaconSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))?;
    let beacon = LanBeacon {
        overlay_id: cfg.overlay,
        p2p_port: cfg.p2p_port,
        kron1_prefix: cfg.kron1,
    };
    let dests = broadcast_targets(port, cfg.lan);
    let seen = Arc::new(Mutex::new(HashSet::new()));
    seen.lock().unwrap().insert(cfg.overlay);
    thread::Builder::new()
        .name("kron-lan-disco".into())
        .spawn(move || {
            discovery_loop(sock, beacon, dests, p2p, graph, stop, seen)
        })
        .map_err(|e| io::Error::new(ErrorKind::Other, e))?;
    Ok(())
}

fn discovery_loop(
    sock: LanBeaconSocket,
    beacon: LanBeacon,
    dests: Vec<SocketAddr>,
    p2p: Arc<P2pNode>,
    graph: Arc<dyn MeshGraph>,
    stop: Arc<AtomicBool>,
    seen: Arc<Mutex<HashSet<NodeOverlayId>>>,
) {
    let mut last_announce = Instant::now()
        .checked_sub(ANNOUNCE_EVERY)
        .unwrap_or_else(Instant::now);
    while !stop.load(Ordering::SeqCst) {
        if last_announce.elapsed() >= ANNOUNCE_EVERY {
            for dest in &dests {
                let _ = sock.send_to(&beacon, *dest);
            }
            last_announce = Instant::now();
        }
        match sock.recv() {
            Ok(Some((remote, from))) => {
                if let Some(peer) = discovered_from(remote, from, beacon.overlay_id) {
                    let mut set = seen.lock().unwrap_or_else(|p| p.into_inner());
                    if !set.insert(peer.overlay_id) {
                        continue;
                    }
                    if p2p.has_overlay(&peer.overlay_id) {
                        continue;
                    }
                    kron_log(
                        "KRON NODE",
                        format!(
                            "peer discovered {} at {}",
                            peer.kron1_prefix, peer.p2p_addr
                        ),
                    );
                    spawn_peer_link(
                        p2p.clone(),
                        graph.clone(),
                        peer.p2p_addr,
                        stop.clone(),
                        "discovery",
                    );
                }
            }
            Ok(None) => thread::sleep(Duration::from_millis(50)),
            Err(_) => thread::sleep(Duration::from_millis(80)),
        }
    }
}

fn discovered_from(
    beacon: LanBeacon,
    from: SocketAddr,
    local: NodeOverlayId,
) -> Option<DiscoveredPeer> {
    if beacon.overlay_id == local {
        return None;
    }
    let ip = match from.ip() {
        IpAddr::V4(ip) if is_usable_lan_ipv4(ip) || ip.is_loopback() => IpAddr::V4(ip),
        _ => return None,
    };
    Some(DiscoveredPeer {
        overlay_id: beacon.overlay_id,
        p2p_addr: SocketAddr::new(ip, beacon.p2p_port),
        kron1_prefix: beacon.kron1_prefix,
    })
}

/// Flushed miner/hub line for a refused or timed-out VPS dial.
pub fn format_hub_connect_error(addr: SocketAddr, err: &NetworkError) -> String {
    match err {
        NetworkError::Io(e) if e.kind() == ErrorKind::TimedOut => {
            format!("hub {addr} timed out (VPS down or not accepting)")
        }
        NetworkError::Io(e) if e.kind() == ErrorKind::ConnectionRefused => {
            format!("hub {addr} connection refused (VPS down or viewer not accepting)")
        }
        NetworkError::Io(e) => format!("hub {addr} failed: {e}"),
        other => format!("hub {addr} failed: {other}"),
    }
}

/// Dial the public hub after local listen. Logs
/// `[KRON MINER] connecting to hub 144.91.105.244:8000 ...` then
/// `connected to hub`, and retries every 8s if the VPS is down.
pub fn spawn_hub_dial(
    p2p: Arc<P2pNode>,
    graph: Arc<dyn MeshGraph>,
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    log_prefix: &'static str,
) {
    let _ = thread::Builder::new()
        .name("kron-hub-dial".into())
        .spawn(move || {
            let mut announced = false;
            while !stop.load(Ordering::SeqCst) {
                if !announced {
                    kron_log(log_prefix, format!("connecting to hub {addr} ..."));
                }
                match mesh_sync_connect(addr, graph.clone(), MeshRole::Hub) {
                    Ok(()) => {
                        if !announced {
                            kron_log(log_prefix, "connected to hub");
                            announced = true;
                            let _ = p2p.connect(addr);
                        }
                    }
                    Err(e) => {
                        announced = false;
                        kron_elog(log_prefix, format_hub_connect_error(addr, &e));
                    }
                }
                let deadline = Instant::now() + HUB_RETRY;
                while Instant::now() < deadline && !stop.load(Ordering::SeqCst) {
                    thread::sleep(Duration::from_millis(200));
                }
            }
        });
}

/// Noise connect + periodic `kron-mesh/1` sync (bootstrap and LAN discovery).
pub fn spawn_peer_link(
    p2p: Arc<P2pNode>,
    graph: Arc<dyn MeshGraph>,
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    how: &'static str,
) {
    let _ = thread::Builder::new()
        .name("kron-peer-link".into())
        .spawn(move || {
            match p2p.connect(addr) {
                Ok(info) => kron_log(
                    "KRON NODE",
                    format!(
                        "connected to {addr} via {how} authenticity={}",
                        info.score.authenticity
                    ),
                ),
                Err(e) => kron_elog("KRON NODE", format!("{how} {addr} failed: {e}")),
            }
            let mut last_n = 0usize;
            while !stop.load(Ordering::SeqCst) {
                match mesh_sync_connect(addr, graph.clone(), MeshRole::Hub) {
                    Ok(()) => {
                        let n = graph.vertex_set().len();
                        if n != last_n {
                            kron_log("KRON NODE", format!("mesh sync vertices={n}"));
                            last_n = n;
                        }
                    }
                    Err(e) => kron_elog("KRON NODE", format!("mesh sync {addr} failed: {e}")),
                }
                thread::sleep(Duration::from_millis(500));
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::lattice::LatticeKeyPair;
    use rand::SeedableRng;

    fn overlay(seed: u64) -> NodeOverlayId {
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        NodeOverlayId::from_pubkey(&LatticeKeyPair::generate(&mut rng).public)
    }

    #[test]
    fn beacon_roundtrip() {
        let id = overlay(7);
        let b = LanBeacon {
            overlay_id: id,
            p2p_port: 8000,
            kron1_prefix: "kron1qqqqqqqqqq".into(),
        };
        let back = decode_beacon(&encode_beacon(&b)).unwrap();
        assert_eq!(back, b);
    }

    #[test]
    fn loopback_unicast_beacon_is_not_self() {
        let a = overlay(11);
        let b = overlay(12);
        assert_ne!(a, b);
        let sock_a = LanBeaconSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let sock_b = LanBeaconSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let dest = sock_b.sock.local_addr().unwrap();
        let beacon = LanBeacon {
            overlay_id: a,
            p2p_port: 8000,
            kron1_prefix: "kron1alice".into(),
        };
        sock_a.send_to(&beacon, dest).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut got = None;
        while Instant::now() < deadline {
            if let Ok(Some(pair)) = sock_b.recv() {
                got = Some(pair);
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        let (remote, from) = got.expect("unicast beacon on loopback");
        assert_eq!(remote.overlay_id, a);
        let peer = discovered_from(remote, from, b).expect("B accepts A");
        assert_eq!(peer.overlay_id, a);
        assert_eq!(peer.p2p_addr.port(), 8000);
        assert!(discovered_from(
            LanBeacon {
                overlay_id: b,
                p2p_port: 8000,
                kron1_prefix: "self".into(),
            },
            from,
            b
        )
        .is_none());
    }

    #[test]
    fn beacon_port_is_p2p_plus_one() {
        assert_eq!(beacon_port(8000), 8001);
    }
}
