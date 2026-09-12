//! Bound P2P node: TCP handshake, Have/Need gossip, Kademlia contacts.

use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::listen::bind_tcp_reuse;
use crate::p2p::error::NetworkError;
use crate::p2p::frame::{KIND_INV, KIND_PAYLOAD, KIND_PING, KIND_PONG, KIND_WANT};
use crate::p2p::gossip::{GossipEngine, GossipInventory, GossipPayload, GossipWant};
use crate::p2p::handshake::{perform_secure_handshake, HandshakeConfig};
use crate::p2p::mesh::{serve_mesh_session, MeshGraph, MESH_MAGIC};
use crate::p2p::noise::NoiseSession;
use crate::p2p::overlay::NodeOverlayId;
use crate::p2p::peer::{PeerInfo, PeerRole};
use crate::p2p::routing::RoutingTable;
use crate::types::message::MeshMessage;
use crate::types::{Address, Hash};

enum SessionCmd {
    Inv(GossipInventory),
    #[allow(dead_code)]
    Want(GossipWant),
    #[allow(dead_code)]
    Payload(GossipPayload),
    #[allow(dead_code)]
    Ping,
}

pub struct P2pNode {
    pub local_id: Address,
    pub overlay_id: NodeOverlayId,
    pub addr: std::net::SocketAddr,
    pub role: PeerRole,
    hs: HandshakeConfig,
    stop: Arc<AtomicBool>,
    table: Arc<Mutex<RoutingTable>>,
    gossip: Arc<Mutex<GossipEngine>>,
    sessions: Arc<Mutex<HashMap<Address, Sender<SessionCmd>>>>,
    delivered: Arc<Mutex<Vec<(Address, MeshMessage)>>>,
    graph: Arc<Mutex<Option<Arc<dyn MeshGraph>>>>,
}

impl P2pNode {
    /// Bind an ephemeral localhost port (tests and short-lived clients).
    pub fn bind(hs: HandshakeConfig) -> Result<Self, NetworkError> {
        Self::bind_on(hs, std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
    }

    /// Bind a specific listen address (CLI `--port`).
    pub fn bind_on(hs: HandshakeConfig, bind_addr: std::net::SocketAddr) -> Result<Self, NetworkError> {
        let listener = bind_tcp_reuse(bind_addr)?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let local_id = hs.peer_id();
        let overlay_id = hs.overlay_id();
        let role = hs.role;
        let table = Arc::new(Mutex::new(RoutingTable::new(local_id, role)));
        let gossip = Arc::new(Mutex::new(GossipEngine::for_role(role)));
        let sessions = Arc::new(Mutex::new(HashMap::new()));
        let delivered = Arc::new(Mutex::new(Vec::new()));
        let graph = Arc::new(Mutex::new(None));
        let stop = Arc::new(AtomicBool::new(false));

        let node = Self {
            local_id,
            overlay_id,
            addr,
            role,
            hs: hs.clone(),
            stop: stop.clone(),
            table: table.clone(),
            gossip: gossip.clone(),
            sessions: sessions.clone(),
            delivered: delivered.clone(),
            graph: graph.clone(),
        };

        thread::Builder::new()
            .name("p2p-accept".into())
            .spawn(move || {
                accept_loop(listener, hs, stop, table, gossip, sessions, delivered, graph)
            })
            .map_err(|e| NetworkError::Io(e))?;
        Ok(node)
    }

    /// Attach the hub DAG so `kron-mesh/1` sessions can ingest as LocalGraph.
    pub fn attach_graph(&self, graph: Arc<dyn MeshGraph>) {
        *self.graph.lock().unwrap() = Some(graph);
    }

    pub fn connect(&self, addr: std::net::SocketAddr) -> Result<PeerInfo, NetworkError> {
        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))?;
        let mut session = match NoiseSession::handshake(stream, true) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        let mut hs = self.hs.clone();
        hs.initiator = true;
        let info = match perform_secure_handshake(&mut session, &hs) {
            Ok(i) => i,
            Err(e) => {
                session.shutdown();
                return Err(e);
            }
        };
        self.table.lock().unwrap().insert(info.peer.clone())?;
        spawn_session(
            session,
            info.peer.id,
            self.stop.clone(),
            self.gossip.clone(),
            self.sessions.clone(),
            self.delivered.clone(),
        );
        Ok(info)
    }

    /// Announce via Have/Need: neighbours first see a 32-byte id.
    pub fn broadcast(&self, msg: MeshMessage) -> Hash {
        let inv = self.gossip.lock().unwrap().announce(&msg);
        let id = inv.ids[0];
        let targets = self.table.lock().unwrap().gossip_targets(self.role);
        let sessions = self.sessions.lock().unwrap();
        for peer in targets {
            if let Some(tx) = sessions.get(&peer.id) {
                let _ = tx.send(SessionCmd::Inv(inv.clone()));
            }
        }
        id
    }

    pub fn has(&self, id: &Hash) -> bool {
        self.gossip.lock().unwrap().contains(id)
    }

    pub fn take_delivered(&self) -> Vec<MeshMessage> {
        self.take_delivered_from()
            .into_iter()
            .map(|(_, msg)| msg)
            .collect()
    }

    /// Same as [`take_delivered`], but keeps the authenticated peer address.
    pub fn take_delivered_from(&self) -> Vec<(Address, MeshMessage)> {
        match self.delivered.lock() {
            Ok(mut q) => std::mem::take(&mut *q),
            Err(poisoned) => std::mem::take(&mut *poisoned.into_inner()),
        }
    }

    pub fn live_peers(&self) -> Vec<crate::p2p::peer::Peer> {
        match self.table.lock() {
            Ok(t) => t.live_peers(),
            Err(poisoned) => poisoned.into_inner().live_peers(),
        }
    }

    pub fn peer_count(&self) -> usize {
        self.live_peers().len()
    }

    pub fn has_overlay(&self, id: &NodeOverlayId) -> bool {
        match self.table.lock() {
            Ok(t) => t.contains_overlay(id),
            Err(poisoned) => poisoned.into_inner().contains_overlay(id),
        }
    }

    pub fn shutdown(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

impl Drop for P2pNode {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn accept_loop(
    listener: TcpListener,
    hs: HandshakeConfig,
    stop: Arc<AtomicBool>,
    table: Arc<Mutex<RoutingTable>>,
    gossip: Arc<Mutex<GossipEngine>>,
    sessions: Arc<Mutex<HashMap<Address, Sender<SessionCmd>>>>,
    delivered: Arc<Mutex<Vec<(Address, MeshMessage)>>>,
    graph: Arc<Mutex<Option<Arc<dyn MeshGraph>>>>,
) {
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, from)) => {
                let hs = hs.clone();
                let table = table.clone();
                let gossip = gossip.clone();
                let sessions = sessions.clone();
                let delivered = delivered.clone();
                let graph = graph.clone();
                let stop = stop.clone();
                thread::Builder::new()
                    .name("p2p-inbound".into())
                    .spawn(move || {
                        handle_inbound(
                            stream, from, hs, stop, table, gossip, sessions, delivered, graph,
                        )
                    })
                    .ok();
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(_) => thread::sleep(Duration::from_millis(50)),
        }
    }
}

fn handle_inbound(
    stream: TcpStream,
    from: std::net::SocketAddr,
    hs: HandshakeConfig,
    stop: Arc<AtomicBool>,
    table: Arc<Mutex<RoutingTable>>,
    gossip: Arc<Mutex<GossipEngine>>,
    sessions: Arc<Mutex<HashMap<Address, Sender<SessionCmd>>>>,
    delivered: Arc<Mutex<Vec<(Address, MeshMessage)>>>,
    graph: Arc<Mutex<Option<Arc<dyn MeshGraph>>>>,
) {
    let _ = stream.set_nonblocking(false);
    if inbound_is_mesh(&stream) {
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        let graph_ref = loop {
            if let Some(g) = graph.lock().unwrap().clone() {
                break Some(g);
            }
            if std::time::Instant::now() >= deadline {
                break None;
            }
            thread::sleep(Duration::from_millis(20));
        };
        match graph_ref {
            Some(g) => {
                crate::kron_log("KRON P2P", format!("inbound kron-mesh/1 from {from}"));
                serve_mesh_session(stream, g);
            }
            None => {
                crate::kron_elog(
                    "KRON P2P",
                    format!("inbound kron-mesh/1 from {from} dropped: hub graph not ready"),
                );
            }
        }
        return;
    }
    let mut session = match NoiseSession::handshake(stream, false) {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut cfg = hs;
    cfg.initiator = false;
    match perform_secure_handshake(&mut session, &cfg) {
        Ok(info) => {
            let _ = table.lock().unwrap().insert(info.peer.clone());
            spawn_session(
                session,
                info.peer.id,
                stop,
                gossip,
                sessions,
                delivered,
            );
        }
        Err(_) => {
            session.shutdown();
        }
    }
}

/// Wait until four bytes are peekable so a slow `kron-mesh/1` hello is not
/// mistaken for Noise (`peek` may return 1–3 bytes without blocking).
fn inbound_is_mesh(stream: &TcpStream) -> bool {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(4)));
    let deadline = std::time::Instant::now() + Duration::from_secs(4);
    let mut got = [0u8; 4];
    while std::time::Instant::now() < deadline {
        match stream.peek(&mut got) {
            Ok(n) if n >= 4 => return got == *MESH_MAGIC,
            Ok(_) => thread::sleep(Duration::from_millis(10)),
            Err(e)
                if e.kind() == ErrorKind::WouldBlock
                    || e.kind() == ErrorKind::TimedOut
                    || e.kind() == ErrorKind::Interrupted =>
            {
                thread::sleep(Duration::from_millis(10));
            }
            Err(_) => return false,
        }
    }
    false
}

fn spawn_session(
    mut session: NoiseSession,
    peer_id: Address,
    stop: Arc<AtomicBool>,
    gossip: Arc<Mutex<GossipEngine>>,
    sessions: Arc<Mutex<HashMap<Address, Sender<SessionCmd>>>>,
    delivered: Arc<Mutex<Vec<(Address, MeshMessage)>>>,
) {
    let (tx, rx) = mpsc::channel();
    sessions.lock().unwrap().insert(peer_id, tx);
    thread::Builder::new()
        .name("p2p-session".into())
        .spawn(move || {
            let _ = session.set_read_timeout(Some(Duration::from_millis(200)));
            while !stop.load(Ordering::SeqCst) {
                while let Ok(cmd) = rx.try_recv() {
                    let _ = match cmd {
                        SessionCmd::Inv(inv) => session.write_frame(KIND_INV, &inv.encode()),
                        SessionCmd::Want(w) => session.write_frame(KIND_WANT, &w.encode()),
                        SessionCmd::Payload(p) => session.write_frame(KIND_PAYLOAD, &p.encode()),
                        SessionCmd::Ping => session.write_frame(KIND_PING, &[]),
                    };
                }
                match session.read_frame() {
                    Ok((KIND_INV, payload)) => {
                        if let Ok(inv) = GossipInventory::decode(&payload) {
                            let want = gossip.lock().unwrap().on_inventory(&inv);
                            if !want.ids.is_empty() {
                                let _ = session.write_frame(KIND_WANT, &want.encode());
                            }
                        }
                    }
                    Ok((KIND_WANT, payload)) => {
                        if let Ok(want) = GossipWant::decode(&payload) {
                            let replies = gossip.lock().unwrap().on_want(&want);
                            for p in replies {
                                let _ = session.write_frame(KIND_PAYLOAD, &p.encode());
                            }
                        }
                    }
                    Ok((KIND_PAYLOAD, payload)) => {
                        if let Ok(p) = GossipPayload::decode(&payload) {
                            let id = p.id;
                            if let Ok(Some(msg)) = gossip.lock().unwrap().on_payload(p) {
                                delivered.lock().unwrap().push((peer_id, msg));
                                let inv = GossipInventory { ids: vec![id] };
                                let fanout: Vec<Sender<SessionCmd>> = {
                                    let map = sessions.lock().unwrap();
                                    map.iter()
                                        .filter(|(k, _)| **k != peer_id)
                                        .map(|(_, tx)| tx.clone())
                                        .collect()
                                };
                                for tx in fanout {
                                    let _ = tx.send(SessionCmd::Inv(inv.clone()));
                                }
                            }
                        }
                    }
                    Ok((KIND_PING, _)) => {
                        let _ = session.write_frame(KIND_PONG, &[]);
                    }
                    Ok((KIND_PONG, _)) => {}
                    Ok(_) => {}
                    Err(NetworkError::Io(e))
                        if e.kind() == ErrorKind::TimedOut
                            || e.kind() == ErrorKind::WouldBlock => {}
                    Err(_) => break,
                }
            }
            sessions.lock().unwrap().remove(&peer_id);
        })
        .ok();
}
