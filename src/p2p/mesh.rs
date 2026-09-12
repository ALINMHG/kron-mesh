//! Versioned KRON Mesh wire protocol (`kron-mesh/1`).
//!
//! Authenticated `kron-mesh/1` over Noise XX ( Dilithium identity after handshake).
//! Peers exchange [`SyncInventory`], Have/Need hashes, and [`DagTransaction`]
//! bodies as `KIND_MESH` frames inside the Noise session. Cleartext `KRMS` on
//! port 8000 is rejected. Faucet maps are never advertised.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::anti_bot::profile::DeviceClass;
use crate::crypto::lattice::LatticeKeyPair;
use crate::dag::{compute_dag_diff, DagTransaction, KronDAG, SyncInventory, TxHash, MAX_INVENTORY_HASHES};
use crate::p2p::error::NetworkError;
use crate::p2p::frame::{KIND_MESH, MAX_FRAME};
use crate::p2p::handshake::{perform_secure_handshake, HandshakeConfig};
use crate::p2p::noise::NoiseSession;
use crate::p2p::peer::PeerRole;
/// Protocol name advertised in Hello / Ping.
pub const PROTOCOL_KRON_MESH: &str = "kron-mesh/1";
pub const MESH_MAGIC: &[u8; 4] = b"KRMS";
pub const MESH_VERSION: u8 = 1;

pub const MK_HELLO: u8 = 1;
pub const MK_PING: u8 = 2;
pub const MK_PONG: u8 = 3;
pub const MK_SYNC_INV: u8 = 10;
pub const MK_HAVE: u8 = 11;
pub const MK_NEED: u8 = 12;
pub const MK_DAG_TX: u8 = 13;
pub const MK_DONE: u8 = 14;

/// Max inbound mesh sessions on one hub (plus the accept loop).
pub const MAX_MESH_CONNECTIONS: usize = 64;
/// New vertices accepted from one peer per rate window.
pub const MAX_VERTICES_PER_PEER_WINDOW: u32 = 32;
const VERTEX_RATE_WINDOW: Duration = Duration::from_secs(10);

/// Role on the mesh wire (hub replica, wallet submit, or in-process test).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MeshRole {
    Hub = 0,
    Wallet = 1,
    Test = 2,
}

impl MeshRole {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Hub),
            1 => Some(Self::Wallet),
            2 => Some(Self::Test),
            _ => None,
        }
    }
}

/// Versioned messages. Bodies are bytes on the wire — never a shared graph.
#[derive(Clone, Debug)]
pub enum MeshWireMessage {
    Hello { protocol: String, role: MeshRole },
    Ping,
    Pong,
    SyncInventory(SyncInventory),
    Have { ids: Vec<TxHash> },
    Need { ids: Vec<TxHash> },
    DagTransaction(DagTransaction),
    Done,
}

/// Isolated DAG handle used by hubs and the two-thread loopback test.
/// Each peer owns its own [`KronDAG`]; nothing is shared by `Arc` across peers.
pub trait MeshGraph: Send + Sync {
    fn inventory(&self) -> SyncInventory;
    fn contains(&self, id: &TxHash) -> bool;
    fn get(&self, id: &TxHash) -> Option<DagTransaction>;
    fn ingest(&self, tx: DagTransaction) -> Result<bool, String>;
    fn bodies_in_order(&self, ids: &[TxHash]) -> Vec<DagTransaction>;
    fn apply_inventory(&self, inv: &SyncInventory);
    fn need_and_have(&self, remote: &SyncInventory) -> (Vec<TxHash>, Vec<TxHash>);
    fn vertex_set(&self) -> std::collections::HashSet<TxHash>;
    /// Hub connection slot. Isolated test DAGs always admit.
    fn try_acquire_session(&self) -> bool {
        true
    }
    fn release_session(&self) {}
    /// Per-peer vertex rate limit. Isolated test DAGs always admit.
    fn allow_new_vertex(&self) -> bool {
        true
    }
}

/// One process-local graph. Tests construct two of these — never one `Arc`.
pub struct IsolatedDag {
    dag: Mutex<KronDAG>,
}

impl IsolatedDag {
    pub fn new(dag: KronDAG) -> Self {
        Self {
            dag: Mutex::new(dag),
        }
    }

    pub fn into_inner(self) -> KronDAG {
        self.dag.into_inner().unwrap_or_else(|p| p.into_inner())
    }

    pub fn lock_dag(&self) -> std::sync::MutexGuard<'_, KronDAG> {
        self.dag.lock().unwrap_or_else(|p| p.into_inner())
    }
}

impl MeshGraph for IsolatedDag {
    fn inventory(&self) -> SyncInventory {
        let dag = self.lock_dag();
        SyncInventory::from_dag(&dag, [0u8; 32])
    }

    fn contains(&self, id: &TxHash) -> bool {
        self.lock_dag().contains(id)
    }

    fn get(&self, id: &TxHash) -> Option<DagTransaction> {
        self.lock_dag().get(id).cloned()
    }

    fn ingest(&self, tx: DagTransaction) -> Result<bool, String> {
        self.lock_dag()
            .accept_wire_vertex(tx)
            .map_err(|e| e.to_string())
    }

    fn bodies_in_order(&self, ids: &[TxHash]) -> Vec<DagTransaction> {
        self.lock_dag().transactions_for_in_order(ids)
    }

    fn apply_inventory(&self, _inv: &SyncInventory) {
        // Faucet maps are not on the wire and must not credit spendable balances.
    }

    fn need_and_have(&self, remote: &SyncInventory) -> (Vec<TxHash>, Vec<TxHash>) {
        compute_dag_diff(&self.lock_dag(), remote)
    }

    fn vertex_set(&self) -> std::collections::HashSet<TxHash> {
        self.lock_dag().vertex_set()
    }
}

/// Hub graph: LocalGraph attach, WAL, explorer index. Not a miner.
pub struct HubState {
    dag: Mutex<KronDAG>,
    store: Mutex<Option<crate::persist::DagStore>>,
    api: Arc<Mutex<crate::explorer::ExplorerApi>>,
    sessions: AtomicUsize,
    vertex_window_start: Mutex<Instant>,
    vertices_in_window: AtomicU32,
}

impl HubState {
    pub fn new(dag: KronDAG) -> Arc<Self> {
        Arc::new(Self {
            dag: Mutex::new(dag),
            store: Mutex::new(None),
            api: Arc::new(Mutex::new(crate::explorer::ExplorerApi::new())),
            sessions: AtomicUsize::new(0),
            vertex_window_start: Mutex::new(Instant::now()),
            vertices_in_window: AtomicU32::new(0),
        })
    }

    pub fn set_store(&self, store: crate::persist::DagStore) {
        *self.store.lock().unwrap_or_else(|p| p.into_inner()) = Some(store);
    }

    pub fn explorer_api(&self) -> Arc<Mutex<crate::explorer::ExplorerApi>> {
        self.api.clone()
    }

    pub fn api(&self) -> std::sync::MutexGuard<'_, crate::explorer::ExplorerApi> {
        self.api.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn lock_dag(&self) -> std::sync::MutexGuard<'_, KronDAG> {
        self.dag.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Persist a vertex the local miner already attached (same process DAG).
    pub fn record_attached(&self, tx: &DagTransaction) {
        self.persist_vertex(tx);
    }

    pub fn persist_snapshot(&self) {
        let dag = self.lock_dag();
        let faucet = dag.faucet_snapshot();
        if let Some(store) = self.store.lock().unwrap_or_else(|p| p.into_inner()).as_ref() {
            let _ = store.write_snapshot(&crate::persist::DagSnapshot::from_dag_with_faucet(
                &dag, faucet,
            ));
        }
    }

    fn persist_vertex(&self, tx: &DagTransaction) {
        let dag = self.lock_dag();
        if let Some(store) = self
            .store
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_mut()
        {
            let _ = store.append_vertex(tx, &dag);
            let faucet = dag.faucet_snapshot();
            let _ = store.write_snapshot(&crate::persist::DagSnapshot::from_dag_with_faucet(
                &dag, faucet,
            ));
        }
        drop(dag);
        let dag = self.lock_dag();
        self.api().sync_from_dag(&dag);
    }
}

impl MeshGraph for HubState {
    fn inventory(&self) -> SyncInventory {
        let dag = self.lock_dag();
        SyncInventory::from_dag(&dag, [0u8; 32])
    }

    fn contains(&self, id: &TxHash) -> bool {
        self.lock_dag().contains(id)
    }

    fn get(&self, id: &TxHash) -> Option<DagTransaction> {
        self.lock_dag().get(id).cloned()
    }

    fn ingest(&self, tx: DagTransaction) -> Result<bool, String> {
        let new = {
            let mut dag = self.lock_dag();
            dag.accept_wire_vertex(tx.clone())
                .map_err(|e| e.to_string())?
        };
        if new {
            self.persist_vertex(&tx);
        }
        Ok(new)
    }

    fn bodies_in_order(&self, ids: &[TxHash]) -> Vec<DagTransaction> {
        self.lock_dag().transactions_for_in_order(ids)
    }

    fn apply_inventory(&self, _inv: &SyncInventory) {
        // Peer inventories never credit faucet / spendable balances.
    }

    fn need_and_have(&self, remote: &SyncInventory) -> (Vec<TxHash>, Vec<TxHash>) {
        compute_dag_diff(&self.lock_dag(), remote)
    }

    fn vertex_set(&self) -> std::collections::HashSet<TxHash> {
        self.lock_dag().vertex_set()
    }

    fn try_acquire_session(&self) -> bool {
        let n = self.sessions.fetch_add(1, Ordering::SeqCst);
        if n >= MAX_MESH_CONNECTIONS {
            self.sessions.fetch_sub(1, Ordering::SeqCst);
            return false;
        }
        true
    }

    fn release_session(&self) {
        let _ = self.sessions.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
            Some(n.saturating_sub(1))
        });
    }

    fn allow_new_vertex(&self) -> bool {
        let mut start = self
            .vertex_window_start
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if start.elapsed() >= VERTEX_RATE_WINDOW {
            *start = Instant::now();
            self.vertices_in_window.store(0, Ordering::SeqCst);
        }
        let n = self.vertices_in_window.fetch_add(1, Ordering::SeqCst);
        n < MAX_VERTICES_PER_PEER_WINDOW
    }
}

pub fn default_gateway_addr() -> SocketAddr {
    if let Ok(raw) = std::env::var("KRON_GATEWAY") {
        let trimmed = raw
            .trim()
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .trim_end_matches('/');
        if let Ok(addr) = trimmed.parse() {
            return addr;
        }
    }
    SocketAddr::from(([127, 0, 0, 1], 8000))
}

pub fn write_mesh_frame(stream: &mut impl Write, kind: u8, payload: &[u8]) -> Result<(), NetworkError> {
    if payload.len() > MAX_FRAME as usize {
        return Err(NetworkError::BadFrame);
    }
    let mut hdr = [0u8; 10];
    hdr[0..4].copy_from_slice(MESH_MAGIC);
    hdr[4] = MESH_VERSION;
    hdr[5] = kind;
    hdr[6..10].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    stream.write_all(&hdr)?;
    stream.write_all(payload)?;
    stream.flush()?;
    Ok(())
}

pub fn read_mesh_frame(stream: &mut impl Read) -> Result<(u8, Vec<u8>), NetworkError> {
    let mut hdr = [0u8; 10];
    stream.read_exact(&mut hdr)?;
    if hdr[0..4] != MESH_MAGIC[..] || hdr[4] != MESH_VERSION {
        return Err(NetworkError::BadFrame);
    }
    let kind = hdr[5];
    let len = u32::from_le_bytes(hdr[6..10].try_into().unwrap());
    if len > MAX_FRAME {
        return Err(NetworkError::BadFrame);
    }
    let mut payload = vec![0u8; len as usize];
    stream.read_exact(&mut payload)?;
    Ok((kind, payload))
}

pub fn encode_wire(msg: &MeshWireMessage) -> (u8, Vec<u8>) {
    match msg {
        MeshWireMessage::Hello { protocol, role } => {
            let mut out = Vec::new();
            let p = protocol.as_bytes();
            out.extend_from_slice(&(p.len() as u16).to_le_bytes());
            out.extend_from_slice(p);
            out.push(*role as u8);
            (MK_HELLO, out)
        }
        MeshWireMessage::Ping => (MK_PING, PROTOCOL_KRON_MESH.as_bytes().to_vec()),
        MeshWireMessage::Pong => (MK_PONG, PROTOCOL_KRON_MESH.as_bytes().to_vec()),
        MeshWireMessage::SyncInventory(inv) => (MK_SYNC_INV, encode_sync_inventory(inv)),
        MeshWireMessage::Have { ids } => (MK_HAVE, encode_hash_list(ids)),
        MeshWireMessage::Need { ids } => (MK_NEED, encode_hash_list(ids)),
        MeshWireMessage::DagTransaction(tx) => (MK_DAG_TX, tx.canonical_bytes()),
        MeshWireMessage::Done => (MK_DONE, Vec::new()),
    }
}

pub fn decode_wire(kind: u8, payload: &[u8]) -> Result<MeshWireMessage, NetworkError> {
    match kind {
        MK_HELLO => {
            if payload.len() < 3 {
                return Err(NetworkError::BadFrame);
            }
            let n = u16::from_le_bytes(payload[0..2].try_into().unwrap()) as usize;
            if payload.len() < 2 + n + 1 {
                return Err(NetworkError::BadFrame);
            }
            let protocol = String::from_utf8_lossy(&payload[2..2 + n]).into_owned();
            let role = MeshRole::from_u8(payload[2 + n]).ok_or(NetworkError::BadFrame)?;
            Ok(MeshWireMessage::Hello { protocol, role })
        }
        MK_PING => Ok(MeshWireMessage::Ping),
        MK_PONG => Ok(MeshWireMessage::Pong),
        MK_SYNC_INV => Ok(MeshWireMessage::SyncInventory(decode_sync_inventory(payload)?)),
        MK_HAVE => Ok(MeshWireMessage::Have {
            ids: decode_hash_list(payload)?,
        }),
        MK_NEED => Ok(MeshWireMessage::Need {
            ids: decode_hash_list(payload)?,
        }),
        MK_DAG_TX => {
            let tx = DagTransaction::from_canonical(payload).map_err(|_| NetworkError::BadFrame)?;
            Ok(MeshWireMessage::DagTransaction(tx))
        }
        MK_DONE => Ok(MeshWireMessage::Done),
        _ => Err(NetworkError::BadFrame),
    }
}

fn encode_hash_list(ids: &[TxHash]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(ids.len() as u32).to_le_bytes());
    for id in ids {
        out.extend_from_slice(id);
    }
    out
}

fn decode_hash_list(bytes: &[u8]) -> Result<Vec<TxHash>, NetworkError> {
    if bytes.len() < 4 {
        return Err(NetworkError::BadFrame);
    }
    let n = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
    if n > MAX_INVENTORY_HASHES {
        return Err(NetworkError::BadFrame);
    }
    if bytes.len() != 4 + n * 32 {
        return Err(NetworkError::BadFrame);
    }
    let mut ids = Vec::with_capacity(n);
    for i in 0..n {
        let mut h = [0u8; 32];
        h.copy_from_slice(&bytes[4 + i * 32..4 + (i + 1) * 32]);
        ids.push(h);
    }
    Ok(ids)
}

fn encode_sync_inventory(inv: &SyncInventory) -> Vec<u8> {
    let mut out = encode_hash_list(&inv.tips);
    out.extend(encode_hash_list(&inv.recent));
    match inv.peer_id {
        Some(id) => {
            out.push(1);
            out.extend_from_slice(&id);
        }
        None => out.push(0),
    }
    out
}

fn decode_sync_inventory(bytes: &[u8]) -> Result<SyncInventory, NetworkError> {
    if bytes.len() < 4 {
        return Err(NetworkError::BadFrame);
    }
    let nt = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
    if nt > MAX_INVENTORY_HASHES {
        return Err(NetworkError::BadFrame);
    }
    let mut off = 4;
    if bytes.len() < off + nt * 32 + 4 {
        return Err(NetworkError::BadFrame);
    }
    let mut tips = Vec::with_capacity(nt);
    for _ in 0..nt {
        let mut h = [0u8; 32];
        h.copy_from_slice(&bytes[off..off + 32]);
        tips.push(h);
        off += 32;
    }
    let nr = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap()) as usize;
    if nr > MAX_INVENTORY_HASHES || nt.saturating_add(nr) > MAX_INVENTORY_HASHES {
        return Err(NetworkError::BadFrame);
    }
    off += 4;
    if bytes.len() < off + nr * 32 + 1 {
        return Err(NetworkError::BadFrame);
    }
    let mut recent = Vec::with_capacity(nr);
    for _ in 0..nr {
        let mut h = [0u8; 32];
        h.copy_from_slice(&bytes[off..off + 32]);
        recent.push(h);
        off += 32;
    }
    let has_peer = bytes[off];
    off += 1;
    let peer_id = if has_peer == 1 {
        if bytes.len() < off + 32 {
            return Err(NetworkError::BadFrame);
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&bytes[off..off + 32]);
        off += 32;
        Some(id)
    } else if has_peer == 0 {
        None
    } else {
        return Err(NetworkError::BadFrame);
    };
    // Legacy peers may still append a faucet map. Never apply it.
    let _ = off;
    Ok(SyncInventory {
        tips,
        recent,
        peer_id,
    })
}

fn write_msg(session: &mut NoiseSession, msg: &MeshWireMessage) -> Result<(), NetworkError> {
    let (kind, payload) = encode_wire(msg);
    let mut body = Vec::with_capacity(1 + payload.len());
    body.push(kind);
    body.extend_from_slice(&payload);
    session.write_frame(KIND_MESH, &body)
}

fn read_msg(session: &mut NoiseSession) -> Result<MeshWireMessage, NetworkError> {
    let (kind, payload) = session.read_frame()?;
    if kind != KIND_MESH || payload.is_empty() {
        return Err(NetworkError::BadFrame);
    }
    decode_wire(payload[0], &payload[1..])
}

fn expect_hello(session: &mut NoiseSession) -> Result<MeshRole, NetworkError> {
    match read_msg(session)? {
        MeshWireMessage::Hello { protocol, role } => {
            if protocol != PROTOCOL_KRON_MESH {
                return Err(NetworkError::Handshake("wrong mesh protocol"));
            }
            Ok(role)
        }
        _ => Err(NetworkError::Handshake("expected mesh hello")),
    }
}

fn send_hello(session: &mut NoiseSession, role: MeshRole) -> Result<(), NetworkError> {
    write_msg(
        session,
        &MeshWireMessage::Hello {
            protocol: PROTOCOL_KRON_MESH.to_string(),
            role,
        },
    )
}

fn ephemeral_hs(initiator: bool) -> HandshakeConfig {
    let mut rng = rand::rngs::OsRng;
    HandshakeConfig::honest(
        LatticeKeyPair::generate(&mut rng),
        if initiator {
            PeerRole::EdgeMiner
        } else {
            PeerRole::CoreValidator
        },
        if initiator {
            DeviceClass::LegacyMobile
        } else {
            DeviceClass::PersonalComputer
        },
        initiator,
    )
}

/// Serve mesh after Noise XX + Dilithium. Cleartext `KRMS` callers must not reach here.
pub fn serve_authenticated_mesh(session: &mut NoiseSession, graph: Arc<dyn MeshGraph>) {
    if !graph.try_acquire_session() {
        return;
    }
    let _guard = SessionGuard(graph.clone());
    let role = match expect_hello(session) {
        Ok(r) => r,
        Err(_) => return,
    };
    finish_authenticated_mesh(session, graph.as_ref(), role);
}

/// Hub inbound already consumed the first `KIND_MESH` frame (mesh Hello).
pub fn serve_authenticated_mesh_from_first(
    mut session: NoiseSession,
    graph: Arc<dyn MeshGraph>,
    first_payload: Vec<u8>,
) {
    if !graph.try_acquire_session() {
        return;
    }
    let _guard = SessionGuard(graph.clone());
    if first_payload.is_empty() {
        return;
    }
    let first = match decode_wire(first_payload[0], &first_payload[1..]) {
        Ok(m) => m,
        Err(_) => return,
    };
    let role = match first {
        MeshWireMessage::Hello { protocol, role } if protocol == PROTOCOL_KRON_MESH => role,
        _ => return,
    };
    finish_authenticated_mesh(&mut session, graph.as_ref(), role);
}

fn finish_authenticated_mesh(session: &mut NoiseSession, graph: &dyn MeshGraph, role: MeshRole) {
    if send_hello(session, MeshRole::Hub).is_err() {
        return;
    }
    match role {
        MeshRole::Wallet => {
            let _ = serve_wallet_submit(session, graph);
        }
        MeshRole::Hub | MeshRole::Test => {
            let _ = run_sync_round(session, graph, false);
        }
    }
}

struct SessionGuard(Arc<dyn MeshGraph>);
impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.0.release_session();
    }
}

/// Inbound after Noise + Dilithium (production hub).
pub fn serve_mesh_session(stream: TcpStream, graph: Arc<dyn MeshGraph>) {
    let hs = ephemeral_hs(false);
    let mut session = match NoiseSession::handshake(stream, false) {
        Ok(s) => s,
        Err(_) => return,
    };
    if perform_secure_handshake(&mut session, &hs).is_err() {
        session.shutdown();
        return;
    }
    serve_authenticated_mesh(&mut session, graph);
}

fn serve_wallet_submit(session: &mut NoiseSession, graph: &dyn MeshGraph) -> Result<(), NetworkError> {
    loop {
        match read_msg(session)? {
            MeshWireMessage::Ping => write_msg(session, &MeshWireMessage::Pong)?,
            MeshWireMessage::DagTransaction(tx) => {
                if !graph.allow_new_vertex() {
                    return Err(NetworkError::BadFrame);
                }
                graph.ingest(tx).map_err(|_| NetworkError::BadFrame)?;
                write_msg(session, &MeshWireMessage::Done)?;
                return Ok(());
            }
            MeshWireMessage::Done => return Ok(()),
            _ => return Err(NetworkError::BadFrame),
        }
    }
}

/// Lockstep Have/Need + body exchange. `initiator` is the connecting peer.
pub fn run_sync_round(
    session: &mut NoiseSession,
    graph: &dyn MeshGraph,
    initiator: bool,
) -> Result<(), NetworkError> {
    if initiator {
        write_msg(session, &MeshWireMessage::Ping)?;
        match read_msg(session)? {
            MeshWireMessage::Pong | MeshWireMessage::Ping => {}
            _ => return Err(NetworkError::Handshake("expected mesh pong")),
        }
        write_msg(session, &MeshWireMessage::SyncInventory(graph.inventory()))?;
        let remote = match read_msg(session)? {
            MeshWireMessage::SyncInventory(inv) => inv,
            _ => return Err(NetworkError::BadFrame),
        };
        graph.apply_inventory(&remote);
        let (need, have) = graph.need_and_have(&remote);
        write_msg(session, &MeshWireMessage::Need { ids: need })?;
        write_msg(session, &MeshWireMessage::Have { ids: have })?;
        let their_need = match read_msg(session)? {
            MeshWireMessage::Need { ids } => ids,
            _ => return Err(NetworkError::BadFrame),
        };
        for tx in graph.bodies_in_order(&their_need) {
            write_msg(session, &MeshWireMessage::DagTransaction(tx))?;
        }
        write_msg(session, &MeshWireMessage::Done)?;
        recv_bodies_until_done(session, graph)
    } else {
        match read_msg(session)? {
            MeshWireMessage::Ping => write_msg(session, &MeshWireMessage::Pong)?,
            other => return unexpected_as_inv(session, graph, other),
        }
        let remote = match read_msg(session)? {
            MeshWireMessage::SyncInventory(inv) => inv,
            _ => return Err(NetworkError::BadFrame),
        };
        graph.apply_inventory(&remote);
        write_msg(session, &MeshWireMessage::SyncInventory(graph.inventory()))?;
        let their_need = match read_msg(session)? {
            MeshWireMessage::Need { ids } => ids,
            _ => return Err(NetworkError::BadFrame),
        };
        let their_have = match read_msg(session)? {
            MeshWireMessage::Have { ids } => ids,
            _ => return Err(NetworkError::BadFrame),
        };
        let (mut need, _have) = graph.need_and_have(&remote);
        for id in their_have {
            if !graph.contains(&id) && !need.contains(&id) {
                need.push(id);
            }
        }
        write_msg(session, &MeshWireMessage::Need { ids: need })?;
        for tx in graph.bodies_in_order(&their_need) {
            write_msg(session, &MeshWireMessage::DagTransaction(tx))?;
        }
        recv_bodies_until_done(session, graph)?;
        write_msg(session, &MeshWireMessage::Done)
    }
}

fn unexpected_as_inv(
    session: &mut NoiseSession,
    graph: &dyn MeshGraph,
    first: MeshWireMessage,
) -> Result<(), NetworkError> {
    let MeshWireMessage::SyncInventory(remote) = first else {
        return Err(NetworkError::BadFrame);
    };
    graph.apply_inventory(&remote);
    write_msg(session, &MeshWireMessage::SyncInventory(graph.inventory()))?;
    let (need, _) = graph.need_and_have(&remote);
    write_msg(session, &MeshWireMessage::Need { ids: need })?;
    recv_bodies_until_done(session, graph)
}

fn recv_bodies_until_done(
    session: &mut NoiseSession,
    graph: &dyn MeshGraph,
) -> Result<(), NetworkError> {
    loop {
        match read_msg(session) {
            Ok(MeshWireMessage::DagTransaction(tx)) => {
                if graph.allow_new_vertex() {
                    let _ = graph.ingest(tx);
                }
            }
            Ok(MeshWireMessage::Need { ids }) => {
                for tx in graph.bodies_in_order(&ids) {
                    write_msg(session, &MeshWireMessage::DagTransaction(tx))?;
                }
            }
            Ok(MeshWireMessage::Have { ids }) => {
                let missing: Vec<TxHash> = ids.into_iter().filter(|id| !graph.contains(id)).collect();
                if !missing.is_empty() {
                    write_msg(session, &MeshWireMessage::Need { ids: missing })?;
                }
            }
            Ok(MeshWireMessage::Done) => return Ok(()),
            Ok(MeshWireMessage::Ping) => write_msg(session, &MeshWireMessage::Pong)?,
            Ok(MeshWireMessage::Pong) => {}
            Ok(_) => return Err(NetworkError::BadFrame),
            Err(NetworkError::Io(e))
                if e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::WouldBlock =>
            {
                return Ok(());
            }
            Err(e) => return Err(e),
        }
    }
}

fn open_mesh_client(addr: SocketAddr) -> Result<NoiseSession, NetworkError> {
    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))?;
    let mut session = NoiseSession::handshake(stream, true)?;
    let hs = ephemeral_hs(true);
    perform_secure_handshake(&mut session, &hs)?;
    Ok(session)
}

/// Connect to a hub: Noise XX + Dilithium, then Have/Need inside the session.
pub fn mesh_sync_connect(
    addr: SocketAddr,
    graph: Arc<dyn MeshGraph>,
    role: MeshRole,
) -> Result<(), NetworkError> {
    let mut session = open_mesh_client(addr)?;
    send_hello(&mut session, role)?;
    let _ = expect_hello(&mut session)?;
    run_sync_round(&mut session, graph.as_ref(), true)
}

/// Wallet broadcast: Noise + Dilithium, then a signed vertex (or `KRON_GATEWAY`).
pub fn broadcast_wallet_tx(addr: SocketAddr, tx: &DagTransaction) -> Result<(), NetworkError> {
    let mut session = open_mesh_client(addr)?;
    send_hello(&mut session, MeshRole::Wallet)?;
    let _ = expect_hello(&mut session)?;
    write_msg(&mut session, &MeshWireMessage::DagTransaction(tx.clone()))?;
    match read_msg(&mut session)? {
        MeshWireMessage::Done => Ok(()),
        _ => Err(NetworkError::BadFrame),
    }
}

/// Bind a Noise-authenticated mesh listener (tests). Production hubs share `--port`.
pub fn bind_mesh_listener(
    graph: Arc<dyn MeshGraph>,
) -> Result<(SocketAddr, std::thread::JoinHandle<()>), NetworkError> {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))?;
    listener.set_nonblocking(false)?;
    let addr = listener.local_addr()?;
    let handle = std::thread::Builder::new()
        .name("kron-mesh-test".into())
        .spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                serve_mesh_session(stream, graph);
            }
        })
        .map_err(NetworkError::Io)?;
    std::thread::sleep(Duration::from_millis(20));
    Ok((addr, handle))
}

/// True when the first four peekable bytes are cleartext `KRMS`.
pub fn peek_is_cleartext_krms(stream: &TcpStream) -> bool {
    let mut got = [0u8; 4];
    match stream.peek(&mut got) {
        Ok(n) if n >= 4 => got == *MESH_MAGIC,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kron::generate_kron_wallet_from_rng;
    use rand::SeedableRng;

    #[test]
    fn hello_ping_protocol_is_kron_mesh_1() {
        let msg = MeshWireMessage::Hello {
            protocol: PROTOCOL_KRON_MESH.to_string(),
            role: MeshRole::Hub,
        };
        let (kind, bytes) = encode_wire(&msg);
        let back = decode_wire(kind, &bytes).unwrap();
        match back {
            MeshWireMessage::Hello { protocol, role } => {
                assert_eq!(protocol, "kron-mesh/1");
                assert_eq!(role, MeshRole::Hub);
            }
            _ => panic!("hello"),
        }
        let (k, p) = encode_wire(&MeshWireMessage::Ping);
        assert_eq!(k, MK_PING);
        assert_eq!(p, b"kron-mesh/1");
    }

    #[test]
    fn two_isolated_dags_sync_over_loopback() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x4D45_5348_5731);
        let alice = generate_kron_wallet_from_rng(&mut rng);
        let bob = generate_kron_wallet_from_rng(&mut rng);

        let mut dag_a = KronDAG::with_genesis();
        dag_a.credit_account(*alice.address().as_bytes(), 1_000_000);
        let tx = dag_a
            .compose_and_sign_with_rng(&alice, *bob.address().as_bytes(), 7_000, &mut rng)
            .unwrap();
        dag_a.attach_and_verify_tx(tx.clone()).unwrap();

        let dag_b = KronDAG::with_genesis();
        // B starts with genesis only — faucet and the vertex arrive as bytes.
        assert_ne!(
            dag_a.vertex_set(),
            dag_b.vertex_set(),
            "peers must not share a graph before the wire exchange"
        );

        let graph_a: Arc<dyn MeshGraph> = Arc::new(IsolatedDag::new(dag_a));
        let graph_b: Arc<dyn MeshGraph> = Arc::new(IsolatedDag::new(dag_b));
        let b_listen = graph_b.clone();
        let (addr, handle) = bind_mesh_listener(b_listen).unwrap();
        mesh_sync_connect(addr, graph_a.clone(), MeshRole::Test).unwrap();
        handle.join().unwrap();

        assert_eq!(
            graph_a.vertex_set(),
            graph_b.vertex_set(),
            "after sync both isolated DAGs must store the same vertices"
        );
        assert!(graph_b.contains(&tx.id));
    }

    #[test]
    fn peer_faucet_hint_does_not_increase_receiver_balance() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xF4C7);
        let alice = generate_kron_wallet_from_rng(&mut rng);
        let addr = *alice.address().as_bytes();
        let mut sender = KronDAG::with_genesis();
        sender.credit_account(addr, 5_000_000);
        let receiver = IsolatedDag::new(KronDAG::with_genesis());
        assert_eq!(receiver.lock_dag().balance(&addr), 0);
        receiver.lock_dag().apply_faucet_hint(addr, 5_000_000);
        assert_eq!(receiver.lock_dag().balance(&addr), 0);
        let inv = SyncInventory::from_dag(&sender, [1u8; 32]);
        receiver.apply_inventory(&inv);
        assert_eq!(receiver.lock_dag().balance(&addr), 0);
        assert!(inv.tips.len() + inv.recent.len() <= MAX_INVENTORY_HASHES);
    }

    #[test]
    fn oversized_inventory_is_rejected() {
        let n = MAX_INVENTORY_HASHES + 1;
        let mut payload = Vec::new();
        payload.extend_from_slice(&(n as u32).to_le_bytes());
        payload.extend(std::iter::repeat(0u8).take(n * 32));
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.push(0);
        assert!(decode_sync_inventory(&payload).is_err());
        let mut ids = Vec::new();
        ids.extend(std::iter::repeat([0u8; 32]).take(n));
        assert!(decode_hash_list(&encode_hash_list(&ids)).is_err());
    }
}
