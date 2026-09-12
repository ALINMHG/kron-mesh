//! WAL of DAG vertices + snapshot of KronDAG ledger fields.
//!
//! On boot: load `snapshot.bin` (accounts, supply, dag_tx_count, tips) then
//! replay `wal.log` vertices that are not already in the snapshot prefix.
//! Restart restores the graph.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::crypto::hash::sha256;
use crate::crypto::lattice::CryptoError;
use crate::dag::{DagError, DagTransaction, KronDAG, TxHash};
use crate::types::{Address, Hash};

const WAL_MAGIC: &[u8; 4] = b"KRDW";
const SNAP_MAGIC: &[u8; 4] = b"KRDS";
const VERSION: u8 = 1;
const SNAPSHOT_EVERY: u64 = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PersistError {
    Io(String),
    Corrupt(&'static str),
    Crypto(CryptoError),
    Dag(DagError),
}

impl std::fmt::Display for PersistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "persist i/o: {e}"),
            Self::Corrupt(e) => write!(f, "persist corrupt: {e}"),
            Self::Crypto(e) => write!(f, "persist crypto: {e}"),
            Self::Dag(e) => write!(f, "persist dag: {e}"),
        }
    }
}

impl From<std::io::Error> for PersistError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

impl From<CryptoError> for PersistError {
    fn from(e: CryptoError) -> Self {
        Self::Crypto(e)
    }
}

impl From<DagError> for PersistError {
    fn from(e: DagError) -> Self {
        Self::Dag(e)
    }
}

/// Ledger checkpoint. Vertices themselves live in the WAL (plus genesis).
/// `faucet` is bootstrap credit (not minted supply) reapplied before WAL replay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DagSnapshot {
    pub supply: u64,
    pub dag_tx_count: u64,
    pub vertex_count: u64,
    pub accounts: BTreeMap<Address, u64>,
    pub faucet: BTreeMap<Address, u64>,
    pub tips: Vec<TxHash>,
}

impl Default for DagSnapshot {
    fn default() -> Self {
        Self {
            supply: 0,
            dag_tx_count: 0,
            vertex_count: 0,
            accounts: BTreeMap::new(),
            faucet: BTreeMap::new(),
            tips: Vec::new(),
        }
    }
}

impl DagSnapshot {
    pub fn from_dag(dag: &KronDAG) -> Self {
        Self::from_dag_with_faucet(dag, dag.faucet_snapshot())
    }

    pub fn from_dag_with_faucet(dag: &KronDAG, faucet: BTreeMap<Address, u64>) -> Self {
        Self {
            supply: dag.current_supply,
            dag_tx_count: dag.dag_tx_count,
            vertex_count: dag.vertex_count() as u64,
            accounts: dag.account_snapshot(),
            faucet,
            tips: dag.tip_list(),
        }
    }
}

/// One appended DAG vertex.
#[derive(Clone, Debug)]
pub struct WalRecord {
    pub tx: DagTransaction,
}

pub struct DagStore {
    dir: PathBuf,
}

impl DagStore {
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, PersistError> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    pub fn wal_path(&self) -> PathBuf {
        self.dir.join("wal.log")
    }

    pub fn snapshot_path(&self) -> PathBuf {
        self.dir.join("snapshot.bin")
    }

    /// Genesis + faucet credits + WAL replay. Restores the graph.
    pub fn load(&self) -> Result<(KronDAG, DagSnapshot), PersistError> {
        let snap = if self.snapshot_path().exists() {
            read_snapshot(&self.snapshot_path())?
        } else {
            DagSnapshot::default()
        };
        let mut dag = KronDAG::with_genesis();
        for (addr, amount) in &snap.faucet {
            if *amount > 0 {
                dag.credit_account(*addr, *amount);
            }
        }
        let records = read_wal(&self.wal_path())?;
        for rec in records {
            if dag.contains(&rec.tx.id) {
                continue;
            }
            dag.attach_and_verify_tx(rec.tx)?;
        }
        Ok((dag, snap))
    }

    pub fn append_vertex(
        &mut self,
        tx: &DagTransaction,
        dag: &KronDAG,
    ) -> Result<(), PersistError> {
        if tx.is_genesis() {
            return Ok(());
        }
        append_wal(&self.wal_path(), tx)?;
        if dag.dag_tx_count > 0 && dag.dag_tx_count % SNAPSHOT_EVERY == 0 {
            self.write_snapshot(&DagSnapshot::from_dag(dag))?;
        }
        Ok(())
    }

    pub fn write_snapshot(&self, snap: &DagSnapshot) -> Result<(), PersistError> {
        write_snapshot(&self.snapshot_path(), snap)
    }
}

fn write_checksummed(file: &mut File, magic: &[u8; 4], body: &[u8]) -> Result<(), PersistError> {
    let sum = sha256(body);
    file.write_all(magic)?;
    file.write_all(&[VERSION])?;
    file.write_all(&(body.len() as u32).to_le_bytes())?;
    file.write_all(body)?;
    file.write_all(&sum)?;
    file.flush()?;
    Ok(())
}

fn read_checksummed(bytes: &[u8], magic: &[u8; 4], off: &mut usize) -> Result<Vec<u8>, PersistError> {
    if bytes.len() < *off + 4 + 1 + 4 + 32 {
        return Err(PersistError::Corrupt("short record"));
    }
    if &bytes[*off..*off + 4] != magic {
        return Err(PersistError::Corrupt("bad magic"));
    }
    *off += 4;
    if bytes[*off] != VERSION {
        return Err(PersistError::Corrupt("unsupported version"));
    }
    *off += 1;
    let n = u32::from_le_bytes(bytes[*off..*off + 4].try_into().unwrap()) as usize;
    *off += 4;
    if bytes.len() < *off + n + 32 {
        return Err(PersistError::Corrupt("truncated body"));
    }
    let body = bytes[*off..*off + n].to_vec();
    *off += n;
    let mut sum = [0u8; 32];
    sum.copy_from_slice(&bytes[*off..*off + 32]);
    *off += 32;
    if sha256(&body) != sum {
        return Err(PersistError::Corrupt("checksum mismatch"));
    }
    Ok(body)
}

fn write_snapshot(path: &Path, snap: &DagSnapshot) -> Result<(), PersistError> {
    let body = encode_snapshot(snap);
    let tmp = path.with_extension("bin.tmp");
    let mut f = File::create(&tmp)?;
    write_checksummed(&mut f, SNAP_MAGIC, &body)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

fn read_snapshot(path: &Path) -> Result<DagSnapshot, PersistError> {
    let bytes = fs::read(path)?;
    let mut off = 0usize;
    let body = read_checksummed(&bytes, SNAP_MAGIC, &mut off)?;
    decode_snapshot(&body)
}

fn append_wal(path: &Path, tx: &DagTransaction) -> Result<(), PersistError> {
    let body = tx.canonical_bytes();
    let mut f = OpenOptions::new().create(true).append(true).open(path)?;
    write_checksummed(&mut f, WAL_MAGIC, &body)
}

fn read_wal(path: &Path) -> Result<Vec<WalRecord>, PersistError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let bytes = fs::read(path)?;
    let mut off = 0usize;
    let mut out = Vec::new();
    while off < bytes.len() {
        match read_checksummed(&bytes, WAL_MAGIC, &mut off) {
            Ok(body) => match DagTransaction::from_canonical(&body) {
                Ok(tx) => out.push(WalRecord { tx }),
                Err(_) => break,
            },
            Err(_) => break,
        }
    }
    Ok(out)
}

fn put_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn put_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn take_u64(bytes: &[u8], off: &mut usize) -> Result<u64, PersistError> {
    if bytes.len() < *off + 8 {
        return Err(PersistError::Corrupt("u64"));
    }
    let v = u64::from_le_bytes(bytes[*off..*off + 8].try_into().unwrap());
    *off += 8;
    Ok(v)
}

fn take_u32(bytes: &[u8], off: &mut usize) -> Result<u32, PersistError> {
    if bytes.len() < *off + 4 {
        return Err(PersistError::Corrupt("u32"));
    }
    let v = u32::from_le_bytes(bytes[*off..*off + 4].try_into().unwrap());
    *off += 4;
    Ok(v)
}

fn take_hash(bytes: &[u8], off: &mut usize) -> Result<Hash, PersistError> {
    if bytes.len() < *off + 32 {
        return Err(PersistError::Corrupt("hash"));
    }
    let mut h = [0u8; 32];
    h.copy_from_slice(&bytes[*off..*off + 32]);
    *off += 32;
    Ok(h)
}

fn encode_accounts(accounts: &BTreeMap<Address, u64>) -> Vec<u8> {
    let mut buf = Vec::new();
    put_u32(&mut buf, accounts.len() as u32);
    for (addr, bal) in accounts {
        buf.extend_from_slice(addr);
        put_u64(&mut buf, *bal);
    }
    buf
}

fn decode_accounts(bytes: &[u8], off: &mut usize) -> Result<BTreeMap<Address, u64>, PersistError> {
    let n = take_u32(bytes, off)? as usize;
    let mut out = BTreeMap::new();
    for _ in 0..n {
        let addr = take_hash(bytes, off)?;
        let bal = take_u64(bytes, off)?;
        out.insert(addr, bal);
    }
    Ok(out)
}

fn encode_snapshot(snap: &DagSnapshot) -> Vec<u8> {
    let mut buf = Vec::new();
    put_u64(&mut buf, snap.supply);
    put_u64(&mut buf, snap.dag_tx_count);
    put_u64(&mut buf, snap.vertex_count);
    buf.extend(encode_accounts(&snap.accounts));
    buf.extend(encode_accounts(&snap.faucet));
    put_u32(&mut buf, snap.tips.len() as u32);
    for t in &snap.tips {
        buf.extend_from_slice(t);
    }
    buf
}

fn decode_snapshot(bytes: &[u8]) -> Result<DagSnapshot, PersistError> {
    let mut off = 0usize;
    let supply = take_u64(bytes, &mut off)?;
    let dag_tx_count = take_u64(bytes, &mut off)?;
    let vertex_count = take_u64(bytes, &mut off)?;
    let accounts = decode_accounts(bytes, &mut off)?;
    let faucet = decode_accounts(bytes, &mut off)?;
    let n = take_u32(bytes, &mut off)? as usize;
    let mut tips = Vec::with_capacity(n);
    for _ in 0..n {
        tips.push(take_hash(bytes, &mut off)?);
    }
    Ok(DagSnapshot {
        supply,
        dag_tx_count,
        vertex_count,
        accounts,
        faucet,
        tips,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kron::generate_kron_wallet_from_rng;
    use rand::SeedableRng;

    #[test]
    fn wal_crash_restart_restores_dag_graph() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x5AFE);
        let alice = generate_kron_wallet_from_rng(&mut rng);
        let bob = generate_kron_wallet_from_rng(&mut rng);
        let dir = std::env::temp_dir().join(format!(
            "kron-dag-wal-{}-{}",
            std::process::id(),
            0x5AFE
        ));
        let _ = fs::remove_dir_all(&dir);
        let mut store = DagStore::open(&dir).unwrap();
        let mut dag = KronDAG::with_genesis();
        let mut faucet = BTreeMap::new();
        faucet.insert(*alice.address().as_bytes(), 1_000_000);
        dag.credit_account(*alice.address().as_bytes(), 1_000_000);
        let tx = dag
            .compose_and_sign_with_rng(&alice, *bob.address().as_bytes(), 10_000, &mut rng)
            .unwrap();
        dag.attach_and_verify_tx(tx.clone()).unwrap();
        store.append_vertex(&tx, &dag).unwrap();
        store
            .write_snapshot(&DagSnapshot::from_dag_with_faucet(&dag, faucet))
            .unwrap();
        let supply = dag.current_supply;
        let count = dag.dag_tx_count;
        let tips = dag.tip_list();
        drop(store);

        let store2 = DagStore::open(&dir).unwrap();
        let (dag2, snap) = store2.load().unwrap();
        assert_eq!(dag2.dag_tx_count, count);
        assert_eq!(dag2.current_supply, supply);
        assert_eq!(dag2.contains(&tx.id), true);
        assert_eq!(dag2.tip_list(), tips);
        assert_eq!(snap.supply, supply);
        let _ = fs::remove_dir_all(&dir);
    }
}
