# KRON Mesh

Phone-only DAG mesh. **Phones are the network.** There are no blocks and no required PC. A Windows machine can only follow a phone as a read-only explorer.

- Addresses: `kron1...` (NIST ML-DSA-44)
- Fee: **0.001 KRON** per user transaction
- Mint: **0.1 KRON** per confirmed tx, **80% miner / 20% relays**
- Cap: **24,000,000 KRON**, premine **0**
- Halving: every **126,144,000** confirmed txs
- Wire: `kron-mesh/1` (`SyncInventory` / Have / Need / `DagTransaction`)

Two phones sync over LAN. An offline PC does not stop the mesh. x86 mining is refused at runtime.

## Requirements

- **Network / mining:** a real ARM phone (Android + [Termux](https://termux.dev), `aarch64`). x86 and Windows cannot mine or run a hub.
- **Optional explorer:** Windows PC with [Rust](https://rustup.rs) (stable).
- Rust + Git on the phone (`pkg install rust git`).

## Termux (this is the network)

```bash
pkg install rust git
git clone <this-repo-url>
cd new-blockchain
cargo build --release --bin kron-phone
./target/release/kron-phone
```

No flags opens a menu:

1. **Generate KRON address** — prints a `kron1...` address and a **24-word** passphrase. Write the words down; they are not shown again (use `--show-mnemonic` only if you must).
2. **Mine** — asks for a `kron1` reward address. The node stays running in the **same process**.

Flags:

```bash
# Phone 1 — node + miner
./target/release/kron-phone --mine --reward-address kron1... --port 8000

# Phone 2 — same LAN, no PC
./target/release/kron-phone --mine --reward-address kron1... --port 8000 --bootstrap <PHONE1_IP>:8000
```

Hub without mining:

```bash
./target/release/kron-phone --hub --port 8000
./target/release/kron-phone --hub --port 8000 --bootstrap <PHONE1_IP>:8000
```

Optional explorer on the phone: add `--explorer-port 8080`.

Other commands:

```bash
./target/release/kron-phone --generate-wallet --data-dir kron-phone
./target/release/kron-phone --show-mnemonic --data-dir kron-phone
./target/release/kron-phone credit --to kron1... --amount 1.0 --data-dir kron-phone
```

`credit` is a local faucet on that phone’s data-dir. It is **not** minted supply.

Default data-dir for `kron-phone` is `./kron-phone` (wallet seed, mnemonic, DAG WAL).

## Two phones, no PC

1. Find Phone 1’s LAN IP (`ip addr` or Wi‑Fi settings).
2. Start Phone 1 on port **8000**.
3. Start Phone 2 with `--bootstrap <PHONE1_IP>:8000`.
4. They exchange vertices over `kron-mesh/1`. The PC can stay off.

## Windows PC (read-only explorer only)

The PC is **not** the network. `kron-node` on x86 is forced read-only. `--mine` is rejected.

```powershell
cargo build --release --bin kron-node
.\target\release\kron-node.exe --follow <PHONE_IP>:8000 --explorer-port 8080 --read-only
```

Open http://127.0.0.1:8080

Default data-dir on Windows: `%APPDATA%\KRON\gateway-8000` (or `gateway-<port>`). Override with `--data-dir DIR`.

On an ARM phone, `kron-node --port 8000` is a full hub (WAL + P2P). Pair it with `kron-phone` to mine, or use `kron-phone` alone (node + miner in one process).

## Wallet broadcast

The desktop wallet (`kron-wallet`) signs a vertex and sends it to **`KRON_GATEWAY`**.

Default: `127.0.0.1:8000`. Point it at a **phone**, not a required PC:

```powershell
$env:KRON_GATEWAY = "<PHONE_IP>:8000"
cargo run --release -p kron-wallet
```

Wallet file on Windows: `%APPDATA%\KRON\wallet.json` (never commit it).

## Build

```bash
cargo test --workspace
cargo build --release --bin kron-phone      # Termux: node + miner
cargo build --release --bin kron-node       # ARM hub, or Windows viewer
cargo build --release --bin kron-phone-miner # optional attach-only miner
cargo build --release -p kron-wallet        # optional desktop GUI
```

`kron-phone-miner` attaches to an existing phone hub (`--phone --reward-address kron1... --node <PHONE_IP>:8000`). Prefer `kron-phone` so the node and miner share one process.

## Ports and data-dir

| Port | Role |
| --- | --- |
| **8000** | Mesh / P2P listen (`--port`, default) |
| **8080** | Explorer HTTP (`--explorer-port`; default on `kron-node`) |

| Binary | Default `--data-dir` |
| --- | --- |
| `kron-phone` | `./kron-phone` |
| `kron-phone-miner` | `./kron-phone-miner` |
| `kron-node` | `%APPDATA%\KRON\gateway-<port>` (Windows) |

Secrets written there: `wallet.seed`, `wallet.mnemonic`, `identity.seed`. Do not copy them into git.

## Security

- Write the **24-word** phrase on paper. Do not screenshot it or share it.
- Do not commit `wallet.json`, `identity.seed`, `wallet.seed`, `wallet.mnemonic`, `.env`, or AppData copies.
- Anyone with the phrase can spend the `kron1` address.
- Mining and hub attach require a real phone ARM profile. x86 hosts are refused.

## Conflict rule

Same-sender spends that cannot both be true: **higher cumulative weight wins**; equal weight → **greater tx-id bytes**. The loser is stored as an orphan and does not change balances.
