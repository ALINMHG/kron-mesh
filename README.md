# KRON Mesh

Phone-only DAG mesh. **Phones mine.** A paid VPS is the public entry (gossip relay + explorer). There are no blocks. A Windows PC is an optional read-only explorer.

- Addresses: `kron1...` (NIST ML-DSA-44)
- **Mesh ID:** `fdxx:…` ULA from SHA-256(ML-DSA pubkey) — overlay identity, **not** a public IP
- **Public hub:** `144.91.105.244:8000` (paid VPS). Explorer: http://144.91.105.244:8080
- Fee: **0.001 KRON** per user transaction
- Mint: **0.1 KRON** per confirmed tx, **80% miner / 20% relays**
- Cap: **24,000,000 KRON**, premine **0**
- Halving: every **126,144,000** confirmed txs
- Wire: `kron-mesh/1` (`SyncInventory` / Have / Need / `DagTransaction`)

Same Wi‑Fi phones auto-find each other (LAN UDP beacon). Different networks join via the VPS. x86 mining is refused at runtime. The VPS **never mines**.

## VPS install (hub)

On Ubuntu. This process does **not** mine. Listen without `--follow` is hub mode (`--hub` is an alias). Binds `0.0.0.0:8000` (mesh) and `0.0.0.0:8080` (explorer).

Already have `~/kron-mesh`? Do **not** clone again:

```bash
cd ~/kron-mesh
git pull
cargo build --release -p new-blockchain
tmux kill-session -t kron 2>/dev/null; tmux new -s kron
./target/release/kron-node --hub --port 8000 --explorer-port 8080 --data-dir /var/lib/kron
```

First time only (empty home directory):

```bash
sudo apt-get update && sudo apt-get install -y git build-essential pkg-config tmux ufw
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
git clone https://github.com/ALINMHG/kron-mesh.git
cd kron-mesh
cargo build --release -p new-blockchain
sudo mkdir -p /var/lib/kron
sudo ufw allow 8000/tcp && sudo ufw allow 8080/tcp && sudo ufw reload
tmux new -s kron
sudo ./target/release/kron-node --hub --port 8000 --explorer-port 8080 --data-dir /var/lib/kron
```

Detach tmux: `Ctrl+B` then `D`. Reattach: `tmux attach -t kron`.

Explorer: **http://144.91.105.244:8080** (never `http://0.0.0.0:8080`). Do not open `:8000` in a browser.

Also allow TCP 8000 and 8080 in the Contabo/Hetzner panel, not only `ufw`.

## Termux install (phone miner)

Already have `~/kron-mesh`? Do **not** clone again:

```bash
cd ~/kron-mesh
git pull
cargo build --release -p new-blockchain
pkill -f kron-phone
./target/release/kron-phone --mine --reward-address kron1...
```

First time only:

```bash
pkg install rust git
git clone https://github.com/ALINMHG/kron-mesh.git
cd kron-mesh
cargo build --release -p new-blockchain
./target/release/kron-phone --mine --reward-address kron1...
```

No `--bootstrap` is required. After local listen the miner dials **144.91.105.244:8000**. Success:

```
[KRON MINER] connecting to hub 144.91.105.244:8000 ...
[KRON MINER] connected to hub
```

Override with `--bootstrap host:port` or `KRON_BOOTSTRAP`. LAN-only: `--no-bootstrap`.

No flags opens a menu: **1** generate a `kron1` address + 24-word phrase (wallet only). **2** mine (prompts for the reward address, binds `:8000`, dials the VPS).

### Cloud firewall (Contabo / Hetzner)

`ufw` on the VM is not enough. Contabo Customer Control Panel and Hetzner Cloud Console have a **separate** inbound firewall. If 8000/8080 are not allowed there, the public internet never reaches `kron-node` even when `ss -lntp` shows `0.0.0.0:8080`.

1. Panel → firewall / network → inbound **TCP 8000** and **TCP 8080** (IPv4). Attach the rule set to this VPS.
2. Then on the VM:

```bash
sudo ufw allow 8000/tcp
sudo ufw allow 8080/tcp
sudo ufw reload
```

A **timeout** from home usually means the panel (or ufw) is dropping packets. **Connection refused** usually means packets reached the VPS but nothing is listening — the hub was never started, or it died when the SSH window closed.

### Keep the hub alive after PuTTY closes

A foreground `kron-node` in a normal PuTTY session dies on disconnect (SIGHUP). Use **systemd** (survives reboot) or **tmux** (survives SSH close only).

Install once (Ubuntu, after you can `sudo`):

```bash
git clone https://github.com/ALINMHG/kron-mesh.git
cd kron-mesh
cargo build --release --bin kron-node
sudo mkdir -p /var/lib/kron
sudo useradd --system --home /var/lib/kron --shell /usr/sbin/nologin kron || true
sudo cp target/release/kron-node /usr/local/bin/kron-node
sudo cp deploy/kron-hub.service /etc/systemd/system/kron-hub.service
sudo chown -R kron:kron /var/lib/kron
sudo ufw allow 8000/tcp
sudo ufw allow 8080/tcp
sudo ufw reload
sudo systemctl daemon-reload
sudo systemctl enable --now kron-hub
sudo systemctl status kron-hub --no-pager
```

Logs: `journalctl -u kron-hub -f`

### PuTTY: tmux (if you are not using systemd yet)

After login, paste this. `Ctrl+B` then `D` detaches. Closing PuTTY after that leaves the hub running.

```bash
sudo apt-get update && sudo apt-get install -y tmux
cd ~/kron-mesh
tmux new -s kron
sudo mkdir -p /var/lib/kron
sudo ./target/release/kron-node --hub --port 8000 --explorer-port 8080 --data-dir /var/lib/kron
```

If `tmux new -s kron` prints `duplicate session: kron`, a session already exists (often from a previous SSH). Do **not** start a second `kron-node` in the raw PuTTY shell — that dies on disconnect.

```bash
tmux attach -t kron          # resume the existing session
# or a second session:
tmux new -s kron2
# or replace the old one:
tmux kill-session -t kron
tmux new -s kron
```

Detach with `Ctrl+B` then `D`. Keep the process running in tmux (or systemd). Reattach later: `tmux attach -t kron`

One-shot without tmux (still dies on reboot):

```bash
sudo mkdir -p /var/lib/kron
nohup sudo ./target/release/kron-node --hub --port 8000 --explorer-port 8080 --data-dir /var/lib/kron > /tmp/kron-hub.log 2>&1 &
disown
```

Binds `0.0.0.0:8000` (P2P) and `0.0.0.0:8080` (explorer). Persist DAG WAL under `--data-dir`. Gossip vertices between connected phones. **Never** pass `--mine`.

Public URL: http://144.91.105.244:8080

## Termux (phones mine)

```bash
pkg install rust git
git clone https://github.com/ALINMHG/kron-mesh.git
cd kron-mesh
sh termux-build.sh
# or, from this repo root only (there is no kron-phone/ crate):
cargo build --release -p new-blockchain
./target/release/kron-phone --mine --reward-address kron1...
```

The miner dials `144.91.105.244:8000` after listen. Override with `--bootstrap host:port` or `KRON_BOOTSTRAP`. LAN-only: `--no-bootstrap`.

`--bin` is a **cargo** flag, not a `kron-phone` flag. Do not type `bin` or `--bin` after `./kron-phone`. The package name is `new-blockchain`; the binary is `./target/release/kron-phone`.

No flags opens a menu:

1. **Generate KRON address** — prints a `kron1...` address and a **24-word** passphrase. Wallet only: it does **not** bind `:8000`. Write the words down; they are not shown again (use `--show-mnemonic` only if you must).
2. **Mine** — prompts for a `kron1` reward address (paste the address only; whitespace/newlines are trimmed). The node stays running in the **same process** and binds P2P once, then dials the VPS. `--no-discovery` only disables LAN beacons. `--no-bootstrap` stays LAN-only.

Flags (all three mine forms are equivalent):

```bash
# Phone — node + miner; joins VPS by default
./target/release/kron-phone --mine --reward-address kron1... --port 8000
./target/release/kron-phone --mine --miner-address kron1... --port 8000
./target/release/kron-phone --mine kron1... --port 8000

# Explicit VPS (same as default)
./target/release/kron-phone --mine --reward-address kron1... --bootstrap 144.91.105.244:8000

# Same Wi‑Fi: phones also auto-find via UDP beacon on :8001 (no PHONE_IP).
# Disable beacons: --no-discovery
```

`--miner-address` is an alias of `--reward-address`. A bare `kron1...` after `--mine` is the reward address, not a flag. Menu option **2** prompts and trims the paste (quotes / newlines); do not type the address as a CLI flag.

Hub without mining (still a phone; still defaults to the VPS):

```bash
./target/release/kron-phone --hub --port 8000
./target/release/kron-phone --hub --port 8000 --bootstrap 144.91.105.244:8000
```

Mining and hub serve a read-only explorer on `0.0.0.0:8080` by default (override with `--explorer-port`). On the phone, that is a LAN URL. The **unique public** explorer is http://144.91.105.244:8080

Other commands:

```bash
./target/release/kron-phone --generate-wallet --data-dir kron-phone
./target/release/kron-phone --show-mnemonic --data-dir kron-phone
./target/release/kron-phone credit --to kron1... --amount 1.0 --data-dir kron-phone
```

`credit` is a local faucet on that phone’s data-dir. It is **not** minted supply.

Default data-dir for `kron-phone` is `./kron-phone` (wallet seed, mnemonic, DAG WAL).

## Unique mesh ID, not a public IP

Each node prints:

```
[KRON NODE] P2P listening 0.0.0.0:8000
[KRON NODE] Mesh ID: fd12:xxxx:...
[KRON NODE] kron1...
[KRON NODE] LAN: 192.168.x.x:8000
[KRON NODE] peer discovered kron1... at 192.168.x.x:8000
[KRON EXPLORER] http://192.168.x.x:8080
```

**Mesh ID** = first 15 bytes of SHA-256(versioned ML-DSA pubkey), prefixed `fd`, shown as IPv6 ULA. Routing is keyed by that overlay id, not by `192.168`. Same Wi‑Fi phones beacon on UDP `p2p_port+1` and TCP-connect without typing an IP.

Internet-wide reach uses the paid VPS `144.91.105.244:8000`. A Rust repo cannot allocate a global IPv4; this one is the VPS you already pay for.

## Two phones

**Same Wi‑Fi:** both `--mine`. LAN discovery finds the other phone. They also join `144.91.105.244:8000` so the global mesh stays in sync.

**Different Wi‑Fi:** default/VPS bootstrap is enough. No PC required.

## Windows PC (read-only explorer only)

The home PC is **not** the network. `kron-node` on x86 **without `--follow`** is a hub/relay (same as `--hub`). A Windows viewer must pass `--follow` (and usually `--read-only`). `--mine` is rejected.

Easiest: open http://144.91.105.244:8080

Or follow the VPS (or a phone LAN IP):

```powershell
cargo build --release --bin kron-node
.\target\release\kron-node.exe --follow 144.91.105.244:8000 --explorer-port 8080 --read-only
```

Open http://127.0.0.1:8080

Default data-dir on Windows: `%APPDATA%\KRON\gateway-8000` (or `gateway-<port>`). Override with `--data-dir DIR`.

On an ARM phone, `kron-node --port 8000` is a full hub (WAL + P2P). Pair it with `kron-phone` to mine, or use `kron-phone` alone (node + miner in one process).

## Wallet broadcast

The desktop wallet (`kron-wallet`) signs a vertex and sends it to **`KRON_GATEWAY`**.

Point it at the VPS (or a phone):

```powershell
$env:KRON_GATEWAY = "144.91.105.244:8000"
cargo run --release -p kron-wallet
```

Wallet file on Windows: `%APPDATA%\KRON\wallet.json` (never commit it).

## Build

```bash
cargo test --workspace
cargo build --release -p new-blockchain     # Termux: kron-phone + kron-node (no --bin)
cargo build --release --bin kron-node       # VPS --hub, ARM hub, or Windows viewer
cargo build --release --bin kron-phone-miner # optional attach-only miner
cargo build --release -p kron-wallet        # optional desktop GUI
```

`kron-phone-miner` attaches to an existing phone hub (`--phone --reward-address kron1... --node <PHONE_IP>:8000`, or `--miner-address` / positional `kron1...`). Prefer `kron-phone` so the node and miner share one process.

## Ports and data-dir

| Port | Role |
| --- | --- |
| **8000** | Mesh / P2P listen (`--port`, default). VPS: `144.91.105.244:8000` — not HTTP |
| **8001** | LAN discovery UDP beacon (`p2p_port + 1`) |
| **8080** | Explorer HTTP. Public: http://144.91.105.244:8080 |

If the public explorer does not load: confirm `kron-hub` / `kron-node --hub` is still running (`systemctl status kron-hub` or `tmux attach -t kron`), open **:8080** not **:8000**, and allow TCP 8000/8080 in **both** ufw and the Contabo/Hetzner panel.

If error 98 (`Address already in use`), stop the leftover process: `pkill -f kron-phone`. Then mine again, or use `--port 8001`. Do not auto-increment unless you pass `--port-auto`.

| Binary | Default `--data-dir` |
| --- | --- |
| `kron-phone` | `./kron-phone` |
| `kron-phone-miner` | `./kron-phone-miner` |
| `kron-node` | `%APPDATA%\KRON\gateway-<port>` (Windows); `/var/lib/kron` on the VPS if you pass it |

Secrets written there: `wallet.seed`, `wallet.mnemonic`, `identity.seed`. Do not copy them into git.

Bootstrap config (no SSH, no passwords in this repo):

| Source | Example |
| --- | --- |
| Default | `144.91.105.244:8000` |
| Env | `KRON_BOOTSTRAP=144.91.105.244:8000` |
| File | `bootstrap.txt` (repo copy already has the VPS) |
| CLI | `--bootstrap 144.91.105.244:8000` |

## Security

- Write the **24-word** phrase on paper. Do not screenshot it or share it.
- Do not commit `wallet.json`, `identity.seed`, `wallet.seed`, `wallet.mnemonic`, `.env`, or AppData copies.
- Anyone with the phrase can spend the `kron1` address.
- Mining requires a real phone ARM profile. x86 hosts cannot mine. `kron-node --hub` on the VPS is a relay only.

## Conflict rule

Same-sender spends that cannot both be true: **higher cumulative weight wins**; equal weight → **greater tx-id bytes**. The loser is stored as an orphan and does not change balances.
