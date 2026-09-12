#!/data/data/com.termux/files/usr/bin/sh
set -e
cd "$(dirname "$0")"
cargo build --release -p new-blockchain
echo "Run: ./target/release/kron-phone --mine --reward-address kron1..."
