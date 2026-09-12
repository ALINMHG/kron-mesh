@echo off
cd /d "%~dp0"
title KRON Miner
echo.
echo  KRON mining is phone-only. Use Termux: kron-phone-miner --phone
echo  The Windows miner does not submit solutions.
echo.
echo  pkg install rust git
echo  cargo build --release --bin kron-phone-miner
echo  ./target/release/kron-phone-miner --phone --node ^<PC_LAN_IP^>:8000 --reward-address kron1...
echo.
pause
