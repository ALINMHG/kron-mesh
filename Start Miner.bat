@echo off
cd /d "%~dp0"
echo.
echo  KRON mining is phone-only.
echo  The Windows miner is disabled and will not submit solutions.
echo.
echo  On Termux (same LAN as this PC):
echo    pkg install rust git
echo    cargo build --release --bin kron-phone-miner
echo    ./target/release/kron-phone-miner --phone --node ^<PC_LAN_IP^>:8000 --reward-address kron1...
echo.
echo  Keep the node running: Start Node.bat  (listens 0.0.0.0:8000)
echo.
pause
