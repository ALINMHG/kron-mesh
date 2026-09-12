@echo off
cd /d "%~dp0"
title KRON launcher
echo Starting KRON Node (P2P + explorer + mining thread^)...
call "%~dp0Ensure-KRON-Node.bat"
if errorlevel 1 (
  echo [KRON ERROR] Could not start the node on port 8000.
  echo Start the node first: double-click KRON Node, or use Start KRON.bat
  pause
  exit /b 1
)
echo Starting KRON Miner window...
if exist "%~dp0kron-miner.exe" (
  start "KRON Miner" "%~dp0kron-miner.exe" --node 127.0.0.1:8000 --data-dir kron-miner
) else (
  start "KRON Miner" cmd /k ""%~dp0Start KRON Miner.bat""
)
echo.
echo Two windows should be open:
echo   1. KRON Node     — keep this running
echo   2. KRON Miner    — paste kron1 address, then Start Mining
echo Explorer: http://127.0.0.1:8080
echo Wallet is not opened.
echo.
exit /b 0
