@echo off
cd /d "%~dp0"
if not exist "%~dp0kron-node.exe" (
  echo kron-node.exe not found in this folder.
  pause
  exit /b 1
)
REM Windows is a read-only explorer. Phones are the network.
REM Add --follow PHONE_IP:8000 to index a live phone hub.
start "KRON Explorer" "%~dp0kron-node.exe" --read-only --explorer-port 8080
echo Read-only explorer: http://127.0.0.1:8080
echo Follow a phone: kron-node.exe --follow PHONE_IP:8000 --explorer-port 8080 --read-only
