@echo off
cd /d "%~dp0"
title KRON Node
echo.
echo  KRON Node
echo  P2P        0.0.0.0:8000
echo  Explorer   http://127.0.0.1:8080
echo  Mining     ON  (dedicated thread — node stays up)
echo.
echo  Look for:
echo    [KRON MINER] Miner address = kron1...
echo    [KRON MINER] Mining started
echo.
if not exist "%~dp0kron-node.exe" (
  echo kron-node.exe not found in this folder.
  pause
  exit /b 1
)
"%~dp0kron-node.exe" --port 8000 --explorer-port 8080 --data-dir kron-data-8000 --name node
echo.
echo Node stopped.
pause
