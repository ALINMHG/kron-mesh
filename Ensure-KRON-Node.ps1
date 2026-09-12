# Ensure a KRON node is listening on 127.0.0.1:8000.
# Starts Start KRON Node.bat in a new window when the port is closed.
$ErrorActionPreference = "Continue"
$port = 8000
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

function Test-KronPort {
    param([int]$Port)
    $client = $null
    try {
        $client = [System.Net.Sockets.TcpClient]::new()
        $iar = $client.BeginConnect("127.0.0.1", $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne(400)) {
            $client.Close()
            return $false
        }
        $client.EndConnect($iar) | Out-Null
        $client.Close()
        return $true
    } catch {
        if ($null -ne $client) {
            try { $client.Close() } catch { }
        }
        return $false
    }
}

if (Test-KronPort -Port $port) {
    Write-Host "[KRON] Node already listening on 127.0.0.1:$port"
    exit 0
}

$exe = Join-Path $here "kron-node.exe"
if (-not (Test-Path -LiteralPath $exe)) {
    Write-Host "[KRON ERROR] kron-node.exe not found in this folder."
    exit 1
}

$nodeBat = Join-Path $here "Start KRON Node.bat"
Write-Host "[KRON] Port $port is closed — starting KRON Node..."
if (Test-Path -LiteralPath $nodeBat) {
    Start-Process -FilePath "cmd.exe" -ArgumentList @("/k", "`"$nodeBat`"") -WorkingDirectory $here
} else {
    Start-Process -FilePath $exe -ArgumentList @("--port", "$port", "--explorer-port", "8080", "--data-dir", "kron-data-8000", "--name", "node") -WorkingDirectory $here
}

for ($i = 1; $i -le 60; $i++) {
    Start-Sleep -Seconds 1
    if (Test-KronPort -Port $port) {
        Write-Host "[KRON] Node is listening on 127.0.0.1:$port"
        exit 0
    }
    Write-Host "[KRON] waiting for node at 127.0.0.1:$port (try $i/60)"
}

Write-Host "[KRON ERROR] Node did not open 127.0.0.1:$port."
Write-Host "[KRON ERROR] Start the node first: double-click KRON Node, or use Start KRON.bat"
exit 1
