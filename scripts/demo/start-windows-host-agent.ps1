#Requires -Version 5.1
<#
.SYNOPSIS
  Start the MSAP Windows-native Dynamic Host Agent for the demo lab.

.DESCRIPTION
  Verifies adb.exe, the Android emulator, and the Frida client, checks whether
  the Frida port (27042) is stale or busy, then starts the Host Agent and prints
  the URL the backend should use. It never prints tokens, credentials, .env
  values, or raw environment variables.

.EXAMPLE
  .\scripts\demo\start-windows-host-agent.ps1

.EXAMPLE
  .\scripts\demo\start-windows-host-agent.ps1 -Port 8766
#>
param(
    [string]$AdbPath = "",
    [string]$FridaPath = "",
    [string]$Serial = "",
    [string]$Host = "0.0.0.0",
    [int]$Port = 8765,
    [string]$BackendDir = ""
)

$ErrorActionPreference = "Stop"

function Write-Status { param([string]$Message) Write-Host "[msap] $Message" }
function Write-Ok { param([string]$Message) Write-Host "[msap] OK - $Message" }
function Write-Warn { param([string]$Message) Write-Host "[msap] WARN - $Message" -ForegroundColor Yellow }
function Write-Fail { param([string]$Message) Write-Host "[msap] FAIL - $Message" -ForegroundColor Red }

$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not $BackendDir) { $BackendDir = Join-Path $RepoRoot "backend" }

function Read-EnvFile {
    $envFile = Join-Path $RepoRoot ".env"
    if (-not (Test-Path $envFile)) { return @{} }
    $values = @{}
    Get-Content $envFile | ForEach-Object {
        $line = $_.Trim()
        if ($line -and -not $line.StartsWith("#") -and $line.Contains("=")) {
            $parts = $line.Split("=", 2)
            $values[$parts[0].Trim()] = $parts[1].Trim().Trim('"').Trim("'")
        }
    }
    return $values
}

function Resolve-AdbPath {
    param([hashtable]$EnvValues)
    if ($AdbPath) {
        if (Test-Path $AdbPath) { return (Resolve-Path $AdbPath).Path }
        Write-Fail "Configured ADB path does not exist: $AdbPath"
        return ""
    }
    $candidates = @()
    if ($EnvValues["MSAP_WINDOWS_ADB_PATH"]) { $candidates += $EnvValues["MSAP_WINDOWS_ADB_PATH"] }
    if ($EnvValues["MSAP_WINDOWS_ANDROID_SDK_ROOT"]) {
        $candidates += Join-Path $EnvValues["MSAP_WINDOWS_ANDROID_SDK_ROOT"] "platform-tools\adb.exe"
    }
    $candidates += "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe"
    $candidates += "$env:USERPROFILE\AppData\Local\Android\Sdk\platform-tools\adb.exe"
    $candidates += (Get-Command adb.exe -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Source)
    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path $candidate)) { return (Resolve-Path $candidate).Path }
    }
    return ""
}

function Resolve-FridaPath {
    param([hashtable]$EnvValues)
    if ($FridaPath) {
        if (Test-Path $FridaPath) { return (Resolve-Path $FridaPath).Path }
        Write-Warn "Configured Frida path does not exist: $FridaPath"
        return ""
    }
    if ($EnvValues["MSAP_WINDOWS_FRIDA_PATH"] -and (Test-Path $EnvValues["MSAP_WINDOWS_FRIDA_PATH"])) {
        return (Resolve-Path $EnvValues["MSAP_WINDOWS_FRIDA_PATH"]).Path
    }
    $command = Get-Command frida -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($command) { return $command.Source }
    $venvFrida = Join-Path $BackendDir ".venv\Scripts\frida.exe"
    if (Test-Path $venvFrida) { return (Resolve-Path $venvFrida).Path }
    return ""
}

function Find-Python {
    $venvPython = Join-Path $BackendDir ".venv\Scripts\python.exe"
    if (Test-Path $venvPython) { return (Resolve-Path $venvPython).Path }
    $command = Get-Command python.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($command) { return $command.Source }
    return ""
}

$EnvValues = Read-EnvFile
if (-not $Serial) { $Serial = if ($EnvValues["MSAP_ANDROID_EMULATOR_SERIAL"]) { $EnvValues["MSAP_ANDROID_EMULATOR_SERIAL"] } else { "emulator-5554" } }
$Token = $EnvValues["MSAP_DYNAMIC_HOST_AGENT_TOKEN"]

Write-Status "MSAP Windows Dynamic Lab (lab_mode=WINDOWS_HOST_AGENT)"
Write-Status "Serial: $Serial"

if (-not $Token) {
    Write-Warn "MSAP_DYNAMIC_HOST_AGENT_TOKEN is not set in .env. Generate one and add it before starting the backend."
}

# 1. adb.exe
$adb = Resolve-AdbPath -EnvValues $EnvValues
if (-not $adb) {
    Write-Fail "adb.exe not found. Set MSAP_WINDOWS_ADB_PATH or install Android SDK platform-tools."
    Write-Fail "Example: C:\Users\<user>\AppData\Local\Android\Sdk\platform-tools\adb.exe"
    exit 1
}
Write-Ok "adb.exe: $adb"
$adbVersion = & $adb version 2>$null | Select-Object -First 1
Write-Status "adb: $adbVersion"

# 2. emulator reachable
Write-Status "Checking emulator $Serial..."
$deviceLines = (& $adb devices 2>$null)
$emulatorOk = $false
foreach ($line in $deviceLines) {
    if ($line -match "^\s*$([regex]::Escape($Serial))\s+device\s*$") { $emulatorOk = $true }
}
if (-not $emulatorOk) {
    Write-Fail "Emulator $Serial is not connected (state=device). Start the Android emulator and retry."
    exit 1
}
Write-Ok "Emulator connected: $Serial"

# 3. Frida client
$frida = Resolve-FridaPath -EnvValues $EnvValues
if (-not $frida) {
    Write-Fail "Frida client not found. Set MSAP_WINDOWS_FRIDA_PATH or install frida-tools (pip install frida-tools)."
    exit 1
}
Write-Ok "Frida client: $frida"

# 4. Frida port 27042 stale/busy check (diagnostic only; never kill blindly)
$fridaServerPid = (& $adb -s $Serial shell "pidof msap-frida-server" 2>$null | Select-Object -First 1).Trim()
$localListener = Get-NetTCPConnection -LocalPort 27042 -ErrorAction SilentlyContinue | Select-Object -First 1
if ($fridaServerPid) {
    Write-Warn "A managed Frida server is running on the emulator (pid $fridaServerPid)."
    Write-Status "Recovery (safe, only the managed msap-frida-server):"
    Write-Status "  adb -s $Serial shell kill $fridaServerPid"
    Write-Status "  adb -s $Serial shell rm -f /data/local/tmp/msap-frida-server.pid"
} elseif ($localListener) {
    Write-Warn "Local TCP port 27042 is already in use (pid $($localListener.OwningProcess))."
    Write-Status "Recovery: identify the owning process with 'Get-Process -Id $($localListener.OwningProcess)' and close only that stale Frida listener, then retry."
} else {
    Write-Ok "Frida port 27042 is free."
}

# 5. start Host Agent
$python = Find-Python
if (-not $python) {
    Write-Fail "Python not found. Create the backend venv or add python.exe to PATH."
    exit 1
}
Write-Ok "Python: $python"
$manage = Join-Path $BackendDir "manage.py"
if (-not (Test-Path $manage)) {
    Write-Fail "manage.py not found at $manage"
    exit 1
}

$env:MSAP_DYNAMIC_HOST_AGENT_ENABLED = "true"
$env:MSAP_DYNAMIC_HOST_AGENT_BIND = $Host
$env:MSAP_DYNAMIC_HOST_AGENT_PORT = "$Port"
if ($Token) { $env:MSAP_DYNAMIC_HOST_AGENT_TOKEN = $Token }
if ($adb) { $env:ADB_WIN = $adb }
if ($Serial) { $env:MSAP_ANDROID_SERIAL = $Serial }

Write-Status "Starting Host Agent on $Host`:$Port ..."
$logDir = Join-Path $RepoRoot ".runtime\msap-demo\logs"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$logFile = Join-Path $logDir "host-agent-windows.log"
$proc = Start-Process -FilePath $python -ArgumentList @($manage, "run_dynamic_host_agent", "--host", $Host, "--port", "$Port") -WorkingDirectory $BackendDir -RedirectStandardOutput $logFile -RedirectStandardError $logFile -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 2
if ($proc.HasExited) {
    Write-Fail "Host Agent exited early. See $logFile"
    exit 1
}
Write-Ok "Host Agent started (pid $($proc.Id)). Log: $logFile"

# 6. print backend URL
Write-Host ""
Write-Host "HOST_AGENT_WINDOWS_RESULT=PASS"
Write-Host "Configure the backend (Docker/WSL) with one of these URLs:"
Write-Host "  http://127.0.0.1:$Port   (backend running directly on this Windows host)"
Write-Host "  http://host.docker.internal:$Port   (Docker on the same Windows machine)"
Write-Host "  http://<Windows host IP>:$Port   (Docker/WSL on another machine)"
Write-Host "Set MSAP_DYNAMIC_HOST_AGENT_URL to the URL and restart the backend/worker."
Write-Host "Verify with: python manage.py demo_health_check"