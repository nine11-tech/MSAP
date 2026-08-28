#Requires -Version 5.1
param(
    [Parameter(Mandatory = $true)][string]$ListenAddress,
    [Parameter(Mandatory = $true)][string]$WslAddress,
    [int]$BridgePort = 27043,
    [int]$AdbForwardPort = 27042
)

$ErrorActionPreference = "Stop"
$RuleName = "MSAP Frida WSL Bridge $BridgePort"

Set-Service -Name iphlpsvc -StartupType Automatic
Start-Service -Name iphlpsvc

& netsh.exe interface portproxy delete v4tov4 `
    "listenaddress=$ListenAddress" `
    "listenport=$BridgePort" | Out-Null

Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule

& netsh.exe interface portproxy add v4tov4 `
    "listenaddress=$ListenAddress" `
    "listenport=$BridgePort" `
    "connectaddress=127.0.0.1" `
    "connectport=$AdbForwardPort" `
    "protocol=tcp"

if ($LASTEXITCODE -ne 0) {
    throw "netsh portproxy creation failed."
}

New-NetFirewallRule `
    -DisplayName $RuleName `
    -Direction Inbound `
    -Action Allow `
    -Protocol TCP `
    -LocalAddress $ListenAddress `
    -LocalPort $BridgePort `
    -RemoteAddress $WslAddress `
    -Profile Any | Out-Null

$PortOpen = Test-NetConnection `
    -ComputerName $ListenAddress `
    -Port $BridgePort `
    -InformationLevel Quiet

Write-Host "WINDOWS_HOST_IP=$ListenAddress"
Write-Host "WSL_IP=$WslAddress"
Write-Host "WINDOWS_BRIDGE_OPEN=$PortOpen"

if (-not $PortOpen) {
    Write-Warning "The bridge rule is configured but the ADB/Frida target is not listening yet."
}
