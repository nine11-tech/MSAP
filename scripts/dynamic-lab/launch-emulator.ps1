param(
    [string]$AvdName = $(if ($env:MSAP_AVD_NAME) { $env:MSAP_AVD_NAME } else { "Lab-Root" }),
    [string]$Snapshot = $(if ($env:MSAP_INSTRUMENTED_SNAPSHOT) { $env:MSAP_INSTRUMENTED_SNAPSHOT } else { "msap-instrumented-base" }),
    [bool]$NoSnapshotSave = $true,
    [string]$EmulatorPath = ""
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($EmulatorPath)) {
    $sdk = if ($env:ANDROID_SDK_WIN -and $env:ANDROID_SDK_WIN -match "^[A-Za-z]:\\") {
        $env:ANDROID_SDK_WIN
    } else {
        "C:\Users\lenovo\AppData\Local\Android\Sdk"
    }

    $EmulatorPath = if ($env:EMULATOR_WIN -and $env:EMULATOR_WIN -match "^[A-Za-z]:\\") {
        $env:EMULATOR_WIN
    } else {
        Join-Path $sdk "emulator\emulator.exe"
    }
}

if (-not (Test-Path -LiteralPath $EmulatorPath -PathType Leaf)) {
    throw "emulator.exe was not found: $EmulatorPath"
}

$arguments = @(
    "-avd", $AvdName,
    "-snapshot", $Snapshot
)

if ($NoSnapshotSave) {
    $arguments += "-no-snapshot-save"
}

$arguments += @(
    "-no-boot-anim",
    "-netdelay", "none",
    "-netspeed", "full"
)

$quotedArgs = $arguments | ForEach-Object {
    if ($_ -match "\s") { '"' + $_ + '"' } else { $_ }
}

Write-Host "Emulator command:"
Write-Host ('"{0}" {1}' -f $EmulatorPath, ($quotedArgs -join " "))

Start-Process `
    -FilePath $EmulatorPath `
    -ArgumentList $arguments `
    -WorkingDirectory "C:\Windows\Temp"
