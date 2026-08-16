# MSAP Dynamic Lab Reproducibility

This folder contains repository-managed scripts for restoring and validating the
local MSAP dynamic Android lab after a PC reboot, emulator restart, WSL IP
change, bridge timeout, or future workstation drift.

The scripts validate the known-good lab contract:

- WSL2 Ubuntu operator shell
- Windows Android SDK mounted under WSL
- `Lab-Root` API 35 x86_64 userdebug AVD
- clean snapshot `msap-clean-base`
- instrumented snapshot `msap-instrumented-base`
- rooted adbd with SELinux `Enforcing`
- Frida client/server `17.16.4`
- isolated mitmproxy `12.2.3` virtual environment
- runtime-only platform CA overlay, with no permanent system or APEX CA changes

## Local-Only State

The repository intentionally does not contain private mitmproxy CA material,
the generated public MSAP CA certificate, emulator snapshots, APKs, flow files,
screenshots, runtime evidence, credentials, logs, or assessed application data.
Scripts reference those local paths and validate their presence or hashes, but
they never copy sensitive local material into the repository.

Snapshots are also local-only. Android emulator snapshots can be large, host
specific, and may contain device state. The scripts check that the expected
snapshot exists and can be loaded, but they never delete, export, or rewrite
snapshots.

Chrome is not used as the platform TLS trust authority because modern Chrome on
Android can use its own root-store behavior. The platform TLS probe uses a
temporary native Android app that relies on `HttpsURLConnection`, which exercises
the Android platform trust path.

## Configuration

Defaults live in `lib/common.sh` and are documented in
`msap-dynamic-lab.env.example`. To override them:

```bash
cp scripts/dynamic-lab/msap-dynamic-lab.env.example .msap-dynamic-lab.local.env
```

The local env file is ignored by Git. The scripts also load
`~/.local/bin/msap-dynamic-env` when present.

## Typical Commands

Start the emulator from WSL using the instrumented snapshot:

```bash
scripts/dynamic-lab/launch-emulator-from-wsl.sh
```

Restore the validated instrumented snapshot:

```bash
scripts/dynamic-lab/restore-instrumented-snapshot.sh
```

Run the main preflight:

```bash
scripts/dynamic-lab/preflight.sh
```

Refresh the Windows-to-WSL Frida bridge after a WSL IP change or timeout:

```bash
scripts/dynamic-lab/refresh-frida-bridge.sh
```

Run Frida and mitmproxy smoke checks:

```bash
scripts/dynamic-lab/frida-smoke.sh
scripts/dynamic-lab/mitmproxy-smoke.sh
```

Run the aggregated health check:

```bash
scripts/dynamic-lab/lab-health.sh
```

The clean-baseline default rejects every third-party package. When health is
checked after an auditor-authorized target has intentionally been installed,
allow only that exact package for the preflight invocation:

```bash
MSAP_PREFLIGHT_ALLOWED_THIRD_PARTY_PACKAGES=owasp.sat.agoat \
  scripts/dynamic-lab/lab-health.sh
```

Any other third-party package still fails preflight. Snapshot restoration and
cleanup verification remain strict zero-package checks.

Run full platform TLS verification when you are ready for a temporary APK,
runtime namespace overlay injection, and emulator reboot during cleanup:

```bash
scripts/dynamic-lab/platform-tls-probe.sh
```

Clean transient state:

```bash
scripts/dynamic-lab/cleanup-runtime-state.sh
scripts/dynamic-lab/cleanup-runtime-state.sh --clear-logcat
```

## Recovery Guide

PC reboot:
Start WSL, launch the emulator with `launch-emulator-from-wsl.sh`, then run
`restore-instrumented-snapshot.sh` and `preflight.sh`.

WSL IP change:
Run `refresh-frida-bridge.sh`. Windows UAC may appear because the helper updates
a scoped Windows portproxy/firewall rule.

Emulator restart:
Run `restore-instrumented-snapshot.sh`, then `preflight.sh`.

Bridge timeout:
Run `refresh-frida-bridge.sh`, then `frida-smoke.sh`.

Missing `android.jar`:
Install the Android platform matching `MSAP_ANDROID_API_LEVEL` in Android Studio
or `sdkmanager`, then rerun `preflight.sh`.

Frida version mismatch:
Recreate the local Frida helper state for `MSAP_EXPECTED_FRIDA_VERSION`, then
rerun `preflight.sh`. The repository does not store Frida binaries.

Proxy left enabled:
Run `cleanup-runtime-state.sh`; it restores Android global proxy to `:0`.

Temporary trust-probe APK left installed:
Run `cleanup-runtime-state.sh`; it force-stops and uninstalls
`tech.nine11.msap.trustprobe`.

## Script Results

Successful scripts end with explicit result markers:

- `PREFLIGHT_RESULT=PASS`
- `RESTORE_INSTRUMENTED_SNAPSHOT_RESULT=PASS`
- `FRIDA_BRIDGE_REFRESH_RESULT=PASS`
- `FRIDA_SMOKE_RESULT=PASS`
- `MITMPROXY_SMOKE_RESULT=PASS`
- `PLATFORM_TLS_PROBE_RESULT=PASS`
- `CLEANUP_RUNTIME_STATE_RESULT=PASS`
- `DYNAMIC_LAB_HEALTH_RESULT=PASS`
