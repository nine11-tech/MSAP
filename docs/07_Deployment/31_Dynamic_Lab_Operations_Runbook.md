# Dynamic Lab Operations Runbook

## Purpose

This runbook is for operators maintaining the validated local MSAP dynamic
Android lab. It covers startup, preflight, smoke tests, cleanup, evidence
locations, troubleshooting, and what to provide for diagnosis.

This runbook does not authorize running arbitrary APKs. Use only APKs that the
organization is authorized to assess. Do not place APK samples, private CA
material, screenshots, proxy flows, credentials, or assessed-app evidence in
Git.

## Prerequisites

| Area | Expected state |
| --- | --- |
| Host | Windows owns Android SDK, emulator binaries, and AVD storage. |
| Linux | WSL2 Ubuntu runs MSAP dynamic-lab scripts and local tooling. |
| Emulator | API 35 x86_64 userdebug emulator with rooted adbd. |
| SELinux | `Enforcing`; do not disable it for MSAP runs. |
| Frida | Client/server `17.16.4`. |
| mitmproxy | `12.2.3` in the dedicated local dynamic-lab virtual environment. |
| Snapshots | `msap-clean-base` and `msap-instrumented-base` exist. |
| CA | Public CA staged for runtime overlay; no permanent CA install. |
| Repository | Scripts under `scripts/dynamic-lab/` are available. |

## Starting the Emulator

Run:

```bash
scripts/dynamic-lab/launch-emulator-from-wsl.sh
```

Expected result:

- Emulator boots as `emulator-5554`.
- ADB can see the device.
- Boot completes before preflight continues.

If the emulator is already running, verify it is the intended AVD before using
it for dynamic analysis.

## Restoring `msap-instrumented-base`

Run:

```bash
scripts/dynamic-lab/restore-instrumented-snapshot.sh
```

Expected baseline:

- Frida binary staged at `/data/local/tmp/msap-frida-server`.
- Public CA staged for runtime overlay.
- Android proxy disabled as `:0`.
- Frida server not left running.
- No target APK installed.
- No temporary trust-probe APK installed.
- SELinux remains `Enforcing`.

## Running Preflight

Run:

```bash
scripts/dynamic-lab/preflight.sh
```

Expected PASS marker:

```text
PREFLIGHT_RESULT=PASS
```

Preflight should validate device reachability, SDK paths, API level, ABI,
rooted adbd, SELinux, snapshot availability, staged CA/public hash expectations,
Frida readiness, mitmproxy readiness, proxy baseline, and absence of permanent
CA drift.

## Refreshing the Frida Bridge After WSL IP Changes

WSL IP addresses can change after host restarts. Refresh the bridge before
Frida smoke tests or dynamic sessions:

```bash
scripts/dynamic-lab/refresh-frida-bridge.sh
```

Expected behavior:

- Script delegates to the local Windows bridge helper.
- It reports the detected WSL IP and gateway.
- It does not disable the Windows firewall globally.

## Running the Frida Smoke Test

Run:

```bash
scripts/dynamic-lab/frida-smoke.sh
```

Expected PASS marker:

```text
FRIDA_SMOKE_RESULT=PASS
```

The smoke test should confirm Frida client/server compatibility at version
`17.16.4` and basic connectivity through the bridge.

## Running the mitmproxy Smoke Test

Run:

```bash
scripts/dynamic-lab/mitmproxy-smoke.sh
```

Expected PASS marker:

```text
MITMPROXY_SMOKE_RESULT=PASS
```

The smoke test should start `mitmdump` locally, verify HTTP and HTTPS requests
through the proxy using the generated public CA as curl trust input, then stop
the proxy. It does not prove that all Android app traffic can be intercepted.

## Running the Platform TLS Probe

Run only when an emulator reboot is acceptable:

```bash
scripts/dynamic-lab/platform-tls-probe.sh
```

Expected PASS marker:

```text
PLATFORM_TLS_PROBE_RESULT=PASS
```

The probe installs a temporary local trust-probe APK, injects a runtime CA
overlay into Android platform TLS trust for newly spawned apps, sends a bounded
HTTPS request, verifies a decrypted mitmproxy flow, then cleans up and reboots
to clear the runtime namespace overlay.

## Cleaning Runtime State

Run:

```bash
scripts/dynamic-lab/cleanup-runtime-state.sh
```

Expected cleanup state:

- Android proxy reset to `:0`.
- Temporary probe package removed.
- Target APKs removed by session cleanup policy.
- Runtime CA overlay directories removed.
- Frida server stopped.
- Bridge processes started by MSAP scripts stopped.
- SELinux remains `Enforcing`.

If cleanup cannot prove a safe baseline, mark the device quarantined and restore
the validated snapshot before reuse.

## Evidence Locations

Dynamic evidence should remain local or in MinIO through
`ObjectStorageReference`, depending on the phase and script. Do not commit:

- APK samples.
- mitmproxy flow files.
- screenshots or recordings.
- logcat captures from assessed apps.
- Frida raw event streams.
- temporary probe output containing assessed-app context.
- private CA material.

For Phase 4 implementation, PostgreSQL should store bounded metadata and
normalized summaries only; MinIO should store large raw evidence and reports.

## Expected PASS Markers

| Script | PASS marker |
| --- | --- |
| `preflight.sh` | `PREFLIGHT_RESULT=PASS` |
| `frida-smoke.sh` | `FRIDA_SMOKE_RESULT=PASS` |
| `mitmproxy-smoke.sh` | `MITMPROXY_SMOKE_RESULT=PASS` |
| `lab-health.sh` | `DYNAMIC_LAB_HEALTH_RESULT=PASS` |
| `platform-tls-probe.sh` | `PLATFORM_TLS_PROBE_RESULT=PASS` |

## Troubleshooting

| Symptom | Likely cause | Recovery |
| --- | --- | --- |
| Emulator offline | Emulator not started, still booting, wrong AVD, or stale ADB state. | Start the emulator, wait for boot completion, then rerun preflight. |
| `adb root` not available | Wrong system image or non-userdebug build. | Restore the validated AVD/snapshot; do not proceed with dynamic lab assumptions. |
| SELinux not `Enforcing` | Host/session drift or manual change. | Restore `msap-instrumented-base`; quarantine if drift persists. |
| Frida bridge timeout | WSL IP changed, bridge not refreshed, or Frida server not running. | Run `refresh-frida-bridge.sh`, rerun preflight, then rerun Frida smoke test. |
| WSL IP changed | Windows host restart or WSL network reset. | Refresh bridge; do not reuse old bridge assumptions. |
| Android proxy left enabled | Previous proxy run or failed cleanup. | Run cleanup; verify proxy is `:0`; restore snapshot if needed. |
| Missing `android.jar` | Android API platform missing from Windows SDK path. | Install/restore API 35 platform outside this sprint and rerun preflight. |
| mitmproxy CA missing | Local mitmproxy environment was removed or regenerated. | Recreate local mitmproxy state deliberately; update snapshot contract only after validation. |
| Platform TLS probe no flow | Proxy bridge, runtime CA overlay, app launch, or trust failure. | Review probe logs, flow reference, logcat marker, and proxy bridge state. |
| Trust-probe APK left installed | Probe cleanup was interrupted. | Run cleanup; restore snapshot if package remains. |
| Snapshot missing | AVD state is incomplete or moved. | Recreate or restore snapshot outside Git; rerun preflight. |
| Permanent CA accidentally detected | System/APEX trust store was modified outside runtime overlay. | Quarantine device, restore clean/instrumented baseline, and verify APEX CA count. |

## Recovery Procedures

1. Stop active dynamic workers for the affected local device.
2. Run `cleanup-runtime-state.sh`.
3. Restore `msap-instrumented-base`.
4. Rerun `preflight.sh`.
5. Refresh the Frida bridge.
6. Rerun Frida and mitmproxy smoke tests.
7. Run platform TLS probe only if TLS trust behavior is part of the failure and
   a reboot is acceptable.
8. Keep the device quarantined until the expected PASS markers return.

Do not reuse a device after lease expiration, partial cleanup, proxy drift,
SELinux drift, or permanent CA drift until cleanup or operator recovery proves a
safe baseline.

## What to Send to Codex for Diagnosis

Provide redacted, bounded information:

- Current branch and `git status --short`.
- Script name, command, and PASS/FAIL marker.
- Redacted terminal output around the failure.
- Whether Windows, WSL, or the emulator was restarted.
- ADB serial and whether `adb devices` shows the emulator.
- SELinux mode, Android proxy state, Frida version, mitmproxy version.
- Whether `msap-instrumented-base` was restored immediately before the run.
- Redacted paths to local evidence directories or MinIO object references.

Do not send APK samples, private CA material, credentials, tokens, cookies,
passwords, full assessed-app screenshots, full proxy flows, or unredacted client
data.
