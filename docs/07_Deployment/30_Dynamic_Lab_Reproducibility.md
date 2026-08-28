# Dynamic Lab Reproducibility

## Purpose

The MSAP dynamic Android lab is a local operator environment for controlled
runtime validation of implemented dynamic-analysis features. This document defines
the validated workstation contract and the repository-managed scripts used to
restore, check, and document that contract after host or emulator drift.

The lab tooling is reproducibility infrastructure only. It does not install or
run target APKs, does not assert malware behavior, and does not create
vulnerability findings.

## Validated Local Architecture

The validated split is:

- Windows owns the Android SDK, emulator binaries, and AVD storage.
- WSL2 Ubuntu runs MSAP operator scripts, Frida client tooling, mitmproxy, and
  local evidence capture.
- Android runs an API 35 x86_64 userdebug emulator with rooted adbd and SELinux
  left in `Enforcing`.

The scripts discover the normal Windows SDK location from `%LOCALAPPDATA%` and
convert it with `wslpath`. A non-standard SDK location is configured only in the
ignored `.msap-dynamic-lab.local.env`. The versioned requirements are platform
API 35 and Build Tools 36.0.0; no personal username or clone path is part of the
contract.

## Snapshot Strategy

Two emulator snapshots define the recovery model:

- `msap-clean-base`: a clean rooted API 35 userdebug baseline.
- `msap-instrumented-base`: the validated dynamic-lab baseline with the staged
  public CA and Frida server binary present, Frida stopped, proxy disabled, and
  no third-party APK installed.

Snapshots remain local-only. The repository scripts verify that the expected
snapshot exists and can be loaded, but they never delete snapshots, wipe data, or
commit emulator state.

## Dynamic Lab State Contract

The accepted steady state is:

- Android serial `emulator-5554`
- API level `35`, ABI `x86_64`, build type `userdebug`
- rooted adbd
- SELinux `Enforcing`
- Android global proxy `:0`
- Frida client/server `17.16.4` with a locally recorded server SHA-256
- Android Frida binary `/data/local/tmp/msap-frida-server`
- mitmproxy `12.2.3` in `~/.local/share/msap-dynamic/venvs/mitmproxy`
- locally pinned public CA SHA-256 and Android certificate filename
- staged Android CA under `/data/local/tmp/msap-instrumentation/ca/`
- locally verified APEX CA baseline count for the selected clean image
- no permanent system CA modification
- no permanent APEX CA modification
- zero third-party packages for clean-baseline verification; post-install
  health may explicitly allow only the current auditor-authorized target with
  `MSAP_PREFLIGHT_ALLOWED_THIRD_PARTY_PACKAGES`
- no target APK installed
- Frida not left running

## Frida Bridge Architecture

The Frida path has three segments:

- Android Frida server on `tcp:27042`
- Windows ADB forward `tcp:27042 -> tcp:27042`
- Windows-to-WSL bridge on `tcp:27043`

WSL IP addresses change across host restarts. `refresh-frida-bridge.sh` invokes
the checked-in `configure-frida-bridge.ps1`, which updates only the scoped
Windows portproxy/firewall rule. The script prints the detected WSL IP and
Windows gateway IP and does not disable the firewall globally.

## mitmproxy Environment Architecture

mitmproxy runs from a dedicated virtual environment under
`~/.local/share/msap-dynamic/venvs/mitmproxy`. Its generated CA material remains
local and outside Git. Scripts verify the public CA hash but do not copy the CA
into the repository.

The local WSL smoke test starts `mitmdump` on `127.0.0.1:18080` or a nearby free
port, then verifies both HTTP and HTTPS requests to `example.com` through the
proxy using the generated public CA as curl trust input.

## Runtime CA Overlay Architecture

The lab does not use `adb remount`, writable-system, or permanent CA writes.
For platform TLS validation, the operator-run probe builds a temporary runtime
overlay under `/data/local/tmp/msap-instrumentation/runtime-ca-overlay`, copies
the existing APEX Conscrypt certificates, adds the staged MSAP public CA, and
bind-mounts that overlay into the `zygote64` and `zygote` mount namespaces.

Apps spawned after injection inherit the runtime trust view. Cleanup restores
the proxy, uninstalls the temporary probe app, removes runtime overlay
directories, removes the Windows proxy bridge, and reboots the emulator to clear
the namespace overlay.

## Platform TLS Trust-Probe

`platform-tls-probe.sh` builds a temporary APK outside the repository:

- package `tech.nine11.msap.trustprobe`
- activity using `HttpsURLConnection`
- request `https://example.com/?msap_app_probe=<timestamp>`
- log tag `MSAP_TRUST_PROBE`
- success marker `MSAP_RESULT status=200`

The script starts mitmproxy, configures Android proxy
`10.0.2.2:18080`, creates a Windows bridge from `127.0.0.1:18080` to the WSL
listener, launches the app, captures logcat, screenshot, UI XML, mitmproxy flow,
and readback logs, then validates that a decrypted GET flow returned HTTP 200.

Chrome is intentionally not used as the trust authority because Chrome may use
root-store behavior that is not equivalent to Android platform TLS.

## Limitations

- Chrome is not a platform TLS authority for this lab.
- Certificate pinning may still block application traffic.
- Applications with custom trust stores may still block interception.
- Native TLS stacks may require Frida hooks or other runtime instrumentation.
- QUIC and HTTP/3 may bypass classic HTTP proxy visibility.

## Security Boundaries

- No private CA material in Git.
- No generated public MSAP CA certificate in Git.
- No target APKs or samples in Git.
- No test-account credentials, tokens, cookies, or SSH keys in Git.
- No dynamic evidence blobs, mitmproxy flows, screenshots, or assessed client
  data in Git.
- SELinux remains `Enforcing`.
- No `adb remount`, writable-system, or permanent CA modification.

## Operator Runbook

1. Start the emulator:
   `scripts/dynamic-lab/launch-emulator-from-wsl.sh`
2. Restore the validated baseline:
   `scripts/dynamic-lab/restore-instrumented-snapshot.sh`
3. Run steady-state validation:
   `scripts/dynamic-lab/preflight.sh`
4. Refresh the Frida bridge after WSL IP drift:
   `scripts/dynamic-lab/refresh-frida-bridge.sh`
5. Run the short health suite:
   `scripts/dynamic-lab/lab-health.sh`
6. Run full platform TLS validation only when a reboot is acceptable:
   `scripts/dynamic-lab/platform-tls-probe.sh`
7. Clean transient state:
   `scripts/dynamic-lab/cleanup-runtime-state.sh`

## Troubleshooting

| Symptom | Likely cause | Recovery |
| --- | --- | --- |
| `android.jar` missing | Android API platform not installed | Install API 35 platform and rerun preflight |
| `adb.exe` missing | SDK path changed | Update `.msap-dynamic-lab.local.env` |
| Emulator offline | AVD not running or still booting | Launch AVD and wait for boot completion |
| Proxy is not `:0` | Previous run left Android proxy enabled | Run `cleanup-runtime-state.sh` |
| Frida bridge warning | WSL IP changed or Windows bridge expired | Run `refresh-frida-bridge.sh` |
| Frida version mismatch | Client/server binary drift | Recreate local Frida helper state for `17.16.4` |
| Staged CA hash mismatch | Local CA changed since validation | Rebuild the instrumented snapshot or update the contract deliberately |
| APEX CA count mismatch | Permanent or runtime trust store drift | Restore `msap-instrumented-base` and rerun preflight |
| Third-party packages found | Temporary APK or target APK left installed | Run cleanup, then restore the snapshot if needed |
| Platform probe no flow | Proxy bridge, CA overlay, or app TLS failure | Review evidence under local dynamic evidence root |

## Acceptance Checklist

- `PREFLIGHT_RESULT=PASS`
- `FRIDA_SMOKE_RESULT=PASS`
- `MITMPROXY_SMOKE_RESULT=PASS`
- `DYNAMIC_LAB_HEALTH_RESULT=PASS`
- `PLATFORM_TLS_PROBE_RESULT=PASS` when full TLS verification is intentionally run
- Android proxy restored to `:0`
- SELinux remains `Enforcing`
- no permanent system or APEX CA modification
- APEX CA count remains `145`
- no temporary trust-probe APK installed
- Frida not left running

## Future Repository Phase Mapping

- Phase 3 contracts: dynamic-lab state contract and result markers.
- Phase 4 device models: AVD identity, API level, ABI, and snapshot metadata.
- Phase 5 ADB orchestration: root, wait, proxy, package, and snapshot helpers.
- Phase 7 network interception: mitmproxy environment and TLS flow validation.
- Phase 8 Frida instrumentation: bridge refresh, server lifecycle, and smoke
  checks.
