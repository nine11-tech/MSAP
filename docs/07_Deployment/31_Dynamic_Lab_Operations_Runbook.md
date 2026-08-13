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

## Running deterministic agent mobile checks

In Dynamic Lab, the Agentic Dynamic Assessment section offers Device Readiness
Check and Basic App Interaction Check. Viewer can inspect prior runs but cannot
start one; use an Analyst or Admin account.

For a basic interaction run:

1. Confirm the host agent and emulator are online.
2. Select an audit.
3. Select either an audit-owned `VERIFIED` APK or a package already installed on
   the managed emulator.
4. Leave tap and text empty for the non-interactive acceptance pass.
5. Run the objective and verify status, launch, screenshot, UI hierarchy,
   bounded logcat excerpt, honest tap/text `SKIPPED` steps, and force stop.
6. Optionally repeat with simple authorized coordinates. Coordinates are checked
   against device bounds when the host reports them.

Do not enter credentials or secrets in the text field. Text is bounded and its
stored preview is redacted, but the action still types into the focused Android
UI. Do not use clear-data unless it is a separately authorized, explicitly
confirmed Analyst/Admin action. The current basic objective never clears data
and never uninstalls the app.

The result is observation evidence only. A successful run does not confirm a
vulnerability and is not a malware verdict. Logcat captures are completed and
bounded; `stop_logcat` therefore reports unsupported instead of claiming that a
nonexistent live collector was stopped.

## Running real Frida instrumentation

Use the compact **Runtime Instrumentation** section in Dynamic Lab with an
Analyst/Admin account:

1. Select an audit and an APK-record-authorized installed package.
2. Run **Check Frida**. Require real client/server versions, version agreement,
   device identity, a non-zero process count, target PID, and attach probe.
3. Run **Setup Frida** only when setup is needed. Review `before_state`, each
   fixed action, `after_state`, and RPC verification; do not accept a binary-only
   check.
4. Run **Frida PS** and confirm real emulator processes are returned.
5. Run **Attach** and require a real PID and in-process probe event.
6. Run **Frida — Runtime UI Modification Proof**. Confirm real before/after PNG
   previews, non-zero UI node counts, focused target package, a successful
   `ui_modification` event with `MSAP FRIDA ACTIVE`, changed screenshot digest,
   bounded relevant logcat, detached cleanup state, and final force stop.

If UI dump XML is empty, unparsable, or contains zero nodes, the tool fails with
a precise reason. It must not be reported as captured. If the proof event is
missing/failed or the screenshot digest does not change, the proof run fails.

Custom JavaScript is limited to 32 KiB and 30 seconds, requires explicit
confirmation, and executes only through Frida inside the authorized Android
process. Never paste credentials or host data. Structured messages and errors
are bounded and stored; source is redacted after execution.

Instrumentation PNG bytes live in the evidence bucket. PostgreSQL contains
only object references, digests, bounded summaries, and the consolidated
instrumentation evidence record. A successful proof establishes in-process
instrumentation and visible behavior modification; it is not a vulnerability
or malware verdict.

## Running the AI Assessment Planner

Sprint D is plan-only. In Dynamic Lab, use the **AI Assessment Planner** section
with an Analyst/Admin account:

1. Select an audit and one package authorized by a verified APK record.
2. Enter a bounded assessment objective and scope. Do not enter credentials,
   commands, filesystem paths, or environment instructions.
3. Select **Generate Plan** and inspect the provider/model, target, plan hash,
   ordered steps, rationale, allowlisted tools, bounded arguments, expected
   observations, success conditions, evidence requirements, and dependencies.
4. Select **Validate Plan**. This reruns backend manifest, schema, package,
   dependency, bounds, and unsafe-instruction policies.
5. Select **Approve Plan**. Confirm the state becomes `APPROVED` and the page
   continues to say **PLAN ONLY**.
6. Verify that no `AgentRun` was created and that foreground package, target PID,
   screenshot/UI state, and device action records did not change.

Viewer accounts may inspect plans but cannot generate, validate, or approve
them. Approval does not contact the gateway, host agent, or emulator and does
not authorize direct execution outside a future execution-agent policy.

Local development defaults to the deterministic planner. To enable the intended
OpenAI planner in a backend environment, configure:

```text
MSAP_ASSESSMENT_PLANNER_PROVIDER=OPENAI
MSAP_ASSESSMENT_PLANNER_MODEL=gpt-5.5
MSAP_OPENAI_API_KEY=<backend-only credential>
```

Optional bounded settings are
`MSAP_ASSESSMENT_PLANNER_TIMEOUT_SECONDS`,
`MSAP_ASSESSMENT_PLANNER_MAX_OUTPUT_TOKENS`, and
`MSAP_ASSESSMENT_PLANNER_REASONING_EFFORT`. Never put the key in frontend
configuration, a plan, an agent-runtime environment, logs, or evidence.

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
| Basic interaction rejects APK | APK is from another audit, has no object, or object is not `VERIFIED`. | Select the audit-owned verified APK; never supply a local path. |
| Basic interaction rejects package | Package name is malformed or package is not installed. | Refresh the installed package list and select the exact allowlisted value. |
| Tap rejected | Coordinate is outside the reported screen dimensions. | Use a visible, authorized coordinate inside the current emulator screen. |
| Logcat excerpt is empty | App PID was unavailable or the bounded buffer had no matching lines. | Confirm the app launched; rerun without treating an empty excerpt as a finding. |
| UI hierarchy reports zero nodes | Capture produced invalid evidence or the target is not foreground/running. | Relaunch the authorized package; inspect the precise host-agent failure and do not mark UI captured. |
| Frida server unavailable | Managed server stopped, bridge stale, or endpoint unreachable. | Use Setup Frida, verify fixed server version, refresh the configured bridge if required, and rerun Check Frida. |
| Frida version mismatch | Client and managed server differ. | Install the matching managed pair; setup deliberately refuses to claim success. |
| Proof event missing or screenshot unchanged | Script did not modify the visible Activity or target lost foreground. | Treat the run as failed, review bounded Frida/logcat events, relaunch, and rerun; never substitute mocked evidence. |
| Planner target rejected | The package is malformed or does not belong to an APK record in the selected audit. | Select the exact verified audit package; do not type an unrelated installed package. |
| Planner provider unavailable | OpenAI mode lacks a backend key or the bounded provider request failed. | Check backend-only provider configuration; use the deterministic provider for local acceptance. Never expose provider errors or credentials to the browser. |
| Plan validation rejected | Output referenced an unknown tool/field, unsafe instruction, malformed argument, unsupported script, excessive evidence, or invalid dependency graph. | Review the controlled validation message and generate a new bounded plan. Do not bypass the policy layer. |

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
