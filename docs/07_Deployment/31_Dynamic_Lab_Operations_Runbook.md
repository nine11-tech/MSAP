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

The default is a strict zero-third-party-package baseline. If the authorized
target is already installed, scope preflight to that exact package without
allowing any unrelated application:

```bash
MSAP_PREFLIGHT_ALLOWED_THIRD_PARTY_PACKAGES=owasp.sat.agoat \
  scripts/dynamic-lab/preflight.sh
```

This exception applies only to preflight health. Snapshot restoration still
requires zero third-party packages.

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

## Running and executing an AI Assessment Plan

Planning remains plan-only until the explicit execution action. In Dynamic Lab,
use the **AI Assessment Planner** section
with an Analyst/Admin account:

1. Select an audit and one package authorized by a verified APK record.
2. Select **OpenAI · GPT-5.5**, **Deterministic reference**, or leave the
   provider on **Server default**. This selector never sends a credential or
   model name from the browser.
3. Enter a bounded assessment objective and scope. Do not enter credentials,
   commands, filesystem paths, or environment instructions.
4. Select **Generate Plan** and inspect the provider/model, target, plan hash,
   ordered steps, rationale, allowlisted tools, bounded arguments, expected
   observations, success conditions, evidence requirements, and dependencies.
5. Select **Validate Plan**. This reruns backend manifest, schema, package,
   dependency, bounds, and unsafe-instruction policies.
6. Select **Approve Plan**. Confirm the state becomes `APPROVED`; verify that
   generation, validation, and approval created no `AgentRun` and changed no
   emulator state.
7. Select **Execute Assessment** once. This action accepts no command, tool,
   package, path, prompt, or argument payload.
8. Confirm a plan-linked `AgentRun` progresses from `QUEUED`/`RUNNING` to a
   terminal state. Inspect its plan hash, exact sequential timeline, durations,
   retries, artifacts, evidence, and controlled failure reason.
9. Confirm evidence provenance identifies the audit, plan hash, run, run step,
   artifact when present, and capability.
10. Inspect deterministic findings, risk/compliance, and **View Assessment
    Report**. Runtime instrumentation/coverage findings are informational
    evidence records and are not vulnerability verdicts; only deterministic
    rules can create them.
11. For a terminal run, select **Recommend Next Assessment**. Confirm the new
    plan says **AI-generated recommendation — requires auditor approval**, has a
    new hash, preserves audit/target/objective/scope, and creates no AgentRun.
12. Validate and approve the recommendation separately. Execute it only when a
    second cycle is desired. One source run has one proposal and the lineage is
    capped at two adaptive cycles.
13. **Cancel Run** stops subsequent calls but cannot interrupt a bounded host
    operation already in progress.

The API's `normalized_plan` is the versioned
`msap.assessment-plan/v1` representation. Provider `generated_plan` JSON is
retained for auditability but is never valid executor input. Approval rechecks
the canonical document and its stored hash before changing state. The guarded
`msap.approved-assessment-plan/v1` is the only execution input. The execute API
snapshots it, creates one linked run, and queues the bounded worker. Raw provider
output is never accepted by that endpoint.

If validation reports `PLAN_CONTRACT_INVALID`, treat the plan as tampered or
stale: do not approve or manually translate its text into commands. Generate a
new plan through the backend so schema and policy validation run again.

Viewer accounts may inspect plans and runs but cannot generate, validate,
approve, execute, or cancel them. Approval does not contact the gateway, host
agent, or emulator; only the separate execution action can queue the plan.

Local development defaults to the deterministic planner. To enable the intended
OpenAI planner in a backend environment, configure:

```text
MSAP_ASSESSMENT_PLANNER_PROVIDER=OPENAI
MSAP_ASSESSMENT_PLANNER_MODEL=gpt-5.6-luna
MSAP_OPENAI_API_KEY=<backend-only credential>
```

Optional bounded settings are
`MSAP_ASSESSMENT_PLANNER_TIMEOUT_SECONDS`,
`MSAP_ASSESSMENT_PLANNER_MAX_RETRIES`,
`MSAP_ASSESSMENT_PLANNER_RETRY_BASE_MILLISECONDS`,
`MSAP_ASSESSMENT_PLANNER_MAX_OUTPUT_TOKENS`, and
`MSAP_ASSESSMENT_PLANNER_REASONING_EFFORT`. Never put the key in frontend
configuration, a plan, an agent-runtime environment, logs, or evidence.
`MSAP_ASSESSMENT_MAX_ADAPTIVE_CYCLES` defaults to and is hard-capped at `2`.

Approved execution bounds are backend-only:

```text
MSAP_ASSESSMENT_EXECUTION_TOTAL_TIMEOUT_SECONDS=600
MSAP_ASSESSMENT_EXECUTION_MAX_RETRIES=1
MSAP_ASSESSMENT_EXECUTION_MAX_TOOL_CALLS=96
MSAP_ASSESSMENT_EXECUTION_MAX_OBSERVATION_BYTES=65536
MSAP_ASSESSMENT_EXECUTION_MAX_ARTIFACTS=100
MSAP_ASSESSMENT_EXECUTION_MAX_ARTIFACT_BYTES=25165824
```

The OpenAI path fails closed. It never silently replaces a timeout, refusal,
malformed response, schema rejection, or policy rejection with the deterministic
plan. Safe API errors distinguish missing configuration, timeout, unavailable
provider, rate limit, refusal, incomplete/oversized output, schema rejection,
and policy rejection without exposing provider response bodies or credentials.

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

PostgreSQL stores bounded metadata, normalized observations, hashes, and
provenance only. Existing object storage retains large raw evidence; reports
reference artifact metadata rather than embedding raw screenshot/log/UI bytes.

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
| Approved plan will not execute | Approval/hash/target/runtime changed, the plan already has a run, or current bounds are lower than its requirements. | Do not edit plan/run rows. Restore the target/runtime or generate, validate, and approve a new plan. |
| Execution step skipped | An earlier tool in the same plan step or a declared dependency failed. | Inspect the first failed step and bounded evidence; do not invoke the skipped capability manually. |
| Execution remains cancelling | A bounded host action is still in progress. | Wait for that action to return; cancellation is checked before the next gateway call. |
| Next assessment rejected | The source run is not terminal, already has a proposal, target/scope changed, or the two-cycle bound was reached. | Do not edit lineage rows. Review the existing candidate or start a new auditor-defined initial plan. |
| Assessment report shows post-processing failure | A deterministic rule/scoring/report service failed after tool execution. | Preserve the terminal AgentRun and evidence, inspect bounded backend logs, fix the deterministic service, and regenerate the audit report; do not reinterpret application text as a finding. |

## Adaptive Security Agent execution

After validating and approving a strategy, choose **Adaptive Security Agent**
to create an `ADAPTIVE_AGENT` run. The server derives and persists the immutable
capability envelope before queueing Celery. Approval alone still creates no run
and executes no capability.

Verify the Dynamic Lab activity stream shows the current hypothesis, decision
number, provider/model, concise security rationale, exact capability, gateway
result, deterministic oracle summary, coverage, budgets, and termination
reason. These summaries are not chain-of-thought.

`PAUSED` with `NEEDS_AUDITOR` is safe: no further action executes. Cancel records
a controlled cancellation. Sequential execution remains available as
**Sequential Approved Plan**.

```dotenv
MSAP_AGENT_DECISION_PROVIDER=OPENAI
MSAP_AGENT_MAX_DECISIONS=24
MSAP_AGENT_MAX_TOOL_CALLS=24
MSAP_AGENT_MAX_PROVIDER_CALLS=24
MSAP_AGENT_MAX_CONSECUTIVE_FAILURES=3
MSAP_AGENT_MAX_DURATION_SECONDS=480
MSAP_AGENT_MAX_ARTIFACTS=50
MSAP_AGENT_MAX_EVIDENCE_RECORDS=50
MSAP_AGENT_MAX_STATE_CONTEXT_BYTES=65536
```

OpenAI `429`, refusal, timeout, malformed output, schema/policy rejection,
integrity drift, replay, target drift, or a budget stop never silently switches
to deterministic decisions. Tests may select the deterministic reference
provider explicitly.

## Windows-Native Dynamic Lab Mode (demo default)

The demo defaults to a Windows-native topology: the Android SDK, emulator, and
Host Agent run directly on the Windows host, while Django and Celery run in WSL
or Docker Compose.

Configure the topology in the backend environment:

```dotenv
MSAP_DYNAMIC_LAB_MODE=WINDOWS_HOST_AGENT
MSAP_DYNAMIC_HOST_AGENT_URL=http://host.docker.internal:8765
```

`MSAP_DYNAMIC_LAB_MODE` accepts `WINDOWS_HOST_AGENT` (default) or
`WSL_BRIDGED`. The backend never hardcodes Windows paths; the Host Agent
reports its own platform, SDK path, and diagnostics through `/health`.

Start the Host Agent from Windows PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\demo\start-windows-host-agent.ps1
```

The script verifies `adb.exe`, the emulator serial, and the Frida client,
reports safe recovery hints (for example a stale `127.0.0.1:27042` server), and
prints the URLs the backend can use. It never prints the token or environment
secrets.

Django-to-Host-Agent URL resolution:

| Django location | Host Agent URL |
| --- | --- |
| WSL directly | `http://127.0.0.1:8765` |
| Docker Compose on Windows (default) | `http://host.docker.internal:8765` |
| Docker Compose when `host.docker.internal` resolves to the wrong host | `http://<Windows host IP>:8765` |

In the `WSL_BRIDGED` fallback the Host Agent still runs on Windows, but bridge
and Frida connectivity are managed with the existing
`refresh-frida-bridge.sh` flow.

`demo_health_check` prints the detected topology before the service checks:

```text
TOPOLOGY: configured_url=http://host.docker.internal:8765 lab_mode=WINDOWS_HOST_AGENT resolved_address=172.17.0.1 connected=OK suggested_fix=none
```

## OpenAI call budget (demo-hard limit)

The backend enforces a hard OpenAI call budget that the browser cannot change.
Once a request is sent to OpenAI it counts, regardless of the provider response;
local schema-preflight rejections that never sent a request do not count.
Mocked or deterministic providers never count.

```dotenv
MSAP_OPENAI_MAX_MISSION_GENERATION_CALLS=1
MSAP_OPENAI_MAX_ADAPTIVE_DECISION_CALLS=6
MSAP_OPENAI_MAX_TOTAL_CALLS=7
```

When the budget is exhausted the current mission run finishes as `FAILED` with
termination reason `OPENAI_BUDGET_EXHAUSTED` and the mission becomes
`INCONCLUSIVE`: evidence collected so far is preserved and the page explains
that the AI call budget was reached. This is an expected, safe demo state, not
an error.

The Dynamic Lab page shows the remaining budget, backed by
`dynamic/finding-validations/budget-status/`. An Analyst/Admin can reset the
budget for a fresh demo via `dynamic/finding-validations/budget-reset/` or the
**Reset Budget** control in the right sidebar.

## Working Browser Demo Checklist

Use this path for the finding-driven browser demo. It keeps the current Tool
Gateway, FindingValidationMission workflow, Celery worker, MinIO, and Android
Host Agent architecture.

1. Start core services:

```bash
docker compose up -d postgres redis minio minio-init backend worker frontend
```

2. Configure the Compose Host Agent URL for the current topology.

For Django running directly in WSL, use:

```dotenv
MSAP_DYNAMIC_HOST_AGENT_URL=http://127.0.0.1:8765
```

For Django running in Docker Compose and Host Agent running in WSL, use the WSL
interface IP, not `host.docker.internal`, when Docker resolves
`host.docker.internal` to the Windows/Docker host instead of the WSL distro:

```bash
WSL_IP="$(hostname -I | awk '{print $1}')"
sed -i "s#^MSAP_DYNAMIC_HOST_AGENT_URL=.*#MSAP_DYNAMIC_HOST_AGENT_URL=http://$WSL_IP:8765#" .env
docker compose up -d --force-recreate backend worker
```

3. Start the Host Agent for Compose:

```bash
scripts/demo/start-compose-host-agent.sh start
```

On a Windows host, the same topology uses the PowerShell starter instead:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\demo\start-windows-host-agent.ps1
```

For direct WSL Django, the existing local script starts a loopback Host Agent:

```bash
scripts/demo/start-local-mvp-demo.sh up
```

4. Start or restore Frida for the live PoC:

```bash
scripts/dynamic-lab/frida-start.sh
```

If Frida reports `127.0.0.1:27042` already in use, inspect the emulator for a
stale managed process and clear only that process:

```bash
source scripts/dynamic-lab/lib/common.sh
msap_adb shell 'ps -A | grep -i msap-frida-server || true'
msap_adb shell 'kill <stale-msap-frida-server-pid> || true; rm -f /data/local/tmp/msap-frida-server.pid'
scripts/dynamic-lab/frida-smoke.sh
scripts/dynamic-lab/frida-start.sh
```

5. Run safe lab health before any OpenAI call:

```bash
docker compose exec -T backend python manage.py demo_health_check
```

Expected safe statuses:

```text
BACKEND OK
POSTGRESQL OK
REDIS OK
CELERY OK
MINIO OK
HOST_AGENT OK
EMULATOR OK
TARGET_APP OK
FRIDA OK
DEMO_HEALTH_RESULT=PASS
```

6. Seed the idempotent AndroGoat finding demo:

```bash
docker compose exec -T backend python manage.py seed_androgoat_finding_demo --dev-fixture
```

The command prints the project, audit, APK, finding, target package, expected
playbook, and demo username. It does not print passwords or tokens.

7. Run the zero-cost path with deterministic providers:

```dotenv
MSAP_ASSESSMENT_PLANNER_PROVIDER=DETERMINISTIC
MSAP_AGENT_DECISION_PROVIDER=DETERMINISTIC
MSAP_DYNAMIC_RUNNER_ENABLED=true
```

Recreate backend/worker after changing Compose env:

```bash
docker compose up -d --force-recreate backend worker
docker compose exec -T backend python manage.py check_dynamic_runner
```

8. Run the real browser acceptance only after health is green:

```dotenv
MSAP_ASSESSMENT_PLANNER_PROVIDER=OPENAI
MSAP_AGENT_DECISION_PROVIDER=OPENAI
MSAP_ASSESSMENT_PLANNER_MODEL=gpt-5.6-luna
MSAP_AGENT_DECISION_MODEL=gpt-5.6-luna
MSAP_ASSESSMENT_PLANNER_REASONING_EFFORT=low
MSAP_AGENT_DECISION_REASONING_EFFORT=low
MSAP_AGENT_MAX_PROVIDER_CALLS=3
```

The OpenAI budget caps the whole demo: at most 1 mission-generation call and 6
adaptive-decision calls (7 OpenAI calls total, `MSAP_OPENAI_MAX_*`). After
exhaustion the mission becomes `INCONCLUSIVE` and a budget reset is required
before the next demo cycle.

```bash
cd frontend
MSAP_LIVE_ACCEPTANCE=1 \
MSAP_E2E_AUDIT_ID=<demo-audit-id> \
MSAP_E2E_USERNAME=<demo-user> \
MSAP_E2E_PASSWORD=<demo-password> \
MSAP_E2E_API_BASE_URL=http://127.0.0.1:8000/api \
MSAP_E2E_EVIDENCE_DIR=../.runtime/msap-demo/browser-acceptance-real \
npx playwright test e2e/finding-validation-mission-live.spec.ts --workers=1
```

Use `127.0.0.1` consistently for the frontend and API base in browser tests so
session cookies are sent. If a paid mission already exists and only browser
verification is needed, pass `MSAP_E2E_EXISTING_MISSION_ID` and
`MSAP_E2E_EXISTING_RUN_ID` to avoid another OpenAI mission generation.

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
