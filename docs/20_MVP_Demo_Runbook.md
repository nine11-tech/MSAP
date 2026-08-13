# MSAP MVP Demo Runbook

The accepted Dynamic Lab MVP provides authenticated control of the managed
Android emulator and verified audit APKs. The browser never sends shell commands,
host filesystem paths, or the host-agent token.

## Local topology

- Docker Compose: PostgreSQL, Redis, MinIO, and `minio-init`.
- WSL host: Django, Celery, Vite, and the loopback dynamic host agent.
- Windows: the running Android emulator.
- Browser: `http://127.0.0.1:5173`.

The host agent is the only process that invokes the configured Android Debug
Bridge. Django sends only allowlisted device and package actions. When enabled,
an ephemeral agent-runtime container can call Django only with a short-lived
credential scoped to one run; it never receives the host-agent token.

## Start the demo

Keep the emulator running, then execute from the repository root:

```bash
scripts/demo/start-local-mvp-demo.sh up
```

The helper starts local infrastructure, applies migrations, creates a temporary
host-agent token, and starts the host agent, Django, Celery, and Vite.

The internal controller remains the default. To build and enable the container
sandbox for the local demo, start it with:

```bash
MSAP_AGENT_CONTAINER_ENABLED=true scripts/demo/start-local-mvp-demo.sh up
```

The helper builds `msap-agent-runtime:local` only when this setting is true and
binds Django so the ephemeral container can reach the default
`http://host.docker.internal:8000` gateway. An operator using a dedicated Docker
network can also set `MSAP_AGENT_CONTAINER_NETWORK` and a matching
`MSAP_AGENT_GATEWAY_URL`.

The image can be built independently without starting it:

```bash
docker build -t msap-agent-runtime:local agent_runtime
# Equivalent Compose build target; it is excluded from normal Compose startup.
docker compose --profile agent-runtime-build build agent-runtime
```

Check or stop the demo with:

```bash
scripts/demo/start-local-mvp-demo.sh status
scripts/demo/start-local-mvp-demo.sh logs
scripts/demo/start-local-mvp-demo.sh down
```

## Upload an APK

1. Open `http://127.0.0.1:5173` and sign in as an analyst or administrator.
2. Open an audit.
3. Select the authorized APK.
4. Complete the browser upload.
5. Confirm that the APK storage state is `VERIFIED`.

The browser calculates SHA-256 before upload. Confirmation validates the MinIO
object size, content type, and checksum metadata before installation is allowed.

## Dynamic Lab demo

1. Open **Dynamic Lab** at `/dynamic`.
2. Confirm that Host agent and Emulator are online.
3. Confirm the serial, Android version, API level, ABI, root UID, SELinux state,
   and last sync.
4. Click **Sync Device**.
5. Select the audit.
6. Select a verified APK.
7. Click **Install APK**.
8. Review the installed package metadata.
9. Click **Launch**.
10. Click **Screenshot** and confirm the emulator PNG renders in the screenshot
    panel.
11. Click **Force Stop**.
12. Use **Clear Data** only when needed and approve the confirmation.
13. Use **Uninstall** only when needed and approve the confirmation.

Use **Refresh Packages** to reload the bounded installed-package inventory.
Viewer accounts can inspect status, package inventory, and screenshots but
cannot install or mutate packages.

## Agentic Dynamic Assessment mobile tools

Sprint C2 retains the readiness workflow and adds the deterministic Basic App
Interaction Check to both runtime modes:

1. Select **Internal Controller** and confirm the card reports **Foundation
   available**.
2. As an Analyst or Admin, select **Device Readiness Check**, run it, and confirm it
   succeeds.
3. Confirm the persisted run contains exactly `get_device_status` followed by
   `take_screenshot`.
4. Review host-agent reachability, emulator reachability, device identity,
   SELinux state, run duration, and the final environment-readiness result.
5. Review screenshot content type, dimensions when detectable, byte size,
   SHA-256, and capture time.
6. If the backend was started with `MSAP_AGENT_CONTAINER_ENABLED=true`, select
   **Container Sandbox** and run the same check.
7. Confirm **Executed by** says **Container Sandbox**, both steps succeed, and
   screenshot metadata remains visible.
8. Inspect the bounded backend logs and confirm no host-agent token or run token
   was emitted. Confirm there is still no prompt or chat control.
9. Select **Basic App Interaction Check**, an audit, and either a verified APK
   or an installed authorized package.
10. Run without tap/text. Confirm launch, screenshot, UI hierarchy, bounded
    logcat, explicit tap/text `SKIPPED` steps, and force stop.
11. Optionally repeat with simple authorized tap coordinates. Do not enter
    credentials in the text field, clear data, or uninstall for this check.
12. Confirm the result says evidence only and makes no vulnerability or malware
    verdict.

Viewer accounts can inspect existing runtimes, runs, steps, and artifact
metadata but cannot start a run. The page has no freeform prompt, agent chat,
custom tool selector, or autonomous pentesting control.

To fall back, select **Internal Controller**. To disable all future container
launches, restart the backend with `MSAP_AGENT_CONTAINER_ENABLED=false`; the UI
will show **Container Sandbox (Unavailable)**.

## AI Assessment Planner

Sprint D adds a separate **PLAN ONLY** section and does not replace the existing
deterministic run controls:

1. Select the AndroGoat audit and `owasp.sat.agoat` from the verified-package
   targets.
2. Keep or edit the bounded objective and scope.
3. Click **Generate Plan** and inspect six structured steps.
4. Confirm every visible tool is one of the existing gateway tools and that the
   plan includes expected observations, success conditions, evidence, and
   dependencies.
5. Click **Validate Plan** and then **Approve Plan**.
6. Confirm the final state is `APPROVED` and the page explicitly says approval
   does not execute anything.
7. Confirm the AgentRun count and emulator foreground/PID/UI state did not
   change during generation, validation, or approval.

Local demo mode uses the deterministic provider and requires no OpenAI key. The
OpenAI provider is backend-only, is configured for `gpt-5.5`, and returns the
same strict plan schema. Viewer can inspect plans but cannot mutate them.

For Sprint D1 contract acceptance, inspect the plan detail response and confirm
that `normalized_plan.contract_version` is `msap.assessment-plan/v1`, steps have
stable IDs/action types and manifest-derived bounds, and the plan hash is
present. Approval must still leave the AgentRun count and emulator unchanged.
Raw `generated_plan` content is planner intent only; it must never be copied to
a runner, shell, Frida CLI, or host-agent request.

## Operational checks

Dynamic Lab reports:

- Host agent online or offline.
- Emulator online or offline.
- MinIO online or offline.
- Celery online or offline.

The screenshot is transient browser state and is not retained as a report
artifact in this MVP. Device events are retained for sync, screenshot, install,
launch, force stop, clear data, and uninstall actions.

## Security boundaries

- Package names must match the Android package-name allowlist.
- Package actions require the package to be installed.
- APK installation reads only a verified audit object through the storage
  provider.
- The host agent uses argument arrays and never invokes `shell=True`.
- The host-agent token is server-side only and is redacted from propagated
  errors.
- The sandbox receives only a run ID, fixed objective, bounded validated
  objective input, gateway URL, and short-lived run token. It receives no
  host-agent, database, MinIO, or OpenAI credential.
- The container is non-root, non-privileged, read-only, capability-free,
  resource-bounded, and receives no repository, home, Docker-socket, `.env`, or
  SSH mount.
- Clear Data and Uninstall require browser confirmation.
- Analyst or administrator access is required for device mutation.

## Future execution-agent boundary

Sprint D implements the GPT-5.5-compatible planner boundary but no autonomous
execution agent. A future execution agent may consume only an approved plan,
must use the run-scoped gateway, and must never receive host-agent, database,
MinIO, Docker, shell, repository, or provider credentials. Django remains
responsible for validating and auditing every future tool call.

The D1 executor-facing contract is a hash-checked projection of a persisted,
validated, explicitly approved canonical plan. It is not an execution API and
cannot be constructed from arbitrary raw model text. Tool identifiers in that
projection describe intent; the gateway must independently authorize every
future invocation.
