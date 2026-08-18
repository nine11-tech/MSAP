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

## AI Assessment Planner and bounded execution

Sprint D keeps AI planning, approval, execution, evidence, deterministic
findings, and reporting visibly separate. Use these phases for the final demo:

1. **Start infrastructure.** Run the local demo helper and confirm PostgreSQL,
   Redis, MinIO, Django, Celery, Vite, and the host agent are ready.
2. **Verify Django/backend.** Open `/api/health/` and confirm authenticated API
   access works without exposing backend configuration.
3. **Verify frontend.** Sign in as Analyst/Admin and confirm the system-status
   banner is operational or explains any controlled degradation.
4. **Verify Dynamic Lab.** Confirm `emulator-5554`, Android/API/ABI, SELinux,
   package inventory, and the accepted C2/C3 controls.
5. **Create/select audit.** Select the authorized AndroGoat audit and verified
   package `owasp.sat.agoat`.
6. **Select a finding.** From Findings, choose an eligible AndroGoat root or
   emulator finding and select **Validate dynamically**. Static-only controls
   and controls without an executable playbook stay out of Dynamic Lab.
7. **Generate the Luna scenario.** The Economy profile uses `gpt-5.6-luna`
   with low reasoning. The model receives only the bounded selected-finding
   context; it proposes the hypothesis and expected evidence, while Django
   constrains it to the backend playbook catalog.
8. **Inspect validation.** Confirm the canonical plan has ordered IDs,
   dependencies, bounded arguments/evidence, and only manifest capabilities.
9. **Inspect policy.** Confirm target, objective, scope, package ownership,
   destructive controls, and policy status are accepted by Django.
10. **Approve plan.** Select **Approve Plan** and prove no AgentRun/tool call or
   emulator change occurred. This is auditor authorization, not execution.
11. **Execute assessment.** Select **Execute Assessment**. The endpoint accepts
    no commands/tools/arguments and creates one immutable plan-linked run.
12. **Inspect AgentRun timeline.** Review sequence, capability, status,
    start/end, duration, retries, dependency skips, and controlled failures.
13. **Inspect observations/artifacts.** Confirm observations are labeled
    untrusted data and large screenshot/log/UI bytes remain referenced artifacts.
14. **Inspect evidence.** Verify audit/plan hash/run/step/artifact/tool hashes and
    provenance.
15. **Generate findings.** Confirm only `MSAP-DYN-*`/existing deterministic rules
    create or update findings. AI/application prose alone creates none.
16. **Inspect risk/compliance score.** Confirm existing deterministic scoring is
    recalculated; informational runtime observations do not inflate risk.
17. **Open report.** Select **View Assessment Report** and inspect the approved
    plan, execution, evidence, findings, scores, artifact metadata, provenance,
    status, and limitations. Download the existing PDF if desired.
18. **Request next assessment recommendation.** On a completed run, select
    **Recommend Next Assessment**.
19. **Inspect proposed adaptive plan.** Confirm it preserves audit, target,
    objective, and scope; has a new hash; uses only gateway capabilities; and
    clearly requires auditor approval. No AgentRun is created.
20. **Approve adaptive plan.** Validate and approve it as a new authorization.
    The approval step still does not execute tools.
21. **Execute second assessment if desired.** Select execution explicitly and
    review a new AgentRun. The lineage is capped at two adaptive cycles and
    cannot recursively auto-run.

For a development-only AndroGoat acceptance fixture, run
`python manage.py seed_androgoat_finding_demo --audit-id <id> --dev-fixture`.
The command refuses non-DEBUG environments and requires the audit's verified
package to be `owasp.sat.agoat`. Local demo mode may use the deterministic
provider; the real acceptance uses backend-only `gpt-5.6-luna`. Viewer can
inspect plans but cannot approve or run them.

For Sprint D1 contract acceptance, inspect the plan detail response and confirm
that `normalized_plan.contract_version` is `msap.assessment-plan/v1`, steps have
stable IDs/action types and manifest-derived bounds, and the plan hash is
present. Approval must still leave the AgentRun count and emulator unchanged.
Raw `generated_plan` content is planner intent only; it must never be copied to
a runner, shell, Frida CLI, or host-agent request.

At every phase identify the provenance label: **AI generated**, **schema
validated**, **policy accepted**, **auditor approved**, **actually executed**,
**observed**, **deterministic finding**, or **report output**. No phase silently
promotes data from one label into another.

## Operational checks

Dynamic Lab reports:

- Host agent online or offline.
- Emulator online or offline.
- MinIO online or offline.
- Celery online or offline.

The standalone manual screenshot control is transient browser state. Screenshots
captured by approved AgentRuns use the existing bounded artifact/evidence path
and appear in report metadata. Device events are retained for sync, screenshot,
install, launch, force stop, clear data, and uninstall actions.

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

## Approved execution-agent boundary

The bounded MVP execution agent consumes only an approved, hash-matching plan,
uses the existing run-scoped gateway, and never receives host-agent, database,
MinIO, Docker, shell, repository, or provider credentials. Django validates and
audits every tool call.

The D1 executor-facing contract remains a hash-checked projection of a
persisted, validated, explicitly approved canonical plan and cannot be
constructed from arbitrary raw model text. The execution endpoint accepts no
tools or arguments. Tool identifiers describe intent; the gateway independently
authorizes every invocation.
