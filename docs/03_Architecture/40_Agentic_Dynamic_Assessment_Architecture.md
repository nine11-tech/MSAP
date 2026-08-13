# Agentic Dynamic Assessment Architecture

## Purpose and current scope

Sprint D adds a persistent, plan-only AI assessment planner above the accepted
Sprint C2/C3 deterministic mobile evidence runtime. The planner can use GPT-5.5
through a backend provider abstraction, or a deterministic provider for local
development and tests. It cannot execute tools, perform autonomous pentesting,
confirm vulnerabilities, or produce malware verdicts.

An authenticated Analyst or Admin can request one of two objectives:

- `DEVICE_READINESS_CHECK`: device status followed by a screenshot.
- `BASIC_APP_INTERACTION_CHECK`: status, optional verified APK installation,
  launch, screenshot, bounded UI/log evidence, optional caller-supplied tap and
  text, and force stop.

Tap coordinates and text are never invented. Missing optional actions are
persisted as `SKIPPED` with an explicit reason.

## Architecture

```text
Auditor (session authentication + CSRF)
    |
    v
Django plan API (RBAC + audit-authorized target)
    |
    v
Planner provider (OpenAI GPT-5.5 or deterministic local provider)
    |
    v
Strict plan schema + backend policy validator
    |
    v
Persistent GENERATED -> VALIDATED -> APPROVED plan

No execution edge exists from an AssessmentPlan in Sprint D.

Existing deterministic execution remains separate:

Browser (fixed objective input only)
    |
    v
Django run API (RBAC, audit/APK ownership, typed input validation)
    |
    v
Agent Controller (deterministic objective plan)
    |
    +--> Internal Controller
    |
    +--> Ephemeral Container Sandbox
             |
             v
       Run-scoped Django Tool Gateway
             |
             v
Django Host-Agent Client (host token remains backend-only)
    |
    v
Allowlisted Host Agent actions -> Managed Android Emulator
```

The browser chooses an objective, runtime enum, authorized audit/app target,
and bounded optional interaction values. It cannot choose a tool list, command,
executable, filesystem path, container image, environment variable, or prompt.

The container calls only
`POST /api/dynamic/agent/runs/{id}/tool-call/`. Its short-lived run credential is
stored by Django only as a digest and is bound to one run. Before each action,
Django checks the token, expiry, run state, persisted step order, tool name, and
exact resolved arguments. Values derived at runtime are limited to the package
name returned by `install_verified_apk` and the collector ID returned by
`start_logcat`.

## Deterministic mobile tool manifest

The backend manifest contains only:

1. `get_device_status`
2. `list_packages`
3. `install_verified_apk`
4. `launch_package`
5. `force_stop_package`
6. `clear_package_data`
7. `take_screenshot`
8. `start_logcat`
9. `stop_logcat`
10. `get_logcat_excerpt`
11. `dump_ui`
12. `tap_coordinates`
13. `type_text`
14. `frida_status`
15. `frida_ps`
16. `frida_setup`
17. `frida_attach`
18. `frida_run_js`

Every schema rejects unknown fields. Package names use a strict Android package
regex. APK installation accepts IDs only, verifies that the APK belongs to the
audit, requires a `VERIFIED` object, checks size/signature/SHA-256, and then
reuses the backend-to-host APK byte stream. No local path crosses the browser or
sandbox boundary.

`clear_package_data` requires `confirm=true` and an Analyst/Admin requester. It
is deliberately absent from the current deterministic objectives. Uninstall is
not in the agent tool manifest.

Coordinates are numeric and bounded twice: the backend applies a hard schema
limit and the host agent checks the reported device dimensions when available.
Text is limited to 128 characters, rejects controls and shell metacharacters,
uses fixed ADB argv, and is persisted only as length plus a redacted preview.

## Evidence primitives

- Screenshot: bounded PNG metadata, dimensions, size, digest, and capture time.
- UI hierarchy: bounded XML processing, node count, redacted visible-text and
  resource-ID samples, bounded raw preview, focused package, and XML digest.
- Logcat: bounded completed capture, package PID filter when available, at most
  100 excerpt lines returned to the objective, and redaction status.

The Sprint C2 logcat implementation is a completed bounded capture, not a live
collector. It returns a real collector ID for excerpt lookup. `stop_logcat`
truthfully returns `supported=false` and `stopped=false` for that completed
capture rather than faking success.

These records are evidence primitives only. Instrumentation screenshots are
stored in the evidence bucket through `ObjectStorageReference`; PostgreSQL
stores only their bounded metadata, digests, and linkage. Raw huge XML/log
output is not exposed by default.

## Sprint C3 real Frida instrumentation

The Frida tools use the managed emulator serial and fixed host-agent argv only.
`frida_status` requires a real `frida-ps` RPC enumeration and, when the target
is running, a real in-process attach probe. Binary presence alone cannot produce
PASS. `frida_setup` records before state, fixed setup actions, after state, and
post-setup RPC verification. Client/server versions must agree.

`frida_run_js` is the only code-bearing action. Its bounded JavaScript is sent
to the selected Android application through Frida; it is never interpreted as
a host command. Script size, timeout, event count/size, logcat, and screenshot
capture are bounded. Analyst custom scripts require explicit confirmation and
are redacted from persisted objective and step inputs after execution.

The built-in `Frida — Runtime UI Modification Proof` is backend-owned and uses
a fixed sentinel in the deterministic plan. Django resolves that sentinel to
the canonical JavaScript; the sandbox cannot substitute source. The proof
launches the target, captures before screenshot/UI evidence, verifies Frida and
attach, changes the focused Activity title on Android's UI thread, requires the
structured `ui_modification` event, captures after screenshot/UI evidence and
bounded PID-filtered logcat, compares digests, then force-stops the app. A proof
run cannot succeed without both the successful event and a changed screenshot.

Each proof/custom run also creates a bounded instrumentation evidence record
containing run/package/PID/device/version/script metadata, timing, attach and
event/error counts, before/after digests, logcat digest/summary, interpretation,
and limitations. This proves runtime instrumentation, not a vulnerability.

## Security boundaries

- Host-agent authentication remains only in Django's backend client. It is
  never passed to the browser or sandbox.
- Host actions use fixed argv and `shell=False`; there is no arbitrary command,
  path, process, ADB, or environment inspection tool.
- Responses, package lists, UI values, XML previews, log lines, text, timeouts,
  and coordinates are bounded and normalized before persistence.
- Every executed or skipped step is audited. Destructive and navigation actions
  additionally create host-agent action records when a managed device exists.
- Viewer is read-only. Only Analyst/Admin can create runs. Django sessions,
  CSRF middleware, django-axes, and existing RBAC remain enabled.
- The sandbox remains non-root, read-only, unprivileged, capability-free, and
  resource bounded, without mounts, Docker socket, host network, repository,
  SSH, Git, database, MinIO, or host-agent credentials.
- The sandbox receives only run ID, gateway URL, run token, fixed objective, and
  the validated bounded objective input required to reproduce the plan.

## Sprint D AI assessment planner

`AssessmentPlan` stores the audit, authorized package, objective, scope,
provider/model identity, generated and normalized JSON, planner-input hash,
plan hash, lifecycle state, validation result, and timestamps.
`AssessmentPlanStep` stores a stable identifier, deterministic sequence,
rationale, structured tool references and arguments, expected observation,
success condition, bounded evidence requirements, dependencies, and state.

The planner capability source is the existing `TOOL_MANIFEST`; no second tool
registry exists. Provider output is strict JSON and is rejected before plan
creation when it contains unknown fields/tools, malformed tool arguments,
unauthorized packages/APKs, dependency cycles, excessive steps/evidence,
arbitrary Frida source, shell/path/environment/Docker/credential instructions,
or unsupported/unbounded behavior. The only Frida JavaScript a generated plan
may reference is the backend-owned built-in proof sentinel. The provider is not
given OpenAI-hosted tools or an MSAP execution endpoint.

The backend builds bounded planner context from persisted MSAP data only:
audit identity, authorized APK metadata, a bounded finding summary, persisted
device capabilities, and the public schemas of the real gateway manifest.
Unavailable context is represented explicitly. It does not query or mutate the
emulator while planning. Only a SHA-256 of the sanitized planner input is
persisted; API credentials and raw prompts are not stored.

The OpenAI provider uses the Responses API with model `gpt-5.5` and strict
JSON-schema output. Provider/model/key/timeout configuration is backend-only.
Local development and tests default to `DETERMINISTIC`, which produces the same
validated six-step AndroGoat-compatible plan without an API key.

Plan API lifecycle:

1. Analyst/Admin creates a structurally and policy-checked `GENERATED` plan.
2. Analyst/Admin explicitly promotes it to `VALIDATED`; policy is rerun.
3. Analyst/Admin approves it, producing `APPROVED` state only.
4. Viewer can list and inspect plans but cannot mutate them.

Approval never creates an `AgentRun`, calls the run-scoped gateway, contacts the
host agent, or changes emulator state. The future GPT-5.5 execution agent must
consume only an approved plan and remain behind the existing gateway and policy
boundaries.

### Sprint D1 planner/executor contracts

Provider output is untrusted planner **intent**, not executor input. Existing
deterministic/provider output is accepted through a compatibility adapter, then
normalized into the closed `msap.assessment-plan/v1` contract. That canonical
document contains provider/model and audit traceability, the authorized package,
objective and scope, fixed plan constraints, and ordered steps. Each canonical
step has a stable identifier and sequence, one of the supported action types,
structured tool references and arguments, dependencies, evidence and success
requirements, an explicit destructive-step approval flag, and resource limits
derived from the real `TOOL_MANIFEST` timeouts.

The normalization path is deliberately one-way:

```text
raw provider JSON
    -> legacy intent schema validation
    -> contextual plan policy validation
    -> msap.assessment-plan/v1 normalization
    -> canonical contract validation + SHA-256
    -> persisted plan
    -> auditor validation and approval
    -> msap.approved-assessment-plan/v1 projection (future executor input)
```

The approved executor projection can be built only from a persisted
`AssessmentPlan` whose state is `APPROVED`, whose validation state is `PASSED`,
whose approval actor/time exist, and whose canonical JSON still matches the
persisted plan hash and audit/package/provider fields. It contains no raw
provider response. Passing arbitrary LLM text to this boundary is rejected; D1
does not parse text into execution requests.

Validation boundaries remain distinct:

- **Schema/contract validation** closes fields, types, identifiers, tool
  capability vocabulary, arguments, dependencies, sizes, evidence values,
  action types, and manifest-derived resource bounds. Host command/path,
  credential, environment, Docker, subprocess, and arbitrary Frida-source
  representations have no executable contract shape.
- **Plan policy validation** checks the selected audit and authorized package,
  package/audit arguments, the built-in-only planner Frida proof, and explicit
  destructive scope. D3 may extend this layer without changing either contract.
- **Approval** records auditor authorization for the canonical plan. It does not
  authorize an individual tool invocation or cause execution.
- **Execution authorization** remains future work. Every eventual tool call must
  still pass the run-scoped token, persisted step order, RBAC/scope policy, real
  gateway manifest schema, and backend/host-agent enforcement.

A recognized tool identifier therefore expresses a requested capability only;
it is never a permission. The model is neither the schema, policy, approval, nor
execution security boundary. The deterministic planner remains the local/test
fallback, compatibility reference, and safe fixture for future executor work.

## Remaining limitations

- Execution remains synchronous in the API request lifecycle.
- Logcat uses bounded completed captures rather than live streaming sessions.
- Package list version metadata is returned only when the host can obtain it;
  unavailable values remain empty/null.
- Full UI XML and unbounded log streams are intentionally not retained.
- No GPT execution agent, chat UI, autonomous plan execution, mitmproxy tool,
  MASVS playbook, vulnerability confirmation, malware verdict, or autonomous
  interaction is implemented.
- D1 does not schedule approved plans, convert them to `AgentRun` records, or
  implement the D3 policy engine. The approved executor projection is a guarded
  data contract only; D4 will consume it through a separate execution service.
