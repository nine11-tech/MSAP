# Dynamic Lab State Machine

## Purpose

This document defines the authoritative state machine for future dynamic Android
sessions. It is an implementation contract for Django models, Celery workers,
device leases, operator tooling, and frontend progress display.

The state machine is intentionally conservative. Completion includes cleanup.
Failure and cancellation still require cleanup. Quarantine is used when cleanup
fails or device integrity is uncertain. `NOT_EVALUATED` is a rule-evaluation
result and must not be counted as PASS.

## State Definitions

| State | Purpose | Entry condition | Exit condition | Timeout behavior | Failure behavior | Evidence generated | Cleanup responsibility |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `QUEUED` | Record accepted dynamic work before scheduling | Dynamic job created and authorized | Scheduler starts device matching | Job queue TTL exceeded moves to `FAILED` with `TIMEOUT` | Invalid job contract moves to `FAILED` | Job metadata event | None beyond job cancellation marker |
| `WAITING_FOR_DEVICE` | Wait for a compatible healthy device | Scheduler starts matching capabilities | Candidate device selected | Wait timeout moves to `FAILED` with `DEVICE_UNAVAILABLE` | No compatible device or pool disabled moves to `FAILED` | Scheduling event | None |
| `LEASING_DEVICE` | Acquire exclusive device lease | Candidate device selected | Active lease token created | Lease acquisition timeout retries or fails | Race, stale lease, or DB conflict returns to wait or fails | Lease event | Release partial lease if token exists |
| `RESTORING_BASELINE` | Restore known snapshot | Active lease exists | Snapshot restore verified | Restore timeout moves to cleanup | Restore error moves to cleanup and may quarantine | Snapshot restore log/reference | Restore attempt must be recorded; cleanup must verify device |
| `PREPARING_DEVICE` | Verify health and stage runtime controls | Baseline restored | Device health, proxy baseline, Frida staging, CA staging validated | Preparation timeout moves to cleanup | Health mismatch moves to cleanup or quarantine | Health snapshot, environment event | Undo transient preparation when possible |
| `INSTALLING_APK` | Install authorized target APK | Device prepared and APK reference available | Package installed and package name confirmed | Install timeout moves to cleanup | Install error moves to cleanup | Install log, package metadata | Uninstall target package during cleanup |
| `STARTING_CAPTURE` | Start network/log/screen capture | APK installed and capture profile selected | Capture tools report ready | Capture timeout can degrade coverage or fail by policy | Proxy/log collector failure records coverage gap | Capture startup event, raw references | Stop capture and reset proxy |
| `STARTING_INSTRUMENTATION` | Start Frida or other runtime instrumentation | Capture ready or skipped, Frida profile selected | Instrumentation attached or explicitly skipped by profile | Instrumentation timeout can degrade coverage or fail by policy | Script/server error records coverage gap | Frida startup event, script metadata | Stop Frida scripts/server if started |
| `LAUNCHING_APP` | Start target app process/activity | Install complete and tools ready | App foreground/process observed | Launch timeout moves to cleanup with `APP_LAUNCH_FAILED` | Crash, missing launcher, or permission issue records failure | Launch event, logcat excerpt, screenshot if available | Force-stop and uninstall during cleanup |
| `EXERCISING_APP` | Exercise allowed app flows | App launched | Interaction plan completes or duration limit reached | Session duration limit moves to evidence collection | UI automation failure records partial coverage or failure by policy | UI events, screenshots, behavior timeline | Stop automation and preserve collected evidence |
| `COLLECTING_EVIDENCE` | Pull, finalize, normalize, and reference evidence | Exercise complete or early terminal condition | Required evidence persisted and normalized | Collection timeout moves to cleanup with coverage gap | Pull/storage/normalization failure moves to cleanup | Normalized artifacts, raw MinIO references | Stop collectors and preserve partial evidence |
| `EVALUATING` | Evaluate dynamic rules and coverage | Evidence collection complete | Rule evaluations persisted | Evaluation timeout moves to cleanup with `RULE_EVALUATION_FAILED` | Analyzer failure produces `NOT_EVALUATED` or `REVIEW_REQUIRED`, not PASS | Rule evaluations, finding/evidence links | No device cleanup except active collector teardown if needed |
| `REPORTING` | Generate updated JSON/PDF reports | Evaluation complete | Reports persisted or skipped by policy | Report timeout moves to cleanup | Report failure moves to cleanup; session can fail even if evidence exists | Report object references | No device cleanup except active collector teardown if needed |
| `CLEANING_UP` | Restore device and host runtime state | Terminal path requested after success, failure, cancellation, or timeout | Proxy reset, app removed, tools stopped, temp files removed, lease released | Cleanup timeout requires quarantine | Cleanup failure moves to `QUARANTINED` | Cleanup log, final health event | Worker owns cleanup until success/quarantine |
| `COMPLETED` | Mark successful session | Reporting succeeded and cleanup succeeded | Terminal | None | None | Final session summary | Already complete; no active lease |
| `FAILED` | Mark failed session after cleanup attempt | Non-cancel failure occurred and cleanup succeeded or no device was leased | Terminal | None | None | Failure summary, cleanup result | Already attempted; no active lease |
| `CANCELLED` | Mark operator/user cancellation after cleanup attempt | Cancellation requested and cleanup succeeded or no device was leased | Terminal | None | None | Cancellation summary, cleanup result | Already attempted; no active lease |
| `QUARANTINED` | Mark uncertain device integrity | Cleanup failed, integrity check failed, lease expired in unsafe state, or permanent drift detected | Operator intervention clears quarantine in a separate workflow | None | Device unavailable for scheduling | Quarantine event, reason, last health state | Operator owns recovery; scheduler must not use device |

## Valid Transitions

| From | To |
| --- | --- |
| `QUEUED` | `WAITING_FOR_DEVICE`, `CANCELLED`, `FAILED` |
| `WAITING_FOR_DEVICE` | `LEASING_DEVICE`, `CANCELLED`, `FAILED` |
| `LEASING_DEVICE` | `RESTORING_BASELINE`, `WAITING_FOR_DEVICE`, `CANCELLED`, `FAILED`, `CLEANING_UP` |
| `RESTORING_BASELINE` | `PREPARING_DEVICE`, `CLEANING_UP` |
| `PREPARING_DEVICE` | `INSTALLING_APK`, `CLEANING_UP` |
| `INSTALLING_APK` | `STARTING_CAPTURE`, `STARTING_INSTRUMENTATION`, `LAUNCHING_APP`, `CLEANING_UP` |
| `STARTING_CAPTURE` | `STARTING_INSTRUMENTATION`, `LAUNCHING_APP`, `CLEANING_UP` |
| `STARTING_INSTRUMENTATION` | `LAUNCHING_APP`, `CLEANING_UP` |
| `LAUNCHING_APP` | `EXERCISING_APP`, `COLLECTING_EVIDENCE`, `CLEANING_UP` |
| `EXERCISING_APP` | `COLLECTING_EVIDENCE`, `CLEANING_UP` |
| `COLLECTING_EVIDENCE` | `EVALUATING`, `CLEANING_UP` |
| `EVALUATING` | `REPORTING`, `CLEANING_UP` |
| `REPORTING` | `CLEANING_UP` |
| `CLEANING_UP` | `COMPLETED`, `FAILED`, `CANCELLED`, `QUARANTINED` |
| `COMPLETED` | Terminal |
| `FAILED` | Terminal |
| `CANCELLED` | Terminal |
| `QUARANTINED` | Terminal for the session; device recovery is an operator workflow |

## Invalid Transition Handling

Invalid transitions must be rejected with a structured session event containing
the attempted source, target, actor, timestamp, and reason. The persisted session
state must not change. Repeated invalid transitions from a worker should mark the
worker attempt failed and request cleanup if a lease is active.

Terminal states are immutable for the session. Operator recovery may update the
separate `Device` status after a `QUARANTINED` session, but it must not rewrite
the historical session terminal state.

## Idempotency Rules

- Each session state transition must be guarded by the current state and session
  version.
- Device lease creation must use a unique lease token.
- Snapshot restore, APK install, proxy configuration, Frida startup, and cleanup
  operations must tolerate repeated calls.
- Artifact persistence must use deterministic correlation keys or idempotency
  keys to avoid duplicate evidence when a worker retries.
- Report generation must replace or supersede the session report reference
  without duplicating visible final reports.

## Retry Policy

| Area | Policy |
| --- | --- |
| Device matching | Retry until queue timeout while devices are unavailable |
| Lease acquisition | Retry on optimistic-lock conflicts; fail on incompatible or quarantined device |
| Snapshot restore | One bounded retry only if adapter reports a transient host/emulator error |
| Tool startup | Retry once for bridge/proxy startup after cleanup of partial process state |
| APK install | Retry only when the first failure is an ADB transport error; do not retry invalid APK contracts |
| Evidence upload | Retry transient MinIO errors with bounded backoff |
| Rule evaluation | Retry deterministic evaluator failures only after transient dependency errors |
| Cleanup | Retry bounded cleanup steps; quarantine if final health cannot be proven |

## Cancellation Behavior

Cancellation can be requested in any non-terminal state. The worker should move
to `CLEANING_UP` when a device lease or runtime state may exist. If cancellation
arrives before a lease is acquired, the session may transition to `CANCELLED`
directly after recording the cancellation event.

`CANCELLED` must not skip cleanup. If cleanup fails after cancellation, the
terminal state is `QUARANTINED`, with the cancellation reason preserved in the
session summary.

## Quarantine Behavior

`QUARANTINED` means the device must not be scheduled. Triggers include:

- Cleanup failed or timed out.
- Android proxy could not be reset.
- Target APK could not be removed.
- Frida or instrumentation process could not be stopped.
- Runtime CA overlay or temporary files could not be cleared.
- SELinux state drifted from `Enforcing`.
- Permanent CA material was detected.
- Snapshot restore integrity is uncertain.
- Lease expired while the worker heartbeat was stale and runtime state may exist.

Operator recovery must restore a validated baseline and run preflight before the
device returns to `AVAILABLE`.

## Heartbeat and Lease Expiration

Workers must update session and lease heartbeat timestamps during long states.
If heartbeat becomes stale:

- The scheduler must not assign the leased device to another job.
- A recovery worker may attempt cleanup if ownership can be proven.
- If cleanup cannot prove a healthy baseline, the device moves to
  `QUARANTINED`.

Lease expiration is a safety boundary, not permission to reuse the device.
Expired leases require cleanup or quarantine before reuse.

## Cleanup After Partial Failure

Cleanup should execute the safest available subset:

1. Stop UI automation and instrumentation.
2. Stop network capture and close flow files.
3. Reset Android proxy to `:0`.
4. Force-stop and uninstall the target package and temporary probe packages.
5. Remove temporary files, runtime overlays, and staged session artifacts.
6. Stop host bridge processes started by the session.
7. Verify health and baseline invariants.
8. Release the lease only when the final device state is safe or quarantined.

## Operator-Visible Labels

| State | Label |
| --- | --- |
| `QUEUED` | Queued |
| `WAITING_FOR_DEVICE` | Waiting for device |
| `LEASING_DEVICE` | Leasing device |
| `RESTORING_BASELINE` | Restoring baseline |
| `PREPARING_DEVICE` | Preparing device |
| `INSTALLING_APK` | Installing APK |
| `STARTING_CAPTURE` | Starting capture |
| `STARTING_INSTRUMENTATION` | Starting instrumentation |
| `LAUNCHING_APP` | Launching app |
| `EXERCISING_APP` | Exercising app |
| `COLLECTING_EVIDENCE` | Collecting evidence |
| `EVALUATING` | Evaluating behavior |
| `REPORTING` | Generating reports |
| `CLEANING_UP` | Cleaning up |
| `COMPLETED` | Completed |
| `FAILED` | Failed |
| `CANCELLED` | Cancelled |
| `QUARANTINED` | Quarantined |

## Frontend Progress Mapping

| Progress band | States | User-facing meaning |
| --- | --- | --- |
| 0-10% | `QUEUED`, `WAITING_FOR_DEVICE`, `LEASING_DEVICE` | Scheduling and reserving a lab device |
| 10-30% | `RESTORING_BASELINE`, `PREPARING_DEVICE`, `INSTALLING_APK` | Restoring and preparing the emulator |
| 30-45% | `STARTING_CAPTURE`, `STARTING_INSTRUMENTATION`, `LAUNCHING_APP` | Starting runtime tools and app |
| 45-70% | `EXERCISING_APP`, `COLLECTING_EVIDENCE` | Exercising app and collecting evidence |
| 70-90% | `EVALUATING`, `REPORTING` | Evaluating rules and producing reports |
| 90-100% | `CLEANING_UP`, `COMPLETED` | Cleaning up and finalizing |
| Terminal error | `FAILED`, `CANCELLED`, `QUARANTINED` | Stopped, with cleanup/quarantine details |

The frontend must show coverage warnings separately from verdicts. A collector
that did not run, timed out, or failed should surface as partial coverage and
must not imply a PASS result.
