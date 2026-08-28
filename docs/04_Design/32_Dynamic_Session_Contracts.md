# Dynamic Session Contracts

## Purpose

This document defines the contracts for dynamic-analysis jobs, sessions, stages,
events, and artifacts. The corresponding Django models, serializers, API views,
and orchestration foundations are implemented. Individual runtime capabilities
remain subject to the Host Agent, device, approval, and coverage contracts.

Dynamic sessions are bounded evidence-collection workflows. A session may
produce findings only when runtime behavior, static context, or configuration
evidence supports the result. Missing dynamic coverage must be represented as
`NOT_EVALUATED` or `REVIEW_REQUIRED`, not PASS.

## Contract Overview

| Contract | Purpose |
| --- | --- |
| `DynamicAnalysisJob` | Queue-level request to run dynamic or combined analysis. |
| `DynamicSession` | Runtime execution record bound to one audit/APK/device/lease. |
| `DynamicSessionStage` | Timed execution segment matching the state machine. |
| `DynamicSessionEvent` | Immutable event log for orchestration and diagnosis. |
| `DynamicSessionArtifact` | Normalized metadata for dynamic evidence and raw object references. |

## Enumerations

### Session Mode

| Value | Meaning |
| --- | --- |
| `DYNAMIC_ONLY` | Runtime analysis without requiring static correlation. |
| `COMBINED` | Runtime analysis plus correlation with existing static artifacts and findings. |

### Interaction Mode

| Value | Meaning |
| --- | --- |
| `PASSIVE` | Launch and observe without UI automation beyond lifecycle controls. |
| `BASIC_AUTOMATION` | Bounded generic UI exercise such as launch, tap, scroll, and back. |
| `SCRIPTED_SCENARIO` | Operator-reviewed deterministic script for a known app workflow. |
| `AUTHORIZED_LOGIN_SCENARIO` | Scripted workflow using explicitly authorized credentials supplied through secure runtime channels. |

### Tool Profile

| Value | Meaning |
| --- | --- |
| `ADB_ONLY` | ADB/logcat/device-state collection only. |
| `NETWORK_CAPTURE` | ADB plus mitmproxy capture. |
| `FRIDA_BASIC` | ADB plus basic Frida runtime hooks. |
| `FRIDA_EXTENDED` | ADB plus broader Frida instrumentation. |
| `FULL` | ADB, network capture, Frida, and UI automation where configured. |

### Dynamic Job Status

| Value | Meaning |
| --- | --- |
| `QUEUED` | Accepted and waiting for worker execution. |
| `RUNNING` | Worker has started orchestration. |
| `COMPLETED` | Session completed and cleanup succeeded. |
| `FAILED` | Session failed after cleanup attempt or before device lease. |
| `CANCELLED` | Operator/user cancellation completed after cleanup attempt where needed. |

### Cleanup Status

| Value | Meaning |
| --- | --- |
| `NOT_STARTED` | Cleanup has not begun. |
| `IN_PROGRESS` | Cleanup is running. |
| `SUCCEEDED` | Device and host runtime state were restored. |
| `FAILED` | Cleanup failed and quarantine is required. |
| `PARTIAL` | Some cleanup steps succeeded but final integrity is not proven. |

### Failure Categories

`DEVICE_UNAVAILABLE`, `SNAPSHOT_RESTORE_FAILED`, `APK_INSTALL_FAILED`,
`APP_LAUNCH_FAILED`, `PROXY_FAILED`, `TLS_INTERCEPTION_FAILED`,
`FRIDA_START_FAILED`, `FRIDA_SCRIPT_FAILED`, `UI_AUTOMATION_FAILED`,
`EVIDENCE_COLLECTION_FAILED`, `RULE_EVALUATION_FAILED`, `CLEANUP_FAILED`,
`TIMEOUT`, `OPERATOR_CANCELLED`, and `UNKNOWN`.

## DynamicAnalysisJob

### Purpose

`DynamicAnalysisJob` represents the queued request and scheduling policy for a
dynamic run. It is the bridge between an authenticated audit workflow and the
asynchronous dynamic worker.

### Fields

| Field | Meaning |
| --- | --- |
| `id` | Stable job identifier. |
| `audit` | Required relationship to `Audit`. |
| `apk` | Required relationship to `APKFile`. |
| `requested_by` | Authenticated user or service identity. |
| `status` | Job status from the controlled set above. |
| `session_mode` | `DYNAMIC_ONLY` or `COMBINED`. |
| `interaction_mode` | Requested interaction profile. |
| `tool_profile` | Requested tooling profile. |
| `required_capabilities` | Scheduler requirements, such as API level, ABI, Frida, or mitmproxy. |
| `timeout_policy` | Maximum queue, lease, stage, and session durations. |
| `retry_policy` | Bounded retry rules for transient scheduler/worker failures. |
| `cleanup_policy` | Required cleanup actions and quarantine triggers. |
| `created_at` | Job creation time. |
| `started_at` | First worker start time. |
| `finished_at` | Terminal time. |
| `failure_category` | Controlled failure category when failed. |
| `failure_summary` | Bounded redacted failure summary. |

### Relationships

- Required: `Audit`, `APKFile`.
- Creates one primary `DynamicSession`.
- May reference resulting `RuleEvaluation`, `Finding`, and
  `SuspiciousIndicator` records through the session and evidence graph.

### Validation Rules

- `COMBINED` requires completed or available static artifacts for the audit.
- `AUTHORIZED_LOGIN_SCENARIO` requires an explicit authorization record and
  secrets supplied outside persisted normalized fields.
- Tool profile must be satisfiable by matched device capabilities.
- Jobs must be cancellable before or during execution.

### Example JSON

```json
{
  "id": "dyn_job_1001",
  "audit": "audit_1001",
  "apk": "apk_1001",
  "requested_by": "analyst_01",
  "status": "QUEUED",
  "session_mode": "COMBINED",
  "interaction_mode": "BASIC_AUTOMATION",
  "tool_profile": "FULL",
  "required_capabilities": {
    "api_level_min": 35,
    "abi": "x86_64",
    "frida": true,
    "mitmproxy": true
  },
  "timeout_policy": {
    "queue_seconds": 900,
    "session_seconds": 1800,
    "cleanup_seconds": 180
  },
  "retry_policy": {
    "transient_adb_retries": 1,
    "minio_upload_retries": 3
  },
  "cleanup_policy": {
    "uninstall_target": true,
    "reset_proxy": true,
    "quarantine_on_uncertain_integrity": true
  }
}
```

## DynamicSession

### Purpose

`DynamicSession` is the source of truth for one runtime execution. It carries
the state-machine state, selected device, lease, snapshot, tool flags, cleanup
status, and summary.

### Required Fields

| Field | Meaning |
| --- | --- |
| `audit_id` | Audit under assessment. |
| `apk_id` | APK being executed. |
| `device_id` | Leased device. |
| `lease_id` | Active or historical lease. |
| `snapshot_id` | Restored baseline snapshot. |
| `state` | Current state from the dynamic lab state machine. |
| `state_reason` | Bounded reason for current state. |
| `started_at` | Runtime start timestamp. |
| `finished_at` | Terminal timestamp. |
| `duration_seconds` | Runtime duration excluding or including cleanup by policy; reports must state which. |
| `tool_versions` | Tool versions, including Frida `17.16.4` and mitmproxy `12.2.3` when used. |
| `network_capture_enabled` | Whether network capture was requested and started. |
| `frida_enabled` | Whether Frida instrumentation was requested and started. |
| `runtime_ca_enabled` | Whether runtime CA overlay was requested and injected. |
| `ui_automation_enabled` | Whether UI automation ran. |
| `cleanup_status` | Cleanup status from the controlled set. |
| `quarantine_required` | Whether device integrity is uncertain. |
| `summary` | Redacted session summary and coverage notes. |

### Relationships

- Required: `Audit`, `APKFile`, `Device`, `DeviceLease`, `EmulatorSnapshot`.
- Has many `DynamicSessionStage`, `DynamicSessionEvent`, and
  `DynamicSessionArtifact` records.
- Links to `ObjectStorageReference` through artifacts for raw evidence.
- Produces or enriches `RuleEvaluation`, `Finding`, `SuspiciousIndicator`,
  `NormalizedArtifact`, and `Evidence` records.

### Policies

| Policy | Contract |
| --- | --- |
| Timeout | Every stage has a bounded timeout; total session timeout moves to cleanup. |
| Retry | Retry only transient infrastructure errors with bounded backoff. Invalid APK contracts and deterministic analyzer failures are not retried blindly. |
| Cleanup | Cleanup runs after success, failure, timeout, or cancellation when runtime state may exist. |
| Cancellation | Cancellation records the request, stops new work, and enters cleanup where needed. |

### Example JSON

```json
{
  "audit_id": "audit_1001",
  "apk_id": "apk_1001",
  "device_id": "dev_01",
  "lease_id": "lease_1001",
  "snapshot_id": "snap_instrumented_base",
  "state": "EXERCISING_APP",
  "state_reason": "Basic automation is running",
  "started_at": "2026-08-05T10:06:00Z",
  "finished_at": null,
  "duration_seconds": 420,
  "tool_versions": {
    "frida": "17.16.4",
    "mitmproxy": "12.2.3"
  },
  "network_capture_enabled": true,
  "frida_enabled": true,
  "runtime_ca_enabled": true,
  "ui_automation_enabled": true,
  "cleanup_status": "NOT_STARTED",
  "quarantine_required": false,
  "summary": {
    "coverage": "runtime collection in progress"
  }
}
```

## DynamicSessionStage

### Purpose

`DynamicSessionStage` records state-machine timing, retries, outcome, and
coverage for each orchestration stage.

### Fields

| Field | Meaning |
| --- | --- |
| `id` | Stable identifier. |
| `session` | Owning `DynamicSession`. |
| `state` | State-machine state represented by this stage. |
| `attempt` | Attempt number. |
| `started_at` | Stage start. |
| `finished_at` | Stage finish. |
| `timeout_seconds` | Stage timeout. |
| `status` | `RUNNING`, `SUCCEEDED`, `FAILED`, `SKIPPED`, `CANCELLED`, or `TIMED_OUT`. |
| `failure_category` | Controlled failure category when applicable. |
| `coverage_status` | `FULL`, `PARTIAL`, `NOT_COLLECTED`, or `NOT_APPLICABLE`. |
| `summary` | Bounded redacted summary. |

### Relationships

- Belongs to `DynamicSession`.
- May reference artifacts and events emitted during the stage.

### Example JSON

```json
{
  "id": "stage_01",
  "session": "dyn_session_1001",
  "state": "STARTING_CAPTURE",
  "attempt": 1,
  "started_at": "2026-08-05T10:08:00Z",
  "finished_at": "2026-08-05T10:08:08Z",
  "timeout_seconds": 60,
  "status": "SUCCEEDED",
  "failure_category": null,
  "coverage_status": "FULL",
  "summary": "mitmproxy capture started"
}
```

## DynamicSessionEvent

### Purpose

`DynamicSessionEvent` is an immutable event stream for worker progress,
diagnostics, invalid transitions, cancellation, heartbeat, cleanup, and
quarantine decisions.

### Fields

| Field | Meaning |
| --- | --- |
| `id` | Stable identifier. |
| `session` | Owning session. |
| `stage` | Optional stage. |
| `event_type` | Controlled event label. |
| `severity` | `INFO`, `WARNING`, `ERROR`, or `CRITICAL`. |
| `occurred_at` | Event timestamp. |
| `actor` | Worker, scheduler, analyzer, or operator. |
| `message` | Bounded redacted message. |
| `details` | Structured redacted details. |

### Relationships

- Belongs to `DynamicSession`.
- Optionally belongs to `DynamicSessionStage`.

### Example JSON

```json
{
  "id": "sess_evt_01",
  "session": "dyn_session_1001",
  "stage": "stage_01",
  "event_type": "CAPTURE_READY",
  "severity": "INFO",
  "occurred_at": "2026-08-05T10:08:08Z",
  "actor": "mitmproxy-controller",
  "message": "Network capture listener ready",
  "details": {
    "listener": "android-proxy",
    "redaction": "raw flow stored in object storage"
  }
}
```

## DynamicSessionArtifact

### Purpose

`DynamicSessionArtifact` tracks normalized dynamic evidence and raw object
references created during a session.

### Fields

| Field | Meaning |
| --- | --- |
| `id` | Stable identifier. |
| `session` | Owning session. |
| `artifact_type` | Type from the dynamic evidence schema. |
| `normalized_artifact` | Optional relationship to `NormalizedArtifact`. |
| `object_storage_reference` | Optional relationship to `ObjectStorageReference`. |
| `evidence` | Optional relationship to `Evidence`. |
| `sequence_number` | Session-local ordering. |
| `timestamp` | Artifact event time. |
| `tool` | Collector that produced the artifact. |
| `redaction_state` | Redaction state from the evidence schema. |
| `confidence` | Confidence in normalized interpretation. |
| `manual_validation_required` | Whether analyst validation is required. |
| `summary` | Bounded normalized summary. |

### Relationships

- Belongs to `DynamicSession`.
- May link to `ObjectStorageReference` for large or raw artifacts.
- May create or enrich `RuleEvaluation`, `Finding`, `SuspiciousIndicator`,
  `NormalizedArtifact`, and `Evidence`.

### Example JSON

```json
{
  "id": "dyn_art_01",
  "session": "dyn_session_1001",
  "artifact_type": "NETWORK_FLOW",
  "normalized_artifact": "norm_art_2201",
  "object_storage_reference": "obj_ref_5501",
  "evidence": "evidence_3301",
  "sequence_number": 42,
  "timestamp": "2026-08-05T10:12:30Z",
  "tool": "mitmproxy",
  "redaction_state": "REDACTED",
  "confidence": "STRONG",
  "manual_validation_required": false,
  "summary": "Observed HTTP request to static-correlated endpoint"
}
```

## Implementation Notes

- Store metadata and bounded normalized summaries in PostgreSQL.
- Store large logs, screenshots, screen recordings, flow files, and binary
  evidence in MinIO through `ObjectStorageReference`.
- Do not persist secrets, passwords, session IDs, cookies, tokens, private keys,
  or personal data in normalized fields.
- Analyzer failure does not automatically mean vulnerability.
- `NOT_EVALUATED` must not be counted as PASS.
