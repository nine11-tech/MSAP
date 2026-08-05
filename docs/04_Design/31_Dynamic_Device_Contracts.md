# Dynamic Device Contracts

## Purpose

This document defines the Phase 3 implementation contracts for dynamic-lab
device inventory, capability matching, exclusive leasing, emulator snapshots,
and operational events. These are model contracts for Phase 4 design only; they
are not Django model definitions yet.

The contracts preserve a strict distinction between lab readiness, runtime
evidence collection, and security findings. A healthy device enables dynamic
analysis; it does not imply that the assessed APK is safe or unsafe.

## Contract Overview

| Contract | Purpose |
| --- | --- |
| `Device` | A schedulable Android emulator or future physical device. |
| `DevicePool` | A scheduling group with shared policy, capacity, and ownership. |
| `DeviceCapability` | A normalized capability used by the scheduler and analyzers. |
| `DeviceLease` | An exclusive, time-bounded reservation for one audit/job/session. |
| `EmulatorSnapshot` | A named, validated baseline or session snapshot. |
| `DeviceEvent` | An immutable operational event for auditability and diagnosis. |

## Device

### Purpose

`Device` represents one Android runtime target controlled by MSAP. The validated
initial device is the Windows-owned Android emulator operated from WSL2.

### Main Fields

| Field | Meaning |
| --- | --- |
| `id` | Stable database identifier. |
| `name` | Human-readable lab name, for example `Pixel 7 API 35 dynamic lab`. |
| `serial` | ADB serial such as `emulator-5554`. Must be unique while active. |
| `kind` | `EMULATOR` initially; future values may include `PHYSICAL`. |
| `host_type` | Host ownership model, for example `WINDOWS_WSL2`. |
| `host_identifier` | Stable host label controlled by the operator, not a secret. |
| `status` | Scheduler state from the controlled status set below. |
| `api_level` | Android API level, validated as `35` for the current lab. |
| `android_version` | Android release string reported by the device. |
| `abi` | Primary ABI, validated as `x86_64` for the current lab. |
| `avd_name` | Local AVD name, when applicable. |
| `is_rooted` | Whether rooted adbd is available for lab controls. |
| `selinux_mode` | Expected to remain `Enforcing`. |
| `has_frida` | Whether the validated Frida server is staged and usable. |
| `has_mitm_ready` | Whether mitmproxy CA staging/proxy prerequisites are ready. |
| `current_snapshot` | Reference to the current known snapshot when known. |
| `last_seen_at` | Last successful low-level device contact. |
| `last_health_check_at` | Last full preflight or worker health check. |
| `quarantine_reason` | Operator-visible reason when status is `QUARANTINED`. |
| `notes` | Bounded operator notes; must not contain secrets or client data. |

### Status Values

| Status | Meaning |
| --- | --- |
| `AVAILABLE` | Eligible for scheduling. |
| `LEASED` | Reserved by an active lease but not yet executing app work. |
| `PREPARING` | Snapshot restore, health check, or tool staging is in progress. |
| `BUSY` | A dynamic session is actively using the device. |
| `OFFLINE` | Device is not reachable. |
| `UNHEALTHY` | Device is reachable but failed health checks. |
| `QUARANTINED` | Device integrity is uncertain and operator recovery is required. |
| `MAINTENANCE` | Operator intentionally removed the device from scheduling. |

### Indexes and Constraints

| Constraint | Purpose |
| --- | --- |
| Unique active `serial` | Prevent two schedulable devices from sharing one ADB target. |
| Index on `status` | Fast scheduler lookup. |
| Index on `api_level`, `abi`, `has_frida`, `has_mitm_ready` | Capability matching. |
| Unique `name` within `host_identifier` | Operator clarity. |

### Relationships

- Belongs to zero or one `DevicePool`.
- Has many `DeviceCapability` records.
- Has many `DeviceLease` records.
- Has many `EmulatorSnapshot` records when `kind = EMULATOR`.
- Has many `DeviceEvent` records.

### Lifecycle

`MAINTENANCE` or `OFFLINE` -> operator preflight -> `AVAILABLE` -> lease ->
`LEASED`/`PREPARING`/`BUSY` -> cleanup -> `AVAILABLE`. Any uncertain cleanup,
permanent CA drift, SELinux drift, stale lease with runtime state, or failed
integrity check moves the device to `QUARANTINED`.

### Validation Rules

- `serial`, `kind`, `host_type`, `status`, `api_level`, and `abi` are required.
- `selinux_mode` must be `Enforcing` for schedulable Android devices.
- `is_rooted` must be true for the validated emulator profile.
- `has_frida` is true only when the staged server and client version match the
  validated Frida version `17.16.4`.
- `has_mitm_ready` is true only when proxy prerequisites and CA staging match the
  validated mitmproxy environment `12.2.3`.
- `QUARANTINED` requires a non-empty `quarantine_reason`.

### Security Rules

- Do not store private CA material, APK paths, credentials, cookies, tokens, or
  client evidence in `notes`.
- A device in `QUARANTINED`, `OFFLINE`, `UNHEALTHY`, or `MAINTENANCE` must not
  be scheduled.
- Rooted access is a lab control; it must not be exposed to APK-controlled input.
- The scheduler must never reuse an expired lease without cleanup or quarantine.

### Example JSON

```json
{
  "id": "dev_01",
  "name": "Windows WSL2 API 35 emulator",
  "serial": "emulator-5554",
  "kind": "EMULATOR",
  "host_type": "WINDOWS_WSL2",
  "host_identifier": "local-dynamic-lab-01",
  "status": "AVAILABLE",
  "api_level": 35,
  "android_version": "15",
  "abi": "x86_64",
  "avd_name": "msap-api35",
  "is_rooted": true,
  "selinux_mode": "Enforcing",
  "has_frida": true,
  "has_mitm_ready": true,
  "current_snapshot": "msap-instrumented-base",
  "last_seen_at": "2026-08-05T10:00:00Z",
  "last_health_check_at": "2026-08-05T10:01:00Z",
  "quarantine_reason": "",
  "notes": "Validated local lab emulator"
}
```

## DevicePool

### Purpose

`DevicePool` groups devices under one scheduling and operational policy.
Phase 4 should support a single local pool first, while leaving room for future
GitLab runner pools.

### Fields

| Field | Meaning |
| --- | --- |
| `id` | Stable identifier. |
| `name` | Operator-visible pool name. |
| `pool_type` | `LOCAL_WORKSTATION`, future `GITLAB_RUNNER`, or future `DEDICATED_LAB`. |
| `enabled` | Whether the scheduler may use this pool. |
| `max_concurrent_sessions` | Initial value should be `1`. |
| `default_timeout_seconds` | Default session lease timeout. |
| `allowed_modes` | Supported session modes such as `DYNAMIC_ONLY`, `COMBINED`. |
| `notes` | Bounded operational notes. |

### Indexes and Constraints

- Unique `name`.
- Index on `enabled` and `pool_type`.
- `max_concurrent_sessions` must be positive and should default to one for the
  initial dynamic lab.

### Relationships

- Has many `Device` records.
- Applies default policy to `DeviceLease` and `DynamicAnalysisJob`.

### Lifecycle

Created by an operator, enabled only after preflight, disabled during
maintenance, and retired only after all active leases are released.

### Validation and Security Rules

- Disabled pools must not accept new leases.
- Pool notes must not contain secrets or client data.
- Future runner pools must define runner isolation before being enabled.

### Example JSON

```json
{
  "id": "pool_local_01",
  "name": "Local Windows WSL2 dynamic lab",
  "pool_type": "LOCAL_WORKSTATION",
  "enabled": true,
  "max_concurrent_sessions": 1,
  "default_timeout_seconds": 1800,
  "allowed_modes": ["DYNAMIC_ONLY", "COMBINED"],
  "notes": "Single validated emulator pool"
}
```

## DeviceCapability

### Purpose

`DeviceCapability` gives the scheduler and analyzers a normalized way to match
requirements without hard-coding device fields.

### Fields

| Field | Meaning |
| --- | --- |
| `id` | Stable identifier. |
| `device` | Owning `Device`. |
| `capability_type` | Example: `ANDROID_API`, `ABI`, `FRIDA`, `MITMPROXY`, `ROOT`, `SELINUX`. |
| `name` | Capability key. |
| `value` | String, number, or boolean-compatible value. |
| `validated_at` | Last successful validation timestamp. |
| `validation_status` | `VALID`, `STALE`, `FAILED`, or `UNKNOWN`. |
| `details` | Bounded details useful for diagnosis. |

### Indexes and Constraints

- Unique `(device, capability_type, name)`.
- Index `(capability_type, name, value, validation_status)` for matching.

### Relationships

- Belongs to one `Device`.
- Read by `DynamicAnalysisJob` scheduling and analyzer capability checks.

### Lifecycle

Created during inventory, refreshed by preflight and health checks, marked
`STALE` when not validated recently, and marked `FAILED` when the capability is
expected but unavailable.

### Validation and Security Rules

- Details must not include secrets, raw logs, APK package evidence, or private
  network information beyond bounded diagnostic labels.
- Failed required capabilities make the device unschedulable for matching jobs.

### Example JSON

```json
{
  "id": "cap_01",
  "device": "dev_01",
  "capability_type": "FRIDA",
  "name": "version",
  "value": "17.16.4",
  "validated_at": "2026-08-05T10:01:00Z",
  "validation_status": "VALID",
  "details": "Client/server version matched"
}
```

## DeviceLease

### Purpose

`DeviceLease` is the exclusive reservation that prevents concurrent sessions
from using the same device.

### Main Fields

| Field | Meaning |
| --- | --- |
| `device` | Reserved device. |
| `audit` | Associated audit. |
| `job` | Associated dynamic analysis job. |
| `leased_by` | Worker, scheduler, or operator identity. |
| `lease_status` | Controlled status value below. |
| `lease_token` | Unique unguessable token used for idempotent ownership checks. |
| `started_at` | Lease activation time. |
| `expires_at` | Safety expiration time. |
| `released_at` | Release time, when complete. |
| `heartbeat_at` | Last worker heartbeat. |
| `release_reason` | `COMPLETED`, `FAILED`, `CANCELLED`, `EXPIRED`, or `QUARANTINED`. |

### Lease Status Values

| Status | Meaning |
| --- | --- |
| `REQUESTED` | Lease request exists but ownership is not active. |
| `ACTIVE` | Worker owns the device. |
| `EXPIRED` | Lease exceeded its heartbeat/expiry boundary. |
| `RELEASED` | Lease was released after cleanup or quarantine. |
| `FAILED` | Lease acquisition failed. |
| `CANCELLED` | Lease request was cancelled before active use or released after cancellation. |

### Indexes and Constraints

- Unique `lease_token`.
- Only one active lease per device.
- Index on `(lease_status, expires_at)` for recovery workers.
- Index on `(audit, job)` for session lookup.

### Relationships

- Belongs to one `Device`.
- Belongs to one `Audit`.
- Belongs to one `DynamicAnalysisJob`.
- May be referenced by one `DynamicSession`.

### Lifecycle

`REQUESTED` -> `ACTIVE` -> cleanup -> `RELEASED`. If the worker heartbeat
becomes stale, the lease becomes `EXPIRED`, but the device is not reusable until
cleanup succeeds or quarantine is recorded.

### Validation and Security Rules

- Active operations must present the current `lease_token`.
- `expires_at` is required for active leases.
- Releasing a lease requires cleanup success or explicit quarantine.
- Lease tokens must not be logged in public UI or committed to Git.

### Example JSON

```json
{
  "device": "dev_01",
  "audit": "audit_1001",
  "job": "dyn_job_1001",
  "leased_by": "celery-worker-dynamic-01",
  "lease_status": "ACTIVE",
  "lease_token": "opaque-token-reference",
  "started_at": "2026-08-05T10:05:00Z",
  "expires_at": "2026-08-05T10:35:00Z",
  "released_at": null,
  "heartbeat_at": "2026-08-05T10:08:00Z",
  "release_reason": null
}
```

## EmulatorSnapshot

### Purpose

`EmulatorSnapshot` records named emulator baselines and session snapshots used
to restore repeatable dynamic-lab state.

### Main Fields

| Field | Meaning |
| --- | --- |
| `name` | Snapshot name, such as `msap-clean-base` or `msap-instrumented-base`. |
| `device` | Owning emulator device. |
| `snapshot_type` | Controlled type below. |
| `description` | Operator-visible purpose. |
| `api_level` | Android API level snapshot was validated against. |
| `abi` | ABI snapshot was validated against. |
| `contains_frida_binary` | Whether Frida server is staged. |
| `contains_public_ca` | Whether public CA is staged for runtime overlay. |
| `contains_target_apk` | Must be false for reusable base snapshots. |
| `created_at` | Record creation time or imported snapshot time. |
| `validated_at` | Last successful validation. |
| `validation_status` | `VALID`, `STALE`, `FAILED`, or `UNKNOWN`. |

### Snapshot Types

| Type | Meaning |
| --- | --- |
| `CLEAN_BASE` | Clean rooted Android baseline. |
| `INSTRUMENTED_BASE` | Validated baseline with staged public CA and Frida binary. |
| `SESSION_TEMP` | Temporary session snapshot; not a reusable baseline. |
| `MANUAL` | Operator-created snapshot outside normal automation. |

### Indexes and Constraints

- Unique `(device, name)`.
- Index on `(snapshot_type, validation_status, api_level, abi)`.
- Reusable base snapshots must have `contains_target_apk = false`.

### Relationships

- Belongs to one `Device`.
- Referenced by `DynamicSession` as the restored baseline.

### Lifecycle

Created or imported by an operator, validated by preflight, used by workers for
baseline restore, marked stale after host or emulator drift, and never deleted
by normal dynamic-analysis jobs.

### Validation and Security Rules

- `INSTRUMENTED_BASE` must contain the staged public CA and Frida binary, proxy
  disabled, Frida stopped, no target APK installed, and SELinux `Enforcing`.
- Private CA material must never be part of repository-managed metadata.
- Session snapshots must not become reusable baselines without operator
  validation.

### Example JSON

```json
{
  "name": "msap-instrumented-base",
  "device": "dev_01",
  "snapshot_type": "INSTRUMENTED_BASE",
  "description": "Validated Frida and runtime CA staging baseline",
  "api_level": 35,
  "abi": "x86_64",
  "contains_frida_binary": true,
  "contains_public_ca": true,
  "contains_target_apk": false,
  "created_at": "2026-08-04T18:00:00Z",
  "validated_at": "2026-08-05T10:01:00Z",
  "validation_status": "VALID"
}
```

## DeviceEvent

### Purpose

`DeviceEvent` is an immutable record of device health, scheduling, lease,
snapshot, cleanup, and quarantine events.

### Fields

| Field | Meaning |
| --- | --- |
| `id` | Stable identifier. |
| `device` | Related device. |
| `event_type` | Example: `HEALTH_CHECK`, `LEASE_CREATED`, `SNAPSHOT_RESTORED`, `QUARANTINE_SET`. |
| `severity` | `INFO`, `WARNING`, `ERROR`, or `CRITICAL`. |
| `occurred_at` | Event timestamp. |
| `actor` | Worker, scheduler, or operator identity. |
| `lease` | Optional related lease. |
| `session` | Optional related dynamic session. |
| `summary` | Bounded operator-visible text. |
| `details` | Structured redacted diagnostics. |

### Indexes and Constraints

- Index on `(device, occurred_at)`.
- Index on `(event_type, severity)`.
- Index on `(lease, session)` when present.

### Relationships

- Belongs to one `Device`.
- Optionally belongs to one `DeviceLease` and one `DynamicSession`.

### Lifecycle

Events are append-only. Corrections require a new event rather than rewriting
history.

### Validation and Security Rules

- Do not store raw logs, tokens, private CA material, APK payloads, screenshots,
  proxy flows, cookies, or passwords in event details.
- High-severity events that imply uncertain device integrity should move the
  device to `QUARANTINED`.

### Example JSON

```json
{
  "id": "dev_evt_01",
  "device": "dev_01",
  "event_type": "HEALTH_CHECK",
  "severity": "INFO",
  "occurred_at": "2026-08-05T10:01:00Z",
  "actor": "preflight",
  "lease": null,
  "session": null,
  "summary": "Dynamic lab preflight passed",
  "details": {
    "api_level": 35,
    "abi": "x86_64",
    "selinux": "Enforcing",
    "frida_version": "17.16.4",
    "mitmproxy_version": "12.2.3"
  }
}
```
