# Dynamic Evidence Schema

## Purpose

This document defines the normalized dynamic evidence types for future MSAP
dynamic Android analysis. It separates raw evidence storage from bounded
normalized summaries and makes coverage, redaction, confidence, and manual
validation explicit.

Dynamic evidence is not a malware verdict. It supports rule evaluation,
findings, suspicious indicators, reports, and static/dynamic correlation only
when the behavior was actually observed or the coverage state is accurately
represented.

## Storage and Privacy Rules

Large logs, screenshots, recordings, flow files, and binary evidence must go to
MinIO through `ObjectStorageReference`. PostgreSQL stores metadata, normalized
summaries, redaction state, confidence, correlation keys, and evidence links.

Normalized fields must not store secrets, cookies, tokens, passwords, session
IDs, private keys, or user personal data in cleartext. When sensitive values are
needed for correlation, store redacted forms, keyed hashes, counts, types, and
object references to protected raw evidence.

## Common Fields

| Field | Meaning |
| --- | --- |
| `artifact_type` | Controlled type listed in this document. |
| `audit_id` | Owning audit. |
| `session_id` | Dynamic session that produced the artifact. |
| `device_id` | Device that produced the artifact. |
| `timestamp` | Event or collection time. |
| `sequence_number` | Session-local ordering. |
| `tool` | Collector or analyzer name. |
| `tool_version` | Tool version where available. |
| `package_name` | Target or observed package. |
| `process_name` | Process name when available. |
| `pid` | Process identifier when available. |
| `thread_id` | Thread identifier when available. |
| `category` | Normalized category such as `network`, `runtime`, or `storage`. |
| `event_name` | Normalized event label. |
| `summary` | Bounded redacted human-readable summary. |
| `normalized` | Structured normalized payload. |
| `raw_reference` | `ObjectStorageReference` for raw/large evidence when present. |
| `redaction_state` | Redaction state from the controlled set below. |
| `confidence` | Confidence in interpretation: `LOW`, `MEDIUM`, `HIGH`, or `CONFIRMED`. |
| `correlation_keys` | Stable keys used for deduplication and static/dynamic correlation. |
| `manual_validation_required` | Whether analyst review is required before treating the evidence as conclusive. |

## Redaction States

| State | Meaning |
| --- | --- |
| `NOT_REQUIRED` | No sensitive content is expected in normalized fields. |
| `REDACTED` | Sensitive content was removed or replaced with safe metadata. |
| `PARTIAL` | Some fields were redacted but raw evidence may still contain sensitive content. |
| `REDACTION_FAILED` | Normalized fields must not be used for reporting until resolved. |
| `UNKNOWN` | Redaction status is unknown; require manual validation. |

## Evidence Type Catalog

Each type uses the common fields and the type-specific requirements below.
`raw_reference` is required whenever the raw payload is large, binary, or likely
to contain sensitive assessed-app data.

### `DEVICE_STATE`

- Purpose: Record device health, configuration, and lab invariants.
- Required fields: `artifact_type`, `audit_id`, `session_id`, `device_id`,
  `timestamp`, `tool`, `summary`, `normalized`, `redaction_state`, `confidence`.
- Optional fields: `raw_reference`, `correlation_keys`.
- Raw storage: MinIO only for full preflight logs or large command output.
- Redaction: Remove host usernames, local absolute paths when not needed, and
  network details beyond bounded diagnostic labels.
- Size limit: normalized payload under 16 KB.
- Confidence: `CONFIRMED` only when read directly from device/preflight tools.
- Manual validation: required for drift, quarantine, or conflicting health data.
- Example JSON:

```json
{
  "artifact_type": "DEVICE_STATE",
  "audit_id": "audit_1001",
  "session_id": "dyn_session_1001",
  "device_id": "dev_01",
  "timestamp": "2026-08-05T10:06:00Z",
  "sequence_number": 1,
  "tool": "adb-preflight",
  "tool_version": "platform-tools",
  "category": "device",
  "event_name": "health_check",
  "summary": "Device healthy with SELinux Enforcing",
  "normalized": {"api_level": 35, "abi": "x86_64", "selinux": "Enforcing"},
  "raw_reference": null,
  "redaction_state": "NOT_REQUIRED",
  "confidence": "CONFIRMED",
  "correlation_keys": ["device:emulator-5554", "api:35"],
  "manual_validation_required": false
}
```

### `DYNAMIC_SESSION`

- Purpose: Summarize dynamic session configuration, coverage, and outcome.
- Required fields: common identity fields, `event_name`, `summary`,
  `normalized`, `redaction_state`, `confidence`.
- Optional fields: tool flags, coverage counters, report references.
- Raw storage: usually PostgreSQL metadata; MinIO for exported full session logs.
- Redaction: No credentials, APK local paths, or raw app data.
- Size limit: normalized payload under 32 KB.
- Confidence: `CONFIRMED` for worker-owned state; lower for recovered sessions.
- Manual validation: required when coverage is partial or cleanup is partial.
- Example JSON:

```json
{
  "artifact_type": "DYNAMIC_SESSION",
  "audit_id": "audit_1001",
  "session_id": "dyn_session_1001",
  "device_id": "dev_01",
  "timestamp": "2026-08-05T10:35:00Z",
  "sequence_number": 200,
  "tool": "dynamic-worker",
  "tool_version": "msap-phase4",
  "category": "session",
  "event_name": "session_summary",
  "summary": "Combined dynamic session completed with cleanup success",
  "normalized": {"mode": "COMBINED", "cleanup_status": "SUCCEEDED"},
  "raw_reference": "obj_ref_session_log",
  "redaction_state": "REDACTED",
  "confidence": "CONFIRMED",
  "correlation_keys": ["audit:audit_1001", "session:dyn_session_1001"],
  "manual_validation_required": false
}
```

### `LOGCAT_EVENT`

- Purpose: Capture bounded Android logcat events relevant to runtime behavior.
- Required fields: common identity fields, `package_name`, `process_name` when
  known, `event_name`, `summary`, `normalized`.
- Optional fields: `pid`, `thread_id`, log level, tag.
- Raw storage: full logcat streams in MinIO; PostgreSQL stores selected events.
- Redaction: Redact user data, URLs with sensitive query values, identifiers,
  credentials, and stack traces that contain secrets.
- Size limit: normalized message under 4 KB per event.
- Confidence: high when timestamp/package/pid match target; lower for ambiguous
  system logs.
- Manual validation: required for ambiguous package attribution or sensitive
  logs.
- Example JSON:

```json
{
  "artifact_type": "LOGCAT_EVENT",
  "audit_id": "audit_1001",
  "session_id": "dyn_session_1001",
  "device_id": "dev_01",
  "timestamp": "2026-08-05T10:12:00Z",
  "sequence_number": 21,
  "tool": "logcat",
  "tool_version": "adb",
  "package_name": "com.example.app",
  "process_name": "com.example.app",
  "pid": 1234,
  "thread_id": "main",
  "category": "runtime",
  "event_name": "app_log",
  "summary": "Target app emitted a redacted warning log",
  "normalized": {"level": "W", "tag": "Example", "message_redacted": true},
  "raw_reference": "obj_ref_logcat_full",
  "redaction_state": "REDACTED",
  "confidence": "HIGH",
  "correlation_keys": ["pkg:com.example.app", "logtag:Example"],
  "manual_validation_required": false
}
```

### `PROCESS_EVENT`

- Purpose: Record process creation, foreground state, death, crash adjacency, or
  command execution observed by ADB/Frida.
- Required fields: `package_name`, `process_name`, `pid`, `event_name`,
  `normalized`.
- Optional fields: parent pid, command name, arguments redaction metadata.
- Raw storage: MinIO for full process snapshots or traces.
- Redaction: Never store unredacted command arguments from APK-controlled input.
- Size limit: normalized payload under 8 KB.
- Confidence: confirmed only when observed by runtime collector with matching
  process identity.
- Manual validation: required for command execution or ambiguous process owner.
- Example JSON:

```json
{
  "artifact_type": "PROCESS_EVENT",
  "audit_id": "audit_1001",
  "session_id": "dyn_session_1001",
  "device_id": "dev_01",
  "timestamp": "2026-08-05T10:13:00Z",
  "sequence_number": 30,
  "tool": "frida",
  "tool_version": "17.16.4",
  "package_name": "com.example.app",
  "process_name": "com.example.app",
  "pid": 1234,
  "category": "process",
  "event_name": "runtime_exec_observed",
  "summary": "Runtime command execution API was observed with redacted arguments",
  "normalized": {"api": "Runtime.exec", "arguments_redacted": true},
  "raw_reference": "obj_ref_frida_events",
  "redaction_state": "REDACTED",
  "confidence": "HIGH",
  "correlation_keys": ["api:java.lang.Runtime.exec"],
  "manual_validation_required": true
}
```

### `COMPONENT_EVENT`

- Purpose: Record component discovery, invocation, or lifecycle behavior.
- Required fields: `package_name`, `category`, `event_name`, `summary`,
  `normalized`.
- Optional fields: component class, intent action, caller package if known.
- Raw storage: MinIO for full dumpsys output.
- Redaction: Redact extras and identifiers from intents.
- Size limit: normalized payload under 8 KB.
- Confidence: high when component name and lifecycle event are observed.
- Manual validation: required for external invocation claims.
- Example JSON:

```json
{
  "artifact_type": "COMPONENT_EVENT",
  "audit_id": "audit_1001",
  "session_id": "dyn_session_1001",
  "device_id": "dev_01",
  "timestamp": "2026-08-05T10:14:00Z",
  "sequence_number": 35,
  "tool": "adb",
  "tool_version": "platform-tools",
  "package_name": "com.example.app",
  "category": "component",
  "event_name": "component_invoked",
  "summary": "Exported activity invocation was observed",
  "normalized": {"component": "com.example.app.DeepLinkActivity", "external": true},
  "raw_reference": "obj_ref_dumpsys",
  "redaction_state": "REDACTED",
  "confidence": "HIGH",
  "correlation_keys": ["component:com.example.app.DeepLinkActivity"],
  "manual_validation_required": true
}
```

### `ACTIVITY_EVENT`

- Purpose: Record foreground activity launch, transition, or lifecycle evidence.
- Required fields: `package_name`, `event_name`, activity name in `normalized`.
- Optional fields: intent action, data scheme/domain redacted.
- Raw storage: MinIO for dumpsys activity snapshots.
- Redaction: Redact intent data values and user-entered strings.
- Size limit: normalized payload under 8 KB.
- Confidence: high when from activity manager or UI automation state.
- Manual validation: required when intent data drives the finding.
- Example JSON:

```json
{
  "artifact_type": "ACTIVITY_EVENT",
  "audit_id": "audit_1001",
  "session_id": "dyn_session_1001",
  "device_id": "dev_01",
  "timestamp": "2026-08-05T10:15:00Z",
  "sequence_number": 40,
  "tool": "adb",
  "tool_version": "platform-tools",
  "package_name": "com.example.app",
  "category": "component",
  "event_name": "activity_foreground",
  "summary": "Main activity reached foreground",
  "normalized": {"activity": "com.example.app.MainActivity"},
  "raw_reference": null,
  "redaction_state": "NOT_REQUIRED",
  "confidence": "CONFIRMED",
  "correlation_keys": ["activity:com.example.app.MainActivity"],
  "manual_validation_required": false
}
```

### `SERVICE_EVENT`

- Purpose: Record service start, bind, stop, or background execution evidence.
- Required fields: `package_name`, `event_name`, service name in `normalized`.
- Optional fields: caller package, intent action, foreground flag.
- Raw storage: MinIO for service dumps or full logs.
- Redaction: Redact intent extras and identifiers.
- Size limit: normalized payload under 8 KB.
- Confidence: high when observed through activity manager or Frida hook.
- Manual validation: required for exported/background risk claims.
- Example JSON:

```json
{
  "artifact_type": "SERVICE_EVENT",
  "audit_id": "audit_1001",
  "session_id": "dyn_session_1001",
  "device_id": "dev_01",
  "timestamp": "2026-08-05T10:16:00Z",
  "sequence_number": 45,
  "tool": "adb",
  "tool_version": "platform-tools",
  "package_name": "com.example.app",
  "category": "component",
  "event_name": "service_started",
  "summary": "Target service start was observed",
  "normalized": {"service": "com.example.app.SyncService", "foreground": false},
  "raw_reference": "obj_ref_services",
  "redaction_state": "REDACTED",
  "confidence": "HIGH",
  "correlation_keys": ["service:com.example.app.SyncService"],
  "manual_validation_required": true
}
```

### `BROADCAST_EVENT`

- Purpose: Record broadcast send/receive behavior.
- Required fields: `package_name`, `event_name`, action in `normalized`.
- Optional fields: receiver class, sender package if known.
- Raw storage: MinIO for full broadcast logs.
- Redaction: Redact extras and data URI values.
- Size limit: normalized payload under 8 KB.
- Confidence: high when receiver and action are observed at runtime.
- Manual validation: required for externally triggered behavior.
- Example JSON:

```json
{
  "artifact_type": "BROADCAST_EVENT",
  "audit_id": "audit_1001",
  "session_id": "dyn_session_1001",
  "device_id": "dev_01",
  "timestamp": "2026-08-05T10:17:00Z",
  "sequence_number": 50,
  "tool": "logcat",
  "tool_version": "adb",
  "package_name": "com.example.app",
  "category": "component",
  "event_name": "broadcast_received",
  "summary": "Target receiver handled a redacted broadcast action",
  "normalized": {"receiver": "com.example.app.BootReceiver", "action": "android.intent.action.BOOT_COMPLETED"},
  "raw_reference": "obj_ref_logcat_full",
  "redaction_state": "REDACTED",
  "confidence": "MEDIUM",
  "correlation_keys": ["broadcast:android.intent.action.BOOT_COMPLETED"],
  "manual_validation_required": true
}
```

### `RUNTIME_API_CALL`

- Purpose: Record observed sensitive or security-relevant API calls.
- Required fields: `package_name`, `process_name`, `event_name`, API signature.
- Optional fields: sanitized arguments, return category, stack fingerprint.
- Raw storage: MinIO for full Frida event streams.
- Redaction: Redact arguments, return values, URLs, identifiers, and secrets.
- Size limit: normalized payload under 12 KB.
- Confidence: high only when hook attribution is reliable.
- Manual validation: required for APIs where use alone is not a vulnerability.
- Example JSON:

```json
{
  "artifact_type": "RUNTIME_API_CALL",
  "audit_id": "audit_1001",
  "session_id": "dyn_session_1001",
  "device_id": "dev_01",
  "timestamp": "2026-08-05T10:18:00Z",
  "sequence_number": 55,
  "tool": "frida",
  "tool_version": "17.16.4",
  "package_name": "com.example.app",
  "process_name": "com.example.app",
  "pid": 1234,
  "category": "runtime_api",
  "event_name": "crypto_api_call",
  "summary": "Weak crypto algorithm was requested at runtime",
  "normalized": {"api": "Cipher.getInstance", "algorithm": "DES"},
  "raw_reference": "obj_ref_frida_events",
  "redaction_state": "REDACTED",
  "confidence": "HIGH",
  "correlation_keys": ["api:javax.crypto.Cipher.getInstance", "crypto:DES"],
  "manual_validation_required": true
}
```

### `FRIDA_EVENT`

- Purpose: Store generic Frida collector events, hook health, script output, and
  instrumentation warnings.
- Required fields: `tool`, `tool_version`, `event_name`, `summary`,
  `normalized`.
- Optional fields: script name/version, hook id, process info.
- Raw storage: MinIO for full Frida JSONL or logs.
- Redaction: Scripts must redact sensitive arguments before normalized storage.
- Size limit: normalized payload under 16 KB per event.
- Confidence: depends on hook reliability and script health.
- Manual validation: required for script errors, anti-hook behavior, and broad
  inference.
- Example JSON:

```json
{
  "artifact_type": "FRIDA_EVENT",
  "audit_id": "audit_1001",
  "session_id": "dyn_session_1001",
  "device_id": "dev_01",
  "timestamp": "2026-08-05T10:19:00Z",
  "sequence_number": 60,
  "tool": "frida",
  "tool_version": "17.16.4",
  "package_name": "com.example.app",
  "category": "instrumentation",
  "event_name": "hook_attached",
  "summary": "Basic network hook attached",
  "normalized": {"script": "network-basic", "hook_count": 3},
  "raw_reference": "obj_ref_frida_events",
  "redaction_state": "NOT_REQUIRED",
  "confidence": "CONFIRMED",
  "correlation_keys": ["frida:network-basic"],
  "manual_validation_required": false
}
```

### `NETWORK_FLOW`

- Purpose: Record normalized HTTP/HTTPS or TCP flow observations.
- Required fields: `event_name`, `summary`, normalized scheme/host/port/method
  where visible, `raw_reference`.
- Optional fields: status code, content type, byte counts, TLS metadata.
- Raw storage: mitmproxy flow files and packet-like exports in MinIO.
- Redaction: Redact query values, headers, bodies, identifiers, and credentials.
- Size limit: normalized payload under 16 KB; raw files in MinIO with retention.
- Confidence: confirmed for decrypted flows from mitmproxy; lower for inferred
  or CONNECT-only flows.
- Manual validation: required for sensitive data exposure or incomplete TLS
  visibility.
- Example JSON:

```json
{
  "artifact_type": "NETWORK_FLOW",
  "audit_id": "audit_1001",
  "session_id": "dyn_session_1001",
  "device_id": "dev_01",
  "timestamp": "2026-08-05T10:20:00Z",
  "sequence_number": 65,
  "tool": "mitmproxy",
  "tool_version": "12.2.3",
  "package_name": "com.example.app",
  "category": "network",
  "event_name": "http_request",
  "summary": "Observed HTTP request to static-correlated endpoint",
  "normalized": {"scheme": "http", "host_hash": "sha256:host-redacted", "method": "GET", "status_code": 200},
  "raw_reference": "obj_ref_mitm_flow",
  "redaction_state": "REDACTED",
  "confidence": "CONFIRMED",
  "correlation_keys": ["network:http", "host_hash:sha256:host-redacted"],
  "manual_validation_required": false
}
```

### `DNS_EVENT`

- Purpose: Record observed DNS lookup behavior.
- Required fields: `event_name`, normalized domain hash or redacted domain,
  timestamp, tool.
- Optional fields: resolver, answer type, IP family, package attribution.
- Raw storage: MinIO for full proxy/system DNS logs.
- Redaction: Hash or redact domains when they identify private services.
- Size limit: normalized payload under 8 KB.
- Confidence: high when package attribution is known; medium for device-level
  DNS only.
- Manual validation: required for private-network or suspicious-domain claims.
- Example JSON:

```json
{
  "artifact_type": "DNS_EVENT",
  "audit_id": "audit_1001",
  "session_id": "dyn_session_1001",
  "device_id": "dev_01",
  "timestamp": "2026-08-05T10:20:05Z",
  "sequence_number": 66,
  "tool": "mitmproxy",
  "tool_version": "12.2.3",
  "package_name": "com.example.app",
  "category": "network",
  "event_name": "dns_lookup",
  "summary": "Observed runtime DNS lookup with redacted host",
  "normalized": {"domain_hash": "sha256:domain-redacted", "record_type": "A"},
  "raw_reference": "obj_ref_dns_log",
  "redaction_state": "REDACTED",
  "confidence": "MEDIUM",
  "correlation_keys": ["domain_hash:sha256:domain-redacted"],
  "manual_validation_required": true
}
```

### `TLS_EVENT`

- Purpose: Record TLS handshakes, interception state, pinning failures, and
  trust-probe results.
- Required fields: `event_name`, `summary`, normalized TLS outcome.
- Optional fields: protocol, cipher suite, certificate fingerprint hash.
- Raw storage: MinIO for flow files, logs, or probe evidence.
- Redaction: Do not store full certificates from assessed apps unless required
  and referenced through MinIO with retention policy.
- Size limit: normalized payload under 12 KB.
- Confidence: confirmed for platform probe and observed handshake metadata.
- Manual validation: required for pinning, native TLS, or custom trust stores.
- Example JSON:

```json
{
  "artifact_type": "TLS_EVENT",
  "audit_id": "audit_1001",
  "session_id": "dyn_session_1001",
  "device_id": "dev_01",
  "timestamp": "2026-08-05T10:20:10Z",
  "sequence_number": 67,
  "tool": "mitmproxy",
  "tool_version": "12.2.3",
  "package_name": "com.example.app",
  "category": "network",
  "event_name": "tls_interception_blocked",
  "summary": "TLS flow was not decrypted; pinning or custom trust may be present",
  "normalized": {"visibility": "connect_only", "possible_causes": ["pinning", "custom_trust_store"]},
  "raw_reference": "obj_ref_mitm_flow",
  "redaction_state": "REDACTED",
  "confidence": "MEDIUM",
  "correlation_keys": ["tls:connect_only"],
  "manual_validation_required": true
}
```

### `FILE_SYSTEM_EVENT`

- Purpose: Record observed file reads, writes, deletes, or insecure path use.
- Required fields: `package_name`, `event_name`, normalized path category.
- Optional fields: redacted path hash, operation, byte count.
- Raw storage: MinIO for full traces.
- Redaction: Do not store cleartext file contents or personal paths.
- Size limit: normalized payload under 8 KB.
- Confidence: high when observed through a hook or reliable system event.
- Manual validation: required for sensitive-storage conclusions.
- Example JSON:

```json
{
  "artifact_type": "FILE_SYSTEM_EVENT",
  "audit_id": "audit_1001",
  "session_id": "dyn_session_1001",
  "device_id": "dev_01",
  "timestamp": "2026-08-05T10:21:00Z",
  "sequence_number": 70,
  "tool": "frida",
  "tool_version": "17.16.4",
  "package_name": "com.example.app",
  "category": "storage",
  "event_name": "file_write",
  "summary": "Observed app file write in external storage category",
  "normalized": {"operation": "write", "path_category": "external_storage", "path_hash": "sha256:path-redacted"},
  "raw_reference": "obj_ref_frida_storage",
  "redaction_state": "REDACTED",
  "confidence": "HIGH",
  "correlation_keys": ["storage:external", "op:write"],
  "manual_validation_required": true
}
```

### `DATABASE_EVENT`

- Purpose: Record SQLite/database open, query, insert, update, or delete
  behavior when observed.
- Required fields: `package_name`, `event_name`, database category/name hash.
- Optional fields: table hash, operation, encrypted/unencrypted indicator.
- Raw storage: MinIO for traces; database files only with explicit policy.
- Redaction: Never store row values in normalized fields.
- Size limit: normalized payload under 8 KB.
- Confidence: high when runtime API call or filesystem evidence confirms it.
- Manual validation: required for sensitive data storage claims.
- Example JSON:

```json
{
  "artifact_type": "DATABASE_EVENT",
  "audit_id": "audit_1001",
  "session_id": "dyn_session_1001",
  "device_id": "dev_01",
  "timestamp": "2026-08-05T10:21:30Z",
  "sequence_number": 72,
  "tool": "frida",
  "tool_version": "17.16.4",
  "package_name": "com.example.app",
  "category": "storage",
  "event_name": "sqlite_open",
  "summary": "Observed SQLite database open",
  "normalized": {"database_hash": "sha256:db-redacted", "encrypted": false},
  "raw_reference": "obj_ref_frida_storage",
  "redaction_state": "REDACTED",
  "confidence": "HIGH",
  "correlation_keys": ["storage:sqlite", "encrypted:false"],
  "manual_validation_required": true
}
```

### `SHARED_PREFERENCE_EVENT`

- Purpose: Record SharedPreferences access patterns.
- Required fields: `package_name`, `event_name`, preference file/key hash.
- Optional fields: operation, value type, encryption indicator.
- Raw storage: MinIO for traces; pulled XML only through protected object
  references when allowed.
- Redaction: Do not store preference values in normalized fields.
- Size limit: normalized payload under 8 KB.
- Confidence: high when observed through runtime hooks.
- Manual validation: required for sensitive preference conclusions.
- Example JSON:

```json
{
  "artifact_type": "SHARED_PREFERENCE_EVENT",
  "audit_id": "audit_1001",
  "session_id": "dyn_session_1001",
  "device_id": "dev_01",
  "timestamp": "2026-08-05T10:22:00Z",
  "sequence_number": 74,
  "tool": "frida",
  "tool_version": "17.16.4",
  "package_name": "com.example.app",
  "category": "storage",
  "event_name": "shared_preference_write",
  "summary": "Observed SharedPreferences write with redacted key",
  "normalized": {"key_hash": "sha256:key-redacted", "value_type": "string", "encrypted": false},
  "raw_reference": "obj_ref_frida_storage",
  "redaction_state": "REDACTED",
  "confidence": "HIGH",
  "correlation_keys": ["storage:shared_preferences", "key_hash:sha256:key-redacted"],
  "manual_validation_required": true
}
```

### `CLIPBOARD_EVENT`

- Purpose: Record clipboard reads or writes by the target app.
- Required fields: `package_name`, `event_name`, operation.
- Optional fields: content type, length bucket, source attribution.
- Raw storage: MinIO only if raw capture is explicitly allowed.
- Redaction: Never store clipboard contents in normalized fields.
- Size limit: normalized payload under 4 KB.
- Confidence: high when runtime API call is observed in target process.
- Manual validation: required for privacy-impact conclusions.
- Example JSON:

```json
{
  "artifact_type": "CLIPBOARD_EVENT",
  "audit_id": "audit_1001",
  "session_id": "dyn_session_1001",
  "device_id": "dev_01",
  "timestamp": "2026-08-05T10:22:30Z",
  "sequence_number": 76,
  "tool": "frida",
  "tool_version": "17.16.4",
  "package_name": "com.example.app",
  "category": "privacy",
  "event_name": "clipboard_read",
  "summary": "Observed clipboard read without storing contents",
  "normalized": {"operation": "read", "content_type": "text", "length_bucket": "1-64"},
  "raw_reference": "obj_ref_frida_privacy",
  "redaction_state": "REDACTED",
  "confidence": "HIGH",
  "correlation_keys": ["privacy:clipboard", "op:read"],
  "manual_validation_required": true
}
```

### `PERMISSION_EVENT`

- Purpose: Record runtime permission prompts, grants, denials, and protected API
  use.
- Required fields: `package_name`, `event_name`, permission name.
- Optional fields: user action, API call, foreground/background context.
- Raw storage: MinIO for screenshots or log streams.
- Redaction: Redact screen content around prompts if it may include app data.
- Size limit: normalized payload under 8 KB.
- Confidence: confirmed for observed prompt/grant; high for protected API calls.
- Manual validation: required when permission use implies sensitive data access.
- Example JSON:

```json
{
  "artifact_type": "PERMISSION_EVENT",
  "audit_id": "audit_1001",
  "session_id": "dyn_session_1001",
  "device_id": "dev_01",
  "timestamp": "2026-08-05T10:23:00Z",
  "sequence_number": 80,
  "tool": "uiautomator",
  "tool_version": "adb",
  "package_name": "com.example.app",
  "category": "permission",
  "event_name": "permission_prompt",
  "summary": "Runtime location permission prompt observed",
  "normalized": {"permission": "android.permission.ACCESS_FINE_LOCATION", "user_action": "not_granted_by_automation"},
  "raw_reference": "obj_ref_screenshot_prompt",
  "redaction_state": "PARTIAL",
  "confidence": "CONFIRMED",
  "correlation_keys": ["permission:android.permission.ACCESS_FINE_LOCATION"],
  "manual_validation_required": true
}
```

### `WEBVIEW_EVENT`

- Purpose: Record WebView URL loading, JavaScript bridge, mixed-content, or
  file-access behavior observed at runtime.
- Required fields: `package_name`, `event_name`, WebView operation.
- Optional fields: URL hash, scheme, settings snapshot.
- Raw storage: MinIO for Frida streams, screenshots, or logs.
- Redaction: Redact URLs, form values, headers, and page content.
- Size limit: normalized payload under 12 KB.
- Confidence: high when observed in target process through hooks.
- Manual validation: required for bridge exposure and loaded content risk.
- Example JSON:

```json
{
  "artifact_type": "WEBVIEW_EVENT",
  "audit_id": "audit_1001",
  "session_id": "dyn_session_1001",
  "device_id": "dev_01",
  "timestamp": "2026-08-05T10:24:00Z",
  "sequence_number": 85,
  "tool": "frida",
  "tool_version": "17.16.4",
  "package_name": "com.example.app",
  "category": "webview",
  "event_name": "url_loaded",
  "summary": "Observed WebView loading a non-HTTPS URL",
  "normalized": {"scheme": "http", "url_hash": "sha256:url-redacted", "javascript_enabled": true},
  "raw_reference": "obj_ref_frida_webview",
  "redaction_state": "REDACTED",
  "confidence": "HIGH",
  "correlation_keys": ["webview:http", "url_hash:sha256:url-redacted"],
  "manual_validation_required": true
}
```

### `SCREENSHOT`

- Purpose: Store visual evidence of app state, permission prompts, crashes, or
  UI automation checkpoints.
- Required fields: `raw_reference`, `summary`, timestamp, redaction state.
- Optional fields: activity, screen label, OCR summary.
- Raw storage: image file in MinIO.
- Redaction: Redact personal data, credentials, message contents, and assessed
  client data before report inclusion.
- Size limit: raw image limit defined by storage policy; thumbnail metadata only
  in PostgreSQL.
- Confidence: confirms UI state only, not underlying vulnerability by itself.
- Manual validation: required before including assessed-app screenshots in
  external reports.
- Example JSON:

```json
{
  "artifact_type": "SCREENSHOT",
  "audit_id": "audit_1001",
  "session_id": "dyn_session_1001",
  "device_id": "dev_01",
  "timestamp": "2026-08-05T10:24:30Z",
  "sequence_number": 90,
  "tool": "adb-screencap",
  "tool_version": "platform-tools",
  "package_name": "com.example.app",
  "category": "visual",
  "event_name": "screenshot_captured",
  "summary": "Redacted screenshot captured after launch",
  "normalized": {"activity": "com.example.app.MainActivity", "redacted_regions": 2},
  "raw_reference": "obj_ref_screenshot",
  "redaction_state": "REDACTED",
  "confidence": "CONFIRMED",
  "correlation_keys": ["screen:main_activity"],
  "manual_validation_required": true
}
```

### `SCREEN_RECORDING`

- Purpose: Store bounded video evidence of interaction flows.
- Required fields: `raw_reference`, start/end timestamps, summary.
- Optional fields: frame count, duration, redaction metadata.
- Raw storage: video file in MinIO.
- Redaction: Require review before report use; do not normalize visible secrets.
- Size limit: strict duration and file-size limits by policy.
- Confidence: confirms observed UI sequence only.
- Manual validation: always required for report inclusion.
- Example JSON:

```json
{
  "artifact_type": "SCREEN_RECORDING",
  "audit_id": "audit_1001",
  "session_id": "dyn_session_1001",
  "device_id": "dev_01",
  "timestamp": "2026-08-05T10:25:00Z",
  "sequence_number": 95,
  "tool": "screenrecord",
  "tool_version": "adb",
  "package_name": "com.example.app",
  "category": "visual",
  "event_name": "recording_captured",
  "summary": "Bounded recording captured for automation flow",
  "normalized": {"duration_seconds": 30, "redaction_reviewed": false},
  "raw_reference": "obj_ref_screen_recording",
  "redaction_state": "UNKNOWN",
  "confidence": "CONFIRMED",
  "correlation_keys": ["session:dyn_session_1001", "visual:recording"],
  "manual_validation_required": true
}
```

### `CRASH_EVENT`

- Purpose: Record app crash evidence from logcat, tombstones, or Android crash
  reports.
- Required fields: `package_name`, `process_name`, `event_name`, crash summary.
- Optional fields: exception type, stack fingerprint, signal, tombstone ref.
- Raw storage: MinIO for full stack traces/tombstones.
- Redaction: Redact file paths, user data, request data, and secrets from stack
  traces.
- Size limit: normalized stack fingerprint under 8 KB.
- Confidence: confirmed when Android reports target process crash.
- Manual validation: required before creating security finding from a crash.
- Example JSON:

```json
{
  "artifact_type": "CRASH_EVENT",
  "audit_id": "audit_1001",
  "session_id": "dyn_session_1001",
  "device_id": "dev_01",
  "timestamp": "2026-08-05T10:26:00Z",
  "sequence_number": 100,
  "tool": "logcat",
  "tool_version": "adb",
  "package_name": "com.example.app",
  "process_name": "com.example.app",
  "pid": 1234,
  "category": "stability",
  "event_name": "app_crash",
  "summary": "Target app crash observed with redacted stack fingerprint",
  "normalized": {"exception_type": "RuntimeException", "stack_fingerprint": "sha256:stack-redacted"},
  "raw_reference": "obj_ref_crash_log",
  "redaction_state": "REDACTED",
  "confidence": "CONFIRMED",
  "correlation_keys": ["crash:sha256:stack-redacted"],
  "manual_validation_required": true
}
```

### `ANR_EVENT`

- Purpose: Record application-not-responding evidence.
- Required fields: `package_name`, `event_name`, summary, process identity.
- Optional fields: reason, input dispatch timeout, trace reference.
- Raw storage: MinIO for traces and logcat excerpts.
- Redaction: Redact traces and UI context that may contain sensitive data.
- Size limit: normalized payload under 8 KB.
- Confidence: confirmed when Android reports target package ANR.
- Manual validation: required for security or availability conclusions.
- Example JSON:

```json
{
  "artifact_type": "ANR_EVENT",
  "audit_id": "audit_1001",
  "session_id": "dyn_session_1001",
  "device_id": "dev_01",
  "timestamp": "2026-08-05T10:27:00Z",
  "sequence_number": 105,
  "tool": "logcat",
  "tool_version": "adb",
  "package_name": "com.example.app",
  "process_name": "com.example.app",
  "category": "stability",
  "event_name": "app_anr",
  "summary": "Target app ANR observed",
  "normalized": {"reason": "input_dispatching_timeout"},
  "raw_reference": "obj_ref_anr_log",
  "redaction_state": "REDACTED",
  "confidence": "CONFIRMED",
  "correlation_keys": ["anr:com.example.app"],
  "manual_validation_required": true
}
```

### `BEHAVIOR_TIMELINE`

- Purpose: Provide an ordered summary of meaningful runtime events for reports
  and analyst review.
- Required fields: `summary`, `normalized.timeline`, event references.
- Optional fields: coverage gaps, linked findings, linked indicators.
- Raw storage: MinIO for full timeline export if large.
- Redaction: Timeline entries inherit redaction from linked artifacts; do not
  reintroduce sensitive values.
- Size limit: PostgreSQL summary under 64 KB; full export in MinIO.
- Confidence: minimum confidence is the lowest material linked event confidence.
- Manual validation: required when any included event requires validation.
- Example JSON:

```json
{
  "artifact_type": "BEHAVIOR_TIMELINE",
  "audit_id": "audit_1001",
  "session_id": "dyn_session_1001",
  "device_id": "dev_01",
  "timestamp": "2026-08-05T10:34:00Z",
  "sequence_number": 190,
  "tool": "evidence-normalizer",
  "tool_version": "msap-phase4",
  "package_name": "com.example.app",
  "category": "timeline",
  "event_name": "behavior_timeline",
  "summary": "Runtime timeline generated with network, WebView, and permission events",
  "normalized": {
    "event_count": 12,
    "coverage_gaps": ["credential_gated_flows_not_exercised"]
  },
  "raw_reference": "obj_ref_timeline_export",
  "redaction_state": "REDACTED",
  "confidence": "HIGH",
  "correlation_keys": ["audit:audit_1001", "timeline:dyn_session_1001"],
  "manual_validation_required": true
}
```
