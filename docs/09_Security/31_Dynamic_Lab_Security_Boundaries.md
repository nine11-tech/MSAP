# Dynamic Lab Security Boundaries

## Purpose

This document defines security boundaries for the MSAP dynamic Android lab and
future dynamic-analysis implementation. The lab executes authorized APKs in a
controlled emulator to collect limited runtime evidence. It does not execute APK
code on the host and it does not produce malware verdicts.

## Non-Negotiable Boundaries

| Boundary | Contract |
| --- | --- |
| Authorized APKs only | Run only APKs the organization is authorized to assess. |
| No secrets in Git | Do not commit credentials, tokens, cookies, passwords, keys, or local secret files. |
| No private CA in Git | mitmproxy private CA material remains local and protected. |
| No APK samples in Git | APK uploads and samples belong in approved object storage or local lab paths only. |
| No app evidence in Git | Screenshots, recordings, proxy flows, Frida logs, and assessed-app logs must not be committed. |
| No disabling SELinux | The validated lab requires SELinux `Enforcing`. |
| No permanent CA install | Use runtime CA overlay only; do not modify system/APEX CA stores permanently. |
| No host execution of APK code | Static workers inspect APKs; dynamic execution happens only inside the Android runtime target. |
| No APK-controlled shell | Never pass APK-controlled input directly to host, WSL, Windows, or ADB shell commands. |
| Bounded subprocesses | Every subprocess has timeout, argument control, output limits, and cleanup ownership. |
| Bounded logs | Logs are size-limited, redacted, and stored by policy. |

## Evidence Redaction and Sensitive Data Handling

- PostgreSQL stores metadata and bounded normalized summaries only.
- MinIO stores raw or large evidence through `ObjectStorageReference`.
- Normalized fields must not contain cleartext secrets, cookies, tokens,
  passwords, session IDs, private keys, or personal data.
- Reports must show redacted evidence by default.
- Full screenshots, recordings, flows, Frida streams, and logs require access
  control, retention policy, and analyst need.
- Redaction failures must block report inclusion or require manual validation.
- Hashes and fingerprints used for correlation must be generated in a way that
  does not reveal the original sensitive value.

## Device Quarantine Triggers

Move the device to `QUARANTINED` when:

- Cleanup fails or times out.
- Android proxy cannot be reset.
- Target APK or temporary probe package cannot be removed.
- Frida, UI automation, proxy, or bridge processes cannot be stopped.
- Runtime CA overlay cannot be cleared or final trust state is uncertain.
- SELinux is not `Enforcing`.
- Permanent system/APEX CA modification is detected.
- Snapshot restore integrity is uncertain.
- Lease expires with stale heartbeat and runtime state may exist.
- Evidence suggests the device baseline was poisoned or modified unexpectedly.

Quarantined devices must not be scheduled until an operator restores a validated
baseline and reruns preflight.

## Runner Isolation for Future GitLab Android-Dynamic Runner

The initial production contract should assume one concurrent dynamic job. A
future `android-dynamic` runner must be isolated from normal static-analysis
workers.

Required boundaries:

- Dedicated runner host or VM for dynamic Android work.
- No shared writable workspace with static workers.
- Dedicated MinIO credentials scoped to required buckets/prefixes.
- Dedicated network policy and egress controls.
- No privileged host access beyond explicit emulator/ADB requirements.
- Per-job cleanup and baseline restore.
- Runner registration token stored outside Git.
- Job logs redacted and bounded.
- Artifacts retained by policy, not indefinitely.

## Threat Model

| Threat | Risk | Boundary and mitigation |
| --- | --- | --- |
| Malicious APK | Attempts to evade, persist, exploit emulator/tooling, or exfiltrate data. | Execute only in Android emulator, restore snapshots, bound runtime, restrict evidence handling, quarantine on drift. |
| Escaped instrumentation | Frida scripts or hooks behave unexpectedly or expose bridge surfaces. | Use reviewed scripts, bounded hooks, scoped bridge, cleanup ownership, and no global firewall disablement. |
| Poisoned evidence | APK emits misleading logs, fake indicators, or crafted payloads. | Treat app-controlled data as untrusted, preserve provenance, require manual validation for ambiguous evidence. |
| Credential leakage | Authorized login scenarios expose secrets in logs/screenshots/flows. | Supply credentials through secure runtime channels, redact evidence, avoid normalized cleartext, require review before reporting. |
| Stale emulator state | Previous app, proxy, CA overlay, or instrumentation affects results. | Restore `msap-instrumented-base`, run preflight, enforce cleanup, quarantine uncertain state. |
| Bridge exposure | Frida or proxy bridge reachable beyond intended local scope. | Bind narrowly, refresh after WSL IP changes, document ports, stop bridge processes during cleanup. |
| Proxy leakage | App or device traffic routed through proxy unintentionally after session. | Reset Android proxy to `:0`, stop mitmproxy, verify cleanup, quarantine on failure. |
| Private network access | APK reaches internal services through host/lab network. | Future egress restrictions, dedicated VLAN, allowlists, and one-job concurrency. |

## Runtime Command Safety

All host, WSL, Windows, ADB, and emulator commands must be constructed from
controlled arguments. APK-controlled values may be used only as data after
validation and escaping by structured APIs. Commands must have:

- Timeout.
- Maximum output size.
- Explicit working directory.
- Redacted logging.
- Ownership metadata for cleanup.
- No shell interpolation of app-controlled values.

## Certificate Authority Boundary

The lab may stage a public CA certificate and use a runtime CA overlay when
needed for platform TLS validation. It must not:

- Commit CA material to Git.
- Commit generated public or private CA files.
- Permanently install a CA into Android system or APEX trust stores.
- Claim complete traffic visibility.

Certificate pinning, custom trust stores, native TLS stacks, and QUIC/HTTP3 may
prevent or limit proxy visibility.

## Future Hardening

| Hardening item | Purpose |
| --- | --- |
| Dedicated analysis VLAN | Isolate dynamic devices from developer and internal networks. |
| Egress restrictions | Limit APK network reachability and reduce data leakage. |
| Disposable emulator instances | Reduce stale-state risk beyond snapshot restore. |
| Retention policies | Remove raw evidence according to project policy. |
| Self-hosted runner protection | Restrict GitLab runner privileges and artifact exposure. |
| One concurrent job initially | Simplify lease safety, bridge ownership, and evidence isolation. |

## Reporting Boundaries

Reports must state coverage limitations. They must not say:

- MSAP classifies assessed APKs as malicious or benign.
- Network visibility was complete.
- Unexercised flows are safe.
- A static permission or API reference is a confirmed vulnerability without
  supporting evidence.
- An ATT&CK Mobile signal is a malware verdict.

Reports may say that specific runtime behavior was observed during a specific
session, under the listed collectors, tool versions, coverage limitations, and
redaction state.
