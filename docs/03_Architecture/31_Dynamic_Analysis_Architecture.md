# Dynamic Analysis Architecture

## Purpose

This document defines the Phase 3 architecture contract for MSAP dynamic Android
analysis. It prepares Phase 4 implementation by naming the runtime components,
data boundaries, orchestration flow, supported modes, and limitations before any
Django models, APIs, frontend screens, or Celery tasks are implemented.

Dynamic analysis is an evidence-gathering extension to the existing static MSAP
platform. It observes selected runtime behavior in a controlled Android lab and
correlates those observations with static findings. It does not classify malware
and it does not prove that unexercised code paths are safe.

## Scope

In scope:

- Android APK execution in the validated local dynamic lab.
- Device leasing, snapshot restoration, health checks, instrumentation startup,
  APK installation, app launch, limited app exercising, evidence collection,
  dynamic rule evaluation, static/dynamic correlation, reporting, cleanup, and
  device release.
- Contracts for PostgreSQL metadata, MinIO evidence objects, Redis/Celery
  orchestration, and future frontend progress display.

Out of scope for this phase:

- Django model implementation.
- API endpoint implementation.
- Frontend implementation.
- Celery task implementation.
- Migrations.
- Dependency installation.
- Malware verdicts or automated exploitability claims.

## What Dynamic Analysis Adds Beyond Static Analysis

Static analysis identifies declared capabilities, packaged resources, code
references, configuration, extracted endpoints, probable secrets, resilience
signals, and other indicators without executing APK code. Dynamic analysis adds
runtime observations from an instrumented environment:

| Static signal | Dynamic contribution |
| --- | --- |
| Declared permission | Whether the exercised app path actually accessed the protected capability |
| URL or endpoint string | Whether a network flow was observed at runtime |
| Cleartext traffic capability | Whether HTTP traffic was actually sent |
| WebView configuration risk | Whether unsafe runtime URL loading was observed |
| Dynamic code loading reference | Whether class loading or dex loading occurred during the session |
| Runtime command execution reference | Whether a command was observed during the session |
| Crypto API usage | Whether weak runtime crypto use was observed with sufficient context |
| ATT&CK Mobile mapping | Runtime triage evidence, not a malware verdict |

Dynamic evidence can increase confidence only when behavior is observed. Absence
of an observation is not a PASS unless the relevant collector was active, scoped
to the behavior, and completed with adequate coverage.

## Current Validated Laboratory Baseline

The Phase 2 lab baseline is validated as follows:

| Area | Validated contract |
| --- | --- |
| Host | Windows owns the Android SDK, emulator binaries, and AVD storage |
| Linux environment | WSL2 Ubuntu runs MSAP scripts, Frida client tooling, mitmproxy, and local captures |
| Android emulator | API 35 x86_64 userdebug emulator, rooted adbd, SELinux `Enforcing` |
| Frida | Frida client/server `17.16.4`; Android binary staged at `/data/local/tmp/msap-frida-server` |
| mitmproxy | mitmproxy `12.2.3` in the dedicated local dynamic-lab virtual environment |
| Runtime CA overlay | Temporary Conscrypt runtime overlay for platform TLS validation; no permanent CA install |
| Clean snapshot | `msap-clean-base` |
| Instrumented snapshot | `msap-instrumented-base`, staged public CA and Frida binary present, proxy disabled, Frida stopped, no target APK installed |

The runtime CA overlay is used only when network interception requires platform
trust. Certificate pinning, custom trust stores, native TLS stacks, and
QUIC/HTTP3 can still limit visibility.

## High-Level Dynamic-Analysis Flow

```text
Audit
-> choose dynamic or combined mode
-> create DynamicAnalysisJob
-> scheduler selects compatible device
-> lease device
-> restore snapshot
-> verify health
-> stage tools
-> configure proxy
-> inject runtime CA overlay when needed
-> start Frida
-> install APK
-> launch app
-> exercise app
-> collect evidence
-> evaluate dynamic rules
-> correlate with static results
-> generate reports
-> cleanup
-> release device
```

The implementation must treat cleanup as part of job completion. `COMPLETED`
requires cleanup success. `FAILED` and `CANCELLED` still require cleanup
attempts. If cleanup fails or device integrity is uncertain, the session must
move to `QUARANTINED`.

## Component Architecture

| Component | Responsibility | Must not do |
| --- | --- | --- |
| Django backend | Own authenticated audit workflow, metadata, authorization, report requests, and job creation | Run emulator control or APK runtime work inline |
| Celery dynamic worker | Execute dynamic orchestration asynchronously with bounded timeouts and structured state updates | Store large evidence in PostgreSQL or produce malware verdicts |
| Device adapter | Abstract device capability, health, lease, snapshot, package, proxy, and cleanup operations | Hide integrity failures or skip quarantine |
| Windows emulator adapter | Launch and restore Windows-owned emulator/AVD resources from WSL-compatible commands | Delete snapshots or mutate host state without explicit operator action |
| ADB controller | Root checks, boot wait, package install/uninstall, shell commands, logcat, proxy settings, file pulls | Execute unbounded shell commands or pass APK-controlled strings directly to shell |
| Frida controller | Start/stop validated Frida server, connect through the bridge, load bounded scripts, capture runtime events | Treat script failure as proof of app safety or vulnerability |
| mitmproxy controller | Start/stop proxy, manage local ports, capture flow files, export normalized network summaries | Claim complete interception of all traffic |
| Evidence normalizer | Convert raw logs, flows, screenshots, Frida events, and device state into normalized artifacts | Preserve secrets in cleartext normalized fields |
| Dynamic rule evaluator | Evaluate dynamic MASVS-oriented rules using observed runtime evidence and coverage state | Count `NOT_EVALUATED` as PASS |
| Report generator | Merge static, dynamic, correlation, and coverage output into deterministic JSON/PDF reports | Bypass redaction or double-count correlated evidence |
| Frontend dynamic workspace | Show mode selection, session progress, evidence, coverage warnings, and report links | Imply complete behavioral coverage or malware classification |

## Data Ownership

| Store | Owns | Notes |
| --- | --- | --- |
| PostgreSQL | Device/session/job metadata, normalized small artifacts, state transitions, rule evaluations, findings, suspicious indicators, evidence links | Use bounded fields and normalized summaries only |
| MinIO | APKs, large logs, screenshots, recordings, mitmproxy flow files, raw Frida captures, binary evidence, generated reports | Access through `ObjectStorageReference` with project/audit scoping |
| Redis/Celery | Queued dynamic jobs, worker execution, asynchronous orchestration, progress updates | Redis is not the source of truth for evidence or final state |

Large logs, screenshots, recordings, flow files, and binary evidence must be
stored in MinIO. PostgreSQL stores metadata, normalized summaries, correlation
keys, redaction state, and references.

## Static/Dynamic Separation

Static analysis remains deterministic, bounded, and non-executing. Dynamic
analysis is opt-in and requires an authorized APK, an available compatible
device, a valid snapshot, and a bounded runtime plan.

The separation rules are:

- Static-only audits must continue to work without dynamic-lab availability.
- Dynamic collectors must not mutate static analyzer results directly.
- Correlation may enrich findings, evidence, confidence, and coverage, but must
  preserve provenance for static capability versus observed runtime behavior.
- A static API reference, permission, or ATT&CK mapping is not a confirmed
  vulnerability without supporting runtime or configuration evidence.
- ATT&CK Mobile indicators remain triage signals and are not malware verdicts.

## Supported Modes

| Mode | Purpose | Required inputs | Expected output |
| --- | --- | --- | --- |
| Static only | Current deterministic APK inspection | Audit and APK | Static artifacts, rule evaluations, findings, indicators, reports |
| Dynamic only | Runtime observation without requiring prior static correlation | Audit, APK, compatible device, snapshot, dynamic profile | Dynamic artifacts, dynamic rule evaluations, findings when supported by observed behavior |
| Combined | Static analysis plus runtime observation and correlation | Audit, APK, static results, compatible device, snapshot, dynamic profile | Static and dynamic artifacts, correlated evidence, enriched findings, coverage warnings |

## Dynamic Limitations

- MSAP does not produce a malware verdict.
- Behavioral coverage is limited to exercised flows, enabled collectors, tool
  health, and session duration.
- Credential-gated flows may require explicitly authorized credentials.
- Certificate pinning may block proxy interception.
- Custom trust stores may block proxy interception.
- Native TLS may require Frida hooks or other instrumentation.
- QUIC/HTTP3 may bypass classic proxy visibility.
- UI automation may miss hidden, conditional, regional, time-delayed, or
  server-controlled flows.
- Failed instrumentation or missing collector coverage must produce
  `NOT_EVALUATED` or `REVIEW_REQUIRED`, not PASS.

## Phase 4 Implementation Readiness Criteria

Phase 4 is ready when the implementation plan can satisfy these criteria:

- Device, lease, snapshot, session, stage, event, artifact, evidence, and
  correlation contracts are reviewed and stable enough for initial Django
  models.
- Dynamic states and transitions are unambiguous, including cancellation,
  timeout, cleanup, and quarantine paths.
- Storage boundaries are agreed: PostgreSQL for metadata and bounded normalized
  summaries; MinIO for large or raw evidence.
- Security boundaries are explicit: authorized APKs only, no secrets or evidence
  blobs in Git, no permanent CA install, SELinux remains `Enforcing`, and
  subprocesses/logs are bounded.
- Dynamic analyzer interface distinguishes collector failure, partial coverage,
  `NOT_EVALUATED`, `REVIEW_REQUIRED`, and confirmed runtime evidence.
- Static/dynamic correlation rules prevent double-counting and preserve
  provenance.
- Operator runbook covers preflight, smoke tests, cleanup, expected PASS
  markers, and recovery for the validated Windows/WSL2/Android lab.
