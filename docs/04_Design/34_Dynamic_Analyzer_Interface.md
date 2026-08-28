# Dynamic Analyzer Interface

## Purpose

This document defines the design contract for dynamic analyzers. Dynamic
analyzers collect, normalize, evaluate, or correlate runtime evidence from a
bounded Android session. They extend MSAP's existing static analyzer model
without changing the static-analysis guarantee that APK code is not executed
during static-only audits.

The persisted session contracts and bounded Host Agent/tool capabilities exist;
the pseudocode interface and full category list below remain the target contract
for analyzer plugins and are not a claim that every category is implemented.

Analyzer output must preserve provenance. A static capability, observed runtime
behavior, confirmed vulnerability, suspicious indicator, ATT&CK triage signal,
and malware verdict are different concepts. MSAP does not produce malware
verdicts.

## Relationship to the Static Analyzer Registry

The existing static analyzer registry should remain the reference pattern:
analyzers are small, named units with declared capabilities, bounded execution,
structured output, and deterministic error handling where possible.

Dynamic analyzers differ because they may depend on:

- A live `DynamicSession`.
- An exclusive `DeviceLease`.
- Runtime tools such as ADB, Frida `17.16.4`, and mitmproxy `12.2.3`.
- Session state, coverage, timeouts, and cleanup outcomes.
- Raw evidence references in MinIO.

Static analyzers must remain runnable without dynamic-lab availability.
Dynamic analyzers must not mutate static results directly; correlation creates
new links or enriched records with explicit provenance.

## Analyzer Categories

| Category | Responsibility |
| --- | --- |
| `ADB_COLLECTOR` | Device state, package state, logcat, dumpsys, screenshots, file pulls where authorized. |
| `NETWORK_COLLECTOR` | Proxy lifecycle, flow capture, DNS/TLS/network normalization. |
| `FRIDA_COLLECTOR` | Frida server/session lifecycle, script loading, runtime API events. |
| `UI_EXERCISER` | Passive, basic, or scripted app interaction. |
| `STORAGE_INSPECTOR` | Runtime storage events and bounded post-run inspection. |
| `PROCESS_MONITOR` | Process lifecycle, foreground state, crashes, ANRs, command execution observations. |
| `COMPONENT_MONITOR` | Activity, service, receiver, intent, and component behavior observations. |
| `RULE_EVALUATOR` | Dynamic rule evaluation using normalized runtime evidence and coverage state. |
| `CORRELATOR` | Static/dynamic evidence correlation and finding enrichment. |

## AnalyzerContext Extension

New analyzer code should extend the existing session and analyzer contexts
rather than creating an unrelated execution model.

| Field | Meaning |
| --- | --- |
| `audit` | Current `Audit`. |
| `apk` | Current `APKFile`. |
| `static_context` | Static artifacts, findings, rule evaluations, and indicators when `COMBINED`. |
| `dynamic_session` | Current `DynamicSession`. |
| `device` | Leased `Device`. |
| `lease` | Active `DeviceLease` and lease token for ownership checks. |
| `snapshot` | Restored `EmulatorSnapshot`. |
| `object_storage` | MinIO adapter for raw and large evidence. |
| `artifact_sink` | Writer for normalized artifacts and evidence links. |
| `event_sink` | Writer for session events and stage diagnostics. |
| `capabilities` | Matched device/tool/session capabilities. |
| `timeouts` | Analyzer and stage timeout budget. |
| `redaction_policy` | Rules for normalized and raw evidence handling. |
| `cancellation_token` | Cooperative cancellation signal. |

## Inputs

Dynamic analyzers may receive:

- `DynamicSession` metadata and current state.
- Normalized dynamic artifacts already collected in the session.
- Raw evidence references through `ObjectStorageReference`.
- Static artifacts when combined mode is enabled.
- Existing `RuleEvaluation`, `Finding`, and `SuspiciousIndicator` records for
  enrichment or deduplication.
- Tool/session coverage metadata, including collector failures and skipped
  analyzers.

Analyzers must treat raw evidence as sensitive and must not copy sensitive
values into normalized fields.

## Outputs

Analyzers may emit:

- `RuleEvaluation` with PASS, FAIL, REVIEW_REQUIRED, NOT_APPLICABLE, or
  NOT_EVALUATED.
- `Finding` when evidence supports a security issue.
- `SuspiciousIndicator` for ATT&CK Mobile or triage signals.
- `NormalizedArtifact` records.
- `Evidence` links between artifacts, rules, findings, and indicators.
- Additional `DynamicSessionArtifact` and `DynamicSessionEvent` records.

Analyzer failure does not automatically mean vulnerability. Missing collector
coverage must produce `NOT_EVALUATED` or `REVIEW_REQUIRED`, not PASS.

## Lifecycle

| Step | Contract |
| --- | --- |
| `prepare` | Check capabilities, validate inputs, reserve local resources, and record coverage intent. |
| `collect` | Interact with the device/tool and capture raw evidence under bounded timeouts. |
| `normalize` | Convert raw evidence to bounded, redacted normalized artifacts. |
| `evaluate` | Apply dynamic rules using observed evidence and coverage state. |
| `cleanup` | Stop analyzer-owned hooks/processes and flush raw evidence references. |

Analyzers that only evaluate or correlate may skip `collect`, but must record
that their coverage depends on upstream artifacts.

## Failure Behavior

- Infrastructure failure: record a session event, mark affected coverage as
  partial or missing, and return a typed analyzer failure.
- Tool startup failure: do not infer that the app avoided the behavior; mark
  dependent rules `NOT_EVALUATED`.
- Hook/script failure: emit `FRIDA_SCRIPT_FAILED` or equivalent category and
  preserve partial evidence that was collected before failure.
- Normalization failure: preserve raw evidence reference where allowed and mark
  normalized output unavailable.
- Rule evaluator failure: produce `NOT_EVALUATED` or `REVIEW_REQUIRED` for
  affected rules, not PASS.
- Cleanup failure: escalate to session cleanup/quarantine policy.

## Timeout Behavior

Each analyzer must have:

- A hard timeout.
- Optional per-operation timeout.
- A cleanup timeout.
- A maximum raw evidence size or duration.
- Cooperative cancellation checks during long operations.

Timeouts must leave the session in a state where cleanup can still run. Timeout
does not prove absence of behavior.

## Partial Coverage Behavior

Partial coverage must be visible in artifacts, rule evaluations, and reports.
Examples:

- mitmproxy did not decrypt a flow: network visibility may be `CONNECT_ONLY`.
- Frida hook failed to attach: runtime API rules depending on that hook are
  `NOT_EVALUATED`.
- UI automation did not pass a login wall: credential-gated behavior is out of
  coverage unless an authorized scenario was supplied.
- QUIC/HTTP3 traffic may bypass classic proxy visibility.

## Capability Checks

Analyzers must declare required and optional capabilities.

| Capability | Example |
| --- | --- |
| Device | Android API level, ABI, root, SELinux `Enforcing`. |
| Tool | ADB availability, Frida `17.16.4`, mitmproxy `12.2.3`. |
| Session | `network_capture_enabled`, `frida_enabled`, `runtime_ca_enabled`, `ui_automation_enabled`. |
| Snapshot | `msap-instrumented-base` for Frida/runtime CA work. |
| Authorization | Explicit approval for credentialed or scripted flows. |

Missing required capability fails the analyzer as `NOT_EVALUATED`. Missing
optional capability records reduced coverage.

## Example Pseudocode Interface

```python
class DynamicAnalyzer:
    id = "network.cleartext_runtime"
    category = "NETWORK_COLLECTOR"
    required_capabilities = {"mitmproxy": "12.2.3"}
    optional_capabilities = {"runtime_ca_overlay": True}

    def prepare(self, context):
        context.require_session_state("STARTING_CAPTURE")
        context.require_capability("mitmproxy")
        return AnalyzerPrepared(coverage_intent=["NETWORK_FLOW", "TLS_EVENT"])

    def collect(self, context):
        with context.timeout("network_collect"):
            flow_ref = context.tools.mitmproxy.capture_until_session_end()
        return AnalyzerCollected(raw_references=[flow_ref])

    def normalize(self, context, collected):
        flows = context.normalizers.network.from_mitmproxy(collected.raw_references)
        return AnalyzerNormalized(artifacts=flows)

    def evaluate(self, context, normalized):
        if not normalized.coverage.decrypted_http_visible:
            return RuleEvaluation(
                rule_id="dynamic.network.visibility",
                result="NOT_EVALUATED",
                reason="No decrypted flow coverage for the exercised path",
            )
        return context.rules.evaluate_dynamic(normalized.artifacts)

    def cleanup(self, context):
        context.tools.mitmproxy.stop_if_owned()
```

## Policy Requirements

- Analyzer failure does not automatically mean vulnerability.
- Missing collector coverage must produce `NOT_EVALUATED` or
  `REVIEW_REQUIRED`, not PASS.
- ATT&CK indicators remain triage signals, not malware verdicts.
- Dynamic evidence increases confidence only when runtime behavior is actually
  observed.
- Static-only audits must remain independent from dynamic analyzer availability.
