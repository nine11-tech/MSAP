# Static/Dynamic Correlation Contract

## Purpose

This document defines how MSAP should correlate static capabilities and
indicators with observed dynamic behavior. Correlation increases analyst value
by linking evidence across phases, but it must not overclaim.

A permission, string, API reference, component declaration, or ATT&CK mapping is
not a confirmed vulnerability by itself. Runtime evidence confirms only the
behavior that was actually observed during the exercised session. MSAP does not
produce malware verdicts.

## Evidence Classes

| Class | Meaning |
| --- | --- |
| Static capability | Declared permission, manifest setting, endpoint string, API reference, component, configuration, or packaged resource. |
| Observed runtime behavior | Dynamic artifact produced by a collector during a bounded session. |
| Confirmed vulnerability | Finding supported by enough configuration and/or runtime evidence under a rule contract. |
| Suspicious indicator | Triage signal, including ATT&CK Mobile mappings, requiring analyst context. |
| Malware verdict | Out of scope for MSAP. |

## Correlation Confidence Levels

| Level | Meaning |
| --- | --- |
| `NONE` | No meaningful relationship found. |
| `WEAK` | Same broad category or package, but no specific shared key. |
| `MODERATE` | Shared domain, component, API family, permission, or behavior class. |
| `STRONG` | Specific static reference matches an observed runtime behavior. |
| `CONFIRMED` | Runtime behavior plus static/configuration context satisfies the rule's confirmation criteria. |

Correlation confidence is not the same as severity. A confirmed low-severity
finding and a weak high-risk signal must remain distinguishable.

## Correlation Examples

| Static signal | Runtime evidence | Correlation result | Reporting behavior |
| --- | --- | --- | --- |
| Cleartext traffic capability in manifest/network config | Observed `NETWORK_FLOW` with `scheme=http` | `CONFIRMED` cleartext behavior if attribution is reliable | Create or enrich cleartext finding with dynamic evidence. |
| WebView risk such as JavaScript/file access reference | Observed `WEBVIEW_EVENT` loading unsafe URL or using risky settings | `STRONG` or `CONFIRMED` depending on exploitability context | Enrich WebView finding; require manual validation for bridge exposure. |
| Dynamic-code-loading reference | Observed `RUNTIME_API_CALL` for dex/class loading | `STRONG`; `CONFIRMED` only when unsafe source/storage context is observed | Create/enrich finding based on rule criteria. |
| `Runtime.exec` reference | Observed `PROCESS_EVENT` or API hook for command execution | `STRONG`; require redacted argument/context review | Usually create `SuspiciousIndicator` or `REVIEW_REQUIRED` finding unless rule criteria are met. |
| Crypto weakness reference | Observed weak algorithm at runtime | `STRONG` or `CONFIRMED` when used in security-sensitive operation | Enrich crypto finding; avoid claiming data compromise without evidence. |
| Sensitive permission | Observed protected API access or permission prompt/grant | `MODERATE` to `CONFIRMED` depending on observed data access | Enrich privacy/security finding; permission alone is not confirmed. |
| Extracted endpoint | Observed network flow to matching host/path hash | `STRONG` | Link endpoint artifact to flow; create finding only if insecure behavior is observed. |
| Secret candidate | Observed runtime use of matching redacted hash/fingerprint | `STRONG`; manual validation required | Enrich existing secret finding or create review item; do not expose secret value. |
| Exported component | Observed external invocation of matching component | `CONFIRMED` external reachability for exercised invocation | Create/enrich exported-component finding if authorization/rule criteria are met. |
| Resilience signal such as anti-hook/root detection | Observed anti-hook/root-detection behavior | `STRONG` suspicious/resilience indicator | Create `SuspiciousIndicator`; do not call it malware. |

## Deduplication Policy

- Use stable correlation keys such as package name, component name, API
  signature, endpoint hash, URL hash, permission name, rule id, and evidence
  fingerprint.
- Prefer enriching an existing finding when the static and dynamic evidence
  describe the same weakness and affected asset.
- Create a new finding only when the runtime behavior represents a distinct
  issue, affected component, data path, or rule.
- Do not create separate findings for every duplicate network request or
  repeated API call; attach representative evidence and aggregate counts.
- Preserve all material evidence links even when findings are deduplicated.

## Evidence Linking

Correlation records should link:

- Static `NormalizedArtifact` records.
- Dynamic `DynamicSessionArtifact` records.
- Raw `ObjectStorageReference` records when report reviewers need traceability.
- `Evidence` records supporting findings and indicators.
- `RuleEvaluation` records that consumed the correlated evidence.

Each link must include provenance, correlation confidence, redaction state, and
whether manual validation is required.

## Finding Update Rules

### Enrich an Existing Finding

Enrich when:

- The static finding already identifies the affected rule and asset.
- Dynamic evidence confirms or strengthens the same behavior.
- The severity and remediation remain materially the same.
- Additional evidence improves confidence, reproduction steps, or coverage.

Allowed updates include confidence, evidence links, observed examples, coverage
notes, report text, and manual-validation status.

### Create a New Finding

Create a new finding when:

- Runtime behavior reveals a weakness not represented statically.
- The affected component, endpoint, data store, or permission use is distinct.
- Runtime evidence changes the rule outcome from not applicable/static-only
  review to a supported FAIL under the rule.
- The remediation differs from the existing finding.

### Create a SuspiciousIndicator

Create a `SuspiciousIndicator` when:

- The behavior is a triage signal, not a confirmed vulnerability.
- ATT&CK Mobile mapping is useful for analyst review.
- Resilience, anti-hook, root-detection, suspicious command execution, or
  unusual network behavior is observed but security impact is not proven.

ATT&CK indicators must be labeled as triage signals and excluded from malware
verdicts and vulnerability risk scoring unless a separate confirmed finding
exists.

## Manual Validation Rules

Manual validation is required when:

- Evidence is partially redacted or redaction status is unknown.
- Attribution to the target app is ambiguous.
- TLS visibility is blocked by pinning, custom trust, native TLS, or QUIC/HTTP3.
- Secret use is inferred from hashes or fingerprints.
- A permission or API reference lacks observed sensitive data access.
- UI automation did not exercise credential-gated or hidden flows.
- The rule depends on exploitability or business context.

## Avoiding Double-Counting

- A static finding and its dynamic confirmation should appear as one finding
  with multiple evidence sources.
- Repeated runtime events should increment occurrence counts or attach sampled
  evidence, not create duplicate findings.
- A suspicious indicator and a vulnerability finding may reference the same
  evidence, but reports must explain their different purposes.
- `NOT_EVALUATED` and `REVIEW_REQUIRED` are coverage states, not passing
  results.

## JSON Report Representation

Reports should expose correlation without flattening provenance:

```json
{
  "finding_id": "finding_cleartext_01",
  "title": "Cleartext HTTP traffic observed",
  "result": "FAIL",
  "correlation": {
    "confidence": "CONFIRMED",
    "static_evidence": ["norm_art_network_config_01"],
    "dynamic_evidence": ["dyn_art_network_flow_01"],
    "raw_references": ["obj_ref_mitm_flow_01"],
    "manual_validation_required": false,
    "notes": "Static cleartext capability matched observed HTTP runtime flow."
  }
}
```

## PDF Report Representation

PDF reports should show:

- Finding title, severity, and rule outcome.
- Static evidence section with capability/configuration details.
- Dynamic evidence section with observed behavior and session coverage.
- Correlation confidence label.
- Redaction and manual-validation notes.
- Limitations such as unexercised flows or blocked TLS interception.

The PDF must not imply all traffic was intercepted, all app behavior was
covered, or the app is malware.
