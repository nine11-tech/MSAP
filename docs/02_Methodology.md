# Security Methodology - MSAP

## Assessment Model
MSAP combines application security assessment with cautious threat triage:
- OWASP MASVS is used for AppSec-oriented findings.
- MITRE ATT&CK Mobile is used for suspicious indicator mapping.
- Evidence links every finding or indicator to an observable source.

## Static Analysis Inputs
Initial analysis focuses on:
- APK metadata.
- Android manifest.
- Permissions.
- Exported components.
- Network configuration.
- Strings, URLs and domains.
- Certificate and signing metadata.
- Simple code and configuration patterns.

## MASVS Findings
MASVS rules identify security weaknesses such as insecure configuration, risky exported components, weak network controls, sensitive data exposure or insecure cryptography indicators.

Each finding should include:
- Rule identifier.
- MASVS mapping.
- Severity.
- Confidence.
- Evidence links.
- Remediation guidance.

The repository catalog contains 36 useful static evaluations across all eight
MASVS categories. `RuleEvaluation` records PASS, FAIL, REVIEW_REQUIRED,
NOT_APPLICABLE, and NOT_EVALUATED. Only FAIL creates a finding. Missing analyzer
evidence is NOT_EVALUATED and is never counted as passing compliance. Mappings
to MASWE and MASTG are included only where official identifiers were manually
verified.

## ATT&CK Mobile Triage
ATT&CK mappings are indicators, not verdicts. They may help analysts prioritize review, but they must not be presented as proof of malware.

Each indicator should include:
- ATT&CK technique mapping.
- Observable behavior or artifact.
- Confidence.
- Evidence links.
- Analyst interpretation note.

The Android catalog contains 20 capability-oriented mappings from the ATT&CK
Mobile matrix snapshot. Permissions and API references indicate capability, not
execution. Indicators remain separate from vulnerability risk.

## Evidence Rules
- Evidence must be traceable to source artifacts.
- Short redacted snippets may be stored in PostgreSQL.
- Larger evidence objects go to MinIO.
- Redaction status must be tracked.
- Reports must distinguish deterministic findings from analyst or optional AI commentary.

## Scoring

Risk scoring uses persisted failed findings only. Severity weights are Critical
`10`, High `7`, Medium `4`, and Low `1`; confidence factors are High `1.0`,
Medium `0.75`, and Low `0.5`:

```text
risk = min(10 × Σ(severity_weight × confidence_factor), 100)
```

Risk levels are Low `0–30`, Medium `31–60`, High `61–80`, and Critical
`81–100`. ATT&CK indicators do not increase this score.

For MASVS, applicable rules are `PASS + FAIL + REVIEW_REQUIRED`. The compliance
formula is:

```text
compliance = PASS / (PASS + FAIL + REVIEW_REQUIRED) × 100
```

The result is `0` when no rule is applicable. `NOT_APPLICABLE` and
`NOT_EVALUATED` are excluded from the denominator; unevaluated rules produce an
explicit partial-coverage warning and are never counted as passing. Reports
include applicable, evaluated, passed, failed, review-required, not-applicable,
and unevaluated counts so the percentage is not presented without its coverage.
