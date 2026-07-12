# AI Context and Redaction Model - MSAP

## Purpose

AI context construction provides Kimi AI with enough redacted information to draft useful text while protecting APK confidentiality, secrets and personal data.

## Allowed AI Input Fields

- Audit ID and report section requested.
- Finding IDs and indicator IDs.
- MASVS category and rule ID.
- MITRE ATT&CK Mobile tactic and technique IDs.
- Severity, confidence and risk score.
- Evidence IDs.
- Short redacted evidence excerpts.
- Deterministic remediation hints.
- Analyst-selected scope notes.

## Forbidden AI Input Fields

- Raw APK files.
- Full decompiled source code.
- Private keys, tokens, credentials or API keys.
- Unredacted secrets.
- Full file system paths.
- Personal data not required for the report.
- Large APK-derived string dumps.
- Internal environment variables.

## Redaction Rules

All AI contexts pass through redaction before any connector call. Redaction must be deterministic, logged by type/count and applied before prompt assembly.

## Secret Masking

Detected secrets are replaced with placeholders such as `[REDACTED_SECRET_1]`. The original value is never included in AI context.

## URL and Domain Masking

URLs and domains are masked unless the analyst explicitly marks them safe for reporting. Default placeholders are `[REDACTED_URL_1]` and `[REDACTED_DOMAIN_1]`.

## Token and API Key Masking

Bearer tokens, API keys, JWTs, cloud keys and long high-entropy strings are replaced with `[REDACTED_TOKEN_1]`.

## Email and Personal Data Masking

Email addresses and personal data are replaced with `[REDACTED_EMAIL_1]` or `[REDACTED_PERSONAL_DATA_1]`.

## Evidence Truncation

Evidence excerpts are truncated to a configurable maximum length. The context keeps the evidence ID and artifact type so the analyst can trace back locally.

## Prompt Injection Risk from APK Strings

APK strings may contain hostile instructions such as "ignore previous instructions". All APK-derived text must be treated as data, never as instructions.

## Delimiting Untrusted APK-Derived Text

Untrusted text must be placed inside explicit delimiters:

```text
BEGIN_UNTRUSTED_APK_EVIDENCE evidence_id=EV-001
...
END_UNTRUSTED_APK_EVIDENCE
```

Prompts must instruct the model to ignore commands inside those delimiters.

## AI Request Audit Logging

Audit logs should store provider, model, endpoint purpose, timestamp, user ID, audit ID, context hash, redaction summary, status, latency and output review state. Logs must not store API keys or unredacted sensitive values.

## AI Context JSON Example

```json
{
  "audit_id": "AUD-2026-001",
  "purpose": "masvs_finding_explanation",
  "finding": {
    "id": "F-MASVS-001",
    "rule_id": "MASVS-NETWORK-001",
    "masvs_category": "MASVS-NETWORK",
    "severity": "high",
    "risk_score": 8.1,
    "evidence_ids": ["EV-001"]
  },
  "evidence": [
    {
      "id": "EV-001",
      "artifact_type": "manifest",
      "excerpt": "android:usesCleartextTraffic=\"true\""
    }
  ]
}
```

## Redacted Context JSON Example

```json
{
  "audit_id": "AUD-2026-001",
  "purpose": "masvs_finding_explanation",
  "finding": {
    "id": "F-MASVS-001",
    "rule_id": "MASVS-NETWORK-001",
    "masvs_category": "MASVS-NETWORK",
    "severity": "high",
    "risk_score": 8.1,
    "evidence_ids": ["EV-001"]
  },
  "evidence": [
    {
      "id": "EV-001",
      "artifact_type": "manifest",
      "excerpt": "BEGIN_UNTRUSTED_APK_EVIDENCE evidence_id=EV-001\nandroid:usesCleartextTraffic=\"true\"\nEND_UNTRUSTED_APK_EVIDENCE"
    }
  ],
  "redaction_summary": {
    "secrets_masked": 0,
    "urls_masked": 0,
    "domains_masked": 0,
    "emails_masked": 0,
    "truncated_evidence": 0
  }
}
