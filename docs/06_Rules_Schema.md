# Rules Schema - MSAP

## Purpose
MSAP uses YAML rule files to define initial MASVS findings and ATT&CK Mobile triage indicators without hard-coding rule logic into the backend.

## Common Fields
```yaml
id: MSAP-AND-001
title: Exported activity without clear protection
description: Detects exported Android components that may need review.
standard: OWASP MASVS
severity: High
confidence: High
prerequisites: [MANIFEST]
condition: exported_activity_unprotected
pattern_or_condition: exported activity and permission is absent
evidence_requirements: Persisted normalized component metadata.
requires_manual_validation: false
```

## MASVS Rule Fields
- `id`
- `title`
- `description`
- `masvs_category`
- `masvs_controls`
- `maswe_ids`
- `mastg_references`
- `cwe_ids`
- `severity`
- `confidence`
- `detection_type`
- `condition`
- `prerequisites`
- `evidence_requirements`
- `remediation`
- `false_positive_guidance`
- `requires_manual_validation`
- `test_type`

## ATT&CK Rule Fields
- `id`
- `title`
- `description`
- `technique_id`
- `technique_name`
- `tactic`
- `confidence`
- `detection_type`
- `condition`
- `values`
- `mapping_rationale`
- `false_positive_considerations`
- `requires_manual_validation`
- `non_malware_verdict_note`

## Controlled Values
Severity: `Low`, `Medium`, `High`, `Critical`.

Confidence: `Low`, `Medium`, `High`.

Detection types:
- `manifest_query`
- `permission_match`
- `component_exposure`
- `network_config`
- `string_pattern`
- `code_pattern`
- `certificate_check`

## Loading Rules
Workers load repository-owned YAML at task execution. `validate_rules` rejects
duplicates, malformed internal/framework identifiers, and missing required
metadata. `rules/framework_metadata.yaml` records official sources and snapshot
dates. Updates are manual; audits never require internet access.
