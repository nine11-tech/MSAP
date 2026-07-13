# Rules Schema - MSAP

## Purpose
MSAP uses YAML rule files to define initial MASVS findings and ATT&CK Mobile triage indicators without hard-coding rule logic into the backend.

## Common Fields
```yaml
id: MASVS-001
title: Exported activity without clear protection
description: Detects exported Android components that may need review.
enabled: true
severity: medium
confidence: medium
detection_type: manifest_query
evidence:
  artifact_type: manifest
  fields:
    - component_name
    - exported
```

## MASVS Rule Fields
- `id`
- `title`
- `description`
- `enabled`
- `masvs_control`
- `severity`
- `confidence`
- `detection_type`
- `match`
- `evidence`
- `remediation`

## ATT&CK Rule Fields
- `id`
- `title`
- `description`
- `enabled`
- `attack_technique_id`
- `attack_technique_name`
- `confidence`
- `detection_type`
- `match`
- `evidence`
- `triage_note`

## Controlled Values
Severity:
- `info`
- `low`
- `medium`
- `high`
- `critical`

Confidence:
- `low`
- `medium`
- `high`

Detection types:
- `manifest_query`
- `permission_match`
- `component_exposure`
- `network_config`
- `string_pattern`
- `code_pattern`
- `certificate_check`

## Loading Rules
Workers load YAML rules at startup or task execution. Invalid rules must fail closed with clear validation errors and must not silently produce findings.

