# Schema des Regles MSAP V1

## Objectif

MSAP V1 utilise deux catalogues YAML:

- `rules/masvs_static_rules.yaml` pour les regles AppSec OWASP MASVS.
- `rules/attck_mobile_triage_rules.yaml` pour les indicateurs de triage MITRE ATT&CK Mobile.

Les deux catalogues sont des configurations de securite. Ils doivent etre charges et valides avant toute analyse.

## Common Fields

| Field | Description |
|---|---|
| `id` | Identifiant unique, par exemple `MSAP-AND-001` ou `MSAP-MOB-001`. |
| `title` | Titre court. |
| `description` | Description de la detection. |
| `standard` | `OWASP MASVS` ou `MITRE ATT&CK Mobile`. |
| `severity` | Severite par defaut. |
| `confidence` | Confiance par defaut. |
| `source` | Artefact analyse. |
| `detection_type` | Type d'execution. |
| `pattern_or_condition` | Motif, regex ou condition. |
| `evidence_example` | Exemple de preuve attendue. |

## MASVS Static Rules Schema

Champs obligatoires:

- `id`
- `title`
- `description`
- `standard`
- `masvs_category`
- `severity`
- `source`
- `detection_type`
- `pattern_or_condition`
- `impact`
- `recommendation`
- `evidence_example`
- `confidence`

Example:

```yaml
id: MSAP-AND-001
title: Android debuggable enabled
description: The application is configured with android:debuggable set to true.
standard: OWASP MASVS
masvs_category: MASVS-RESILIENCE
severity: High
confidence: High
source: AndroidManifest.xml
detection_type: manifest_attribute
pattern_or_condition: "application/@android:debuggable == true"
impact: Debuggable production builds can expose runtime inspection.
recommendation: Disable android:debuggable for production builds.
evidence_example: "<application android:debuggable=\"true\" ...>"
```

## ATT&CK Triage Rules Schema

Champs obligatoires:

- `id`
- `title`
- `description`
- `standard`
- `tactic`
- `technique_id`
- `technique_name`
- `platform`
- `severity`
- `confidence`
- `source`
- `detection_type`
- `pattern_or_condition`
- `triage_interpretation`
- `analyst_recommendation`
- `evidence_example`

Example:

```yaml
id: MSAP-MOB-004
title: Accessibility service usage
description: The APK declares an accessibility service.
standard: MITRE ATT&CK Mobile
tactic: Privilege Escalation
technique_id: M1016
technique_name: Accessibility Features
platform: Android
severity: High
confidence: High
source: AndroidManifest.xml
detection_type: manifest_component_rule
pattern_or_condition: "service declares android.accessibilityservice.AccessibilityService"
triage_interpretation: May indicate accessibility capability and should be reviewed by an analyst.
analyst_recommendation: Verify legitimate accessibility purpose and user consent.
evidence_example: "<service android:permission=\"android.permission.BIND_ACCESSIBILITY_SERVICE\" ...>"
```

## Rule Severity Values

- `Informational`
- `Low`
- `Medium`
- `High`
- `Critical`

## Confidence Values

- `Low`
- `Medium`
- `High`

## Detection Types

- `manifest_attribute`
- `manifest_permission`
- `manifest_component_rule`
- `configuration_condition`
- `xml_configuration_rule`
- `string_pattern`
- `regex_secret_detection`
- `regex_ioc_detection`
- `heuristic_code_pattern`
- `code_pattern`
- `absence_indicator`
- `permission_set_heuristic`
- `obfuscation_heuristic`

## Evidence Fields Produced by Engines

- `standard`
- `rule_id` or `indicator_id`
- `source`
- `artifact_type`
- `file_path`
- `line_number`
- `snippet`
- `redacted`
- `confidence`
- `detected_at`

## Validation Rules

- Root key must be `rules`.
- Rule IDs must be unique.
- MASVS IDs must match `MSAP-AND-NNN`.
- ATT&CK indicator IDs must match `MSAP-MOB-NNN`.
- All required fields must be present and non-empty.
- `severity`, `confidence` and `detection_type` must be allowed values.
- `standard` must match the file purpose.
- Regex patterns must compile before analysis.
- Triage text must avoid definitive malware verdict language.
- Evidence examples must not contain real secrets.

## Backend Loading Process

1. Load YAML files from local `rules/`.
2. Parse YAML safely.
3. Validate root structure and required fields.
4. Validate enum values and ID formats.
5. Compile regex-based rules.
6. Synchronize valid rules into database or load in memory.
7. Fail fast if a mandatory rules file is invalid.
8. Log schema errors locally without leaking APK data.
