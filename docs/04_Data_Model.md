# Data and Storage Model - MSAP

## Core Entities
- `Organization`: tenant boundary.
- `Project`: groups authorized audits.
- `Audit`: one APK assessment workflow.
- `APKFile`: APK metadata and upload hash information.
- `ObjectStorageReference`: pointer to an object stored in MinIO.
- `RawAnalyzerResult`: raw tool or adapter output.
- `NormalizedArtifact`: stable parsed artifact used by rules.
- `Finding`: MASVS-oriented security finding.
- `SuspiciousIndicator`: ATT&CK Mobile triage indicator.
- `Evidence`: traceable support for a finding or indicator.
- `Report`: idempotent metadata record for an on-demand JSON or PDF report.

## Object Storage Principle
PostgreSQL stores metadata, relationships and object references. MinIO stores APKs, large artifacts, evidence objects, reports and exports.

Raw APK bytes must never be stored in PostgreSQL.

## ObjectStorageReference Fields
| Field | Purpose |
|---|---|
| `id` | Stable database identifier |
| `bucket` | MinIO bucket |
| `object_key` | Full key inside the bucket |
| `object_type` | Controlled object category |
| `content_type` | MIME type or descriptor |
| `size_bytes` | Object size |
| `sha256` | Integrity hash |
| `audit_id` | Associated audit |
| `project_id` | Authorization and cleanup boundary |
| `retention_policy` | Retention class |
| `redaction_status` | Redaction state |
| `access_scope` | Project, audit, worker or export scope |

## Object Types
- `APK_UPLOAD`
- `EXTRACTED_MANIFEST`
- `EXTRACTED_RESOURCE`
- `DECOMPILED_CODE_ARCHIVE`
- `RAW_ANALYZER_RESULT`
- `NORMALIZED_ARTIFACT`
- `EVIDENCE_SNIPPET`
- `PDF_REPORT`
- `JSON_EXPORT`
- `AI_REDACTED_CONTEXT`

## Bucket Mapping
| Bucket | Object types |
|---|---|
| `msap-apk-uploads` | `APK_UPLOAD` |
| `msap-artifacts` | Extracted resources, raw results, normalized artifacts, redacted AI context |
| `msap-evidence` | Evidence snippets and larger evidence objects |
| `msap-reports` | PDF reports |
| `msap-exports` | JSON exports |

## Object Key Convention
```text
org/{organization_id}/project/{project_id}/audit/{audit_id}/{object_type}/{sha256_or_uuid}/{safe_filename}
```

Object keys must use sanitized filenames and must not be treated as the authorization boundary.
