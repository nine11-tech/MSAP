# API Contract - MSAP

## Principles
- API endpoints enforce authentication and project authorization.
- APK uploads create metadata first, object storage references second, and analysis tasks third.
- Long-running analysis is asynchronous.
- Report and export downloads are mediated by the backend or short-lived pre-signed URLs.

## Initial Endpoints
| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/projects/` | Create project |
| `GET` | `/api/projects/` | List accessible projects |
| `POST` | `/api/projects/{project_id}/audits/` | Create audit |
| `GET` | `/api/audits/{audit_id}/` | Get audit metadata and status |
| `POST` | `/api/audits/{audit_id}/apk/` | Upload APK |
| `POST` | `/api/audits/{audit_id}/analysis/` | Start or retry analysis |
| `GET` | `/api/audits/{audit_id}/findings/` | List findings |
| `GET` | `/api/audits/{audit_id}/indicators/` | List ATT&CK indicators |
| `GET` | `/api/audits/{audit_id}/evidence/` | List evidence |
| `POST` | `/api/audits/{audit_id}/exports/json/` | Generate JSON export |
| `GET` | `/api/reports/{report_id}/download/` | Download export/report |

## Audit Status Values
- `created`
- `apk_uploaded`
- `queued`
- `analyzing`
- `completed`
- `failed`
- `export_ready`

## Upload Validation
The backend validates:
- File size limit.
- Content type or APK magic where practical.
- SHA-256 hash.
- Project access.
- MinIO write success.
- Database reference creation.

## Error Handling
Errors must be safe for logs and API responses. They should include correlation identifiers but must not include secrets, APK contents or unredacted evidence.

