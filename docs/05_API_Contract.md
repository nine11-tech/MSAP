# API Contract - MSAP

## Principles
- API endpoints enforce authentication and project authorization.
- APK uploads create metadata first, object storage references second, and analysis tasks third.
- Long-running analysis is asynchronous.
- Report and export downloads are mediated by the backend or short-lived pre-signed URLs.

## Authentication and operational endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/auth/csrf/` | Initialize CSRF |
| `POST` | `/api/auth/login/` | Create/rotate Django session |
| `POST` | `/api/auth/logout/` | Invalidate authenticated session |
| `GET` | `/api/auth/me/` | Current safe user/role data |
| `POST` | `/api/auth/change-password/` | Validated password change |
| `GET` | `/api/system/status/` | Sanitized component status |

All endpoints except health, CSRF initialization, and login require an
authenticated session. Unsafe requests require `X-CSRFToken`. Viewers are
read-only, analysts can create/update/upload/analyze, and destructive deletion
is administrator-only.

## Assessment endpoints
| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/projects/` | Create project |
| `GET` | `/api/projects/` | List accessible projects |
| `POST` | `/api/audits/` | Create audit |
| `GET` | `/api/audits/{audit_id}/` | Get audit metadata and status |
| `POST` | `/api/audits/{audit_id}/apk-upload/initiate/` | Create presigned upload contract |
| `POST` | `/api/audits/{audit_id}/analysis/start/` | Start analysis |
| `GET` | `/api/audits/{audit_id}/analysis/status/` | Job/progress state |
| `GET` | `/api/audits/{audit_id}/coverage/` | Rule/analyzer coverage |
| `GET` | `/api/findings/?audit={id}` | Findings |
| `GET` | `/api/indicators/?audit={id}` | ATT&CK triage |
| `GET` | `/api/evidence/?audit={id}` | Evidence |
| `GET` | `/api/rule-evaluations/?audit={id}` | Full evaluation states |
| `GET` | `/api/audits/{audit_id}/report/json/` | JSON report |
| `GET` | `/api/audits/{audit_id}/report/pdf/` | PDF report |

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
