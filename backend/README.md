# MSAP Backend

This directory contains the backend foundation for MSAP. It includes Django settings, initial metadata models, YAML rule catalog validation, and the first DRF API layer for metadata records.

This sprint does not implement React, Kubernetes manifests, Helm charts, Kimi AI, Celery task execution, full APK analysis, MobSF, Frida, dynamic analysis, iOS analysis or malware sandboxing.

## Setup
```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

## Migrations
Create and apply migrations:

```bash
python manage.py makemigrations
python manage.py migrate
```

By default, local development can use SQLite through `DATABASE_URL=sqlite:///db.sqlite3`. For PostgreSQL, set either `DATABASE_URL` or the `POSTGRES_*` variables in `.env`.

## Development Server
Run the local API server:

```bash
python manage.py runserver
```

The API is available at `http://127.0.0.1:8000/api/`.

## API Endpoints
The current API is intentionally simple and does not implement authentication, raw file proxy uploads through Django, APK parsing, Celery execution, or AI assistance.

Writable metadata endpoints:
- `GET /api/health/`
- `GET|POST /api/projects/`
- `GET|PUT|PATCH|DELETE /api/projects/{id}/`
- `GET|POST /api/audits/`
- `GET|PUT|PATCH|DELETE /api/audits/{id}/`
- `POST /api/audits/{id}/apk-upload/initiate/`
- `GET|POST /api/apk-files/`
- `GET|PUT|PATCH|DELETE /api/apk-files/{id}/`
- `POST /api/apk-files/{id}/confirm-upload/`
- `GET|POST /api/storage-references/`
- `GET|PUT|PATCH|DELETE /api/storage-references/{id}/`

Read-only analysis result endpoints:
- `GET /api/findings/`
- `GET /api/findings/{id}/`
- `GET /api/indicators/`
- `GET /api/indicators/{id}/`
- `GET /api/evidence/`
- `GET /api/evidence/{id}/`
- `GET /api/risk-scores/`
- `GET /api/risk-scores/{id}/`
- `GET /api/compliance-scores/`
- `GET /api/compliance-scores/{id}/`
- `GET /api/reports/`
- `GET /api/reports/{id}/`

Health response:

```json
{
  "status": "ok",
  "service": "msap-backend"
}
```

## MinIO Storage
MSAP stores APK bytes and large artifacts in MinIO-compatible object storage. PostgreSQL stores metadata and object references only.

Configure MinIO with:

```env
MINIO_ENDPOINT=http://localhost:9000
MINIO_ACCESS_KEY=your-access-key
MINIO_SECRET_KEY=your-secret-key
MINIO_SECURE=false
MINIO_BUCKET_APK_UPLOADS=msap-apk-uploads
MINIO_BUCKET_ARTIFACTS=msap-artifacts
MINIO_BUCKET_EVIDENCE=msap-evidence
MINIO_BUCKET_REPORTS=msap-reports
MINIO_BUCKET_EXPORTS=msap-exports
MSAP_PRESIGNED_URL_EXPIRES_SECONDS=900
MSAP_MAX_APK_SIZE_BYTES=524288000
```

Tests mock the MinIO/boto3 service and do not require a running MinIO server.

## APK Upload Contract
Start an APK upload by creating metadata and receiving a presigned MinIO PUT URL:

```http
POST /api/audits/1/apk-upload/initiate/
Content-Type: application/json
```

```json
{
  "filename": "sample.apk",
  "content_type": "application/vnd.android.package-archive",
  "size_bytes": 123456,
  "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}
```

Response:

```json
{
  "apk_file_id": 1,
  "storage_reference_id": 1,
  "bucket": "msap-apk-uploads",
  "object_key": "projects/1/audits/1/apk_upload/uuid-sample.apk",
  "upload_url": "http://localhost:9000/...",
  "expires_in": 900
}
```

The client uploads the APK bytes directly to `upload_url` with the same `Content-Type`. V1.0 accepts `.apk` files only; `.aab` and `.ipa` are rejected. Real APK parsing is not implemented yet, and this endpoint does not start analysis.

After the object upload succeeds, confirm metadata:

```http
POST /api/apk-files/1/confirm-upload/
Content-Type: application/json
```

```json
{
  "size_bytes": 123456,
  "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}
```

Confirmation updates APK metadata and the linked storage reference status. It does not parse the APK and does not enqueue analysis.

## OpenAPI and Swagger
The OpenAPI schema and Swagger UI are provided by drf-spectacular:

- OpenAPI schema: `http://127.0.0.1:8000/api/schema/`
- Swagger UI: `http://127.0.0.1:8000/api/docs/`

## Validate Rules
```bash
python manage.py validate_rules
```

The command validates:
- `../rules/masvs_static_rules.yaml`
- `../rules/attck_mobile_triage_rules.yaml`

## Run Tests
```bash
pytest
```

To run only the API tests:

```bash
pytest tests/test_api.py
```

## Environment Variables
Core variables are documented in `.env.example` and include:
- Django settings: `DJANGO_SECRET_KEY`, `DJANGO_DEBUG`, `DJANGO_ALLOWED_HOSTS`
- Database settings: `DATABASE_URL` or `POSTGRES_*`
- Redis settings: `REDIS_URL`
- MinIO settings: `MINIO_ENDPOINT`, `MINIO_ACCESS_KEY`, `MINIO_SECRET_KEY`, `MINIO_SECURE`, bucket names
- Upload settings: `MSAP_PRESIGNED_URL_EXPIRES_SECONDS`, `MSAP_MAX_APK_SIZE_BYTES`, `MSAP_VERIFY_UPLOAD_WITH_HEAD`
- Analyzer settings: `ANALYZER_RULES_PATH`, `ANALYZER_WORKDIR`, `ANALYZER_TIMEOUT_SECONDS`

## Scope Note
This is backend cloud foundation only. It establishes metadata models, rule validation, MinIO presigned upload initiation and upload confirmation before asynchronous analysis and reporting workflows are implemented.
