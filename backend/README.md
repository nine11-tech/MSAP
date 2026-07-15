# MSAP Backend

This directory contains the backend foundation for MSAP. It includes Django settings, initial metadata models, YAML rule catalog validation, MinIO upload metadata, and the first asynchronous analysis boundary with Celery.

This sprint does not implement React, Kubernetes manifests, Helm charts, Kimi AI, full APK parsing, MASVS/ATT&CK execution, MobSF, Frida, dynamic analysis, iOS analysis or malware sandboxing.

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

Run a local Celery worker in a separate shell when not using eager mode:

```bash
celery -A msap worker -l info
```

Celery uses Redis as its broker by default. For local development, run Redis with your preferred package manager or container runtime and point `REDIS_URL` or `CELERY_BROKER_URL` at it, for example `redis://localhost:6379/0`.

## API Endpoints
The current API is intentionally simple and does not implement authentication, raw file proxy uploads through Django, APK parsing, MASVS/ATT&CK execution, or AI assistance.

Writable metadata endpoints:
- `GET /api/health/`
- `GET|POST /api/projects/`
- `GET|PUT|PATCH|DELETE /api/projects/{id}/`
- `GET|POST /api/audits/`
- `GET|PUT|PATCH|DELETE /api/audits/{id}/`
- `POST /api/audits/{id}/apk-upload/initiate/`
- `POST /api/audits/{id}/analysis/start/`
- `GET /api/audits/{id}/analysis/status/`
- `GET|POST /api/apk-files/`
- `GET|PUT|PATCH|DELETE /api/apk-files/{id}/`
- `POST /api/apk-files/{id}/confirm-upload/`
- `GET|POST /api/storage-references/`
- `GET|PUT|PATCH|DELETE /api/storage-references/{id}/`

Read-only analysis result endpoints:
- `GET /api/analyzers/`
- `GET /api/raw-analyzer-results/`
- `GET /api/raw-analyzer-results/{id}/`
- `GET /api/normalized-artifacts/`
- `GET /api/normalized-artifacts/{id}/`
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

## Async Analysis Boundary
After an audit has at least one `APKFile`, start placeholder analysis explicitly:

```http
POST /api/audits/1/analysis/start/
```

Response:

```json
{
  "audit_id": 1,
  "analysis_job_id": 1,
  "task_id": "celery-task-id",
  "status": "ANALYSIS_QUEUED"
}
```

Check the latest analysis job:

```http
GET /api/audits/1/analysis/status/
```

```json
{
  "audit_id": 1,
  "audit_status": "ANALYSIS_COMPLETED",
  "latest_job": {
    "id": 1,
    "task_id": "celery-task-id",
    "status": "COMPLETED",
    "started_at": "2026-07-14T12:00:00Z",
    "finished_at": "2026-07-14T12:00:01Z",
    "error_message": ""
  }
}
```

The placeholder task proves the worker boundary and calls the internal `AnalysisOrchestrator`. It marks the audit and `AnalysisJob` as running, creates placeholder raw and normalized records, then marks the job completed. It does not parse APKs and does not execute MASVS or MITRE ATT&CK Mobile rules yet.

## Analysis Orchestration Skeleton
The Celery analysis task now delegates internal work to `AnalysisOrchestrator`. The orchestrator loads the audit, claims the latest linked `APKFile` metadata, verifies that the APK file has an object storage reference, runs a placeholder metadata analyzer, creates one raw analyzer result, creates one normalized artifact, and returns a structured summary to the `AnalysisJob`.

`RawAnalyzerResult` represents raw output from future analyzer plugins. In this sprint it stores only placeholder metadata from the `APKFile` and its storage reference. It does not contain parsed manifest data, decompiled code, rule matches, evidence, or external tool output.

`NormalizedArtifact` represents canonical data that future MASVS and ATT&CK engines can consume after analyzer-specific output is normalized. In this sprint the orchestrator creates a placeholder `APK_METADATA` artifact only. The normalized payload records known database metadata such as APK id, package name, version name, hash, size, and storage reference id.

No real APK parsing is implemented yet. The orchestrator does not download APK bytes, run apktool, run jadx, run Androguard, execute MASVS rules, execute ATT&CK Mobile indicators, create findings, create suspicious indicators, or calculate risk scores. This keeps V1.0 focused on the durable worker and data-flow boundary before analyzer engines are introduced.

This prepares the future pipeline by separating:
- analyzer plugin execution into the `apps.analyzers` contract,
- raw analyzer output into `RawAnalyzerResult`,
- canonical downstream inputs into `NormalizedArtifact`,
- job and audit lifecycle management into the Celery task and orchestrator boundary.

## Analyzer Registry and Normalization Contracts
`AnalyzerRegistry` is the deterministic discovery layer for analysis components. It returns registered analyzer instances, filters them with each analyzer's `supports(context)` method, and exposes read-only analyzer metadata through `GET /api/analyzers/`. The default registry currently registers only `PlaceholderMetadataAnalyzer`.

Analyzers are registered instead of hardcoded in the orchestrator so future APK metadata, manifest, permissions, components, certificate, string, resource, and code reference analyzers can be added without rewriting the orchestration loop. The registry intentionally avoids dynamic imports; analyzers are added explicitly and run in stable order.

`RawAnalyzerResult` stores the analyzer-specific raw summary for each analyzer run. `NormalizedArtifact` stores stable, canonical payloads that future MASVS and ATT&CK engines can consume without depending on individual analyzer output formats.

Normalized artifact schema helpers live in `apps.normalization.services.schemas`. Current contracts include:
- `APK_METADATA`: populated from existing `APKFile` and storage reference metadata, with `schema_version`, package/version fields, hash, size, and storage location.
- `MANIFEST`: placeholder contract with package/version, empty permissions/components, and `parsing_status: NOT_IMPLEMENTED`.
- `PERMISSIONS`: empty placeholder contract for future permission extraction.
- `COMPONENTS`: empty placeholder contract for future Android component extraction.

`ManifestMetadataAdapter` defines the future manifest analyzer interface and can produce a placeholder `MANIFEST` normalized artifact if explicitly registered. It does not extract `AndroidManifest.xml`, download APK bytes, parse binary XML, run apktool, run jadx, or run Androguard.

The current analyzers are placeholders. Real APK parsing is still deferred to the next sprint, and MASVS/ATT&CK engines are still not executed.

## Celery and Redis
Celery moves analysis work out of the API request path. Django creates an `AnalysisJob`, updates the audit to `ANALYSIS_QUEUED`, enqueues `analyze_audit_placeholder`, and returns the job id plus Celery task id. A Celery worker consumes the task from Redis and updates status fields as the task runs.

Configure Celery with:

```env
REDIS_URL=redis://localhost:6379/0
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/0
CELERY_TASK_ALWAYS_EAGER=false
CELERY_TASK_EAGER_PROPAGATES=true
```

If `CELERY_BROKER_URL` is unset, it falls back to `REDIS_URL`. Tests set `CELERY_TASK_ALWAYS_EAGER=true`, so no real Redis worker or broker is required for pytest.

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

The test settings run Celery tasks eagerly in-process and mock MinIO/boto3 access, so tests do not require Redis or MinIO.

To run only the API tests:

```bash
pytest tests/test_api.py
```

## Environment Variables
Core variables are documented in `.env.example` and include:
- Django settings: `DJANGO_SECRET_KEY`, `DJANGO_DEBUG`, `DJANGO_ALLOWED_HOSTS`
- Database settings: `DATABASE_URL` or `POSTGRES_*`
- Redis/Celery settings: `REDIS_URL`, `CELERY_BROKER_URL`, `CELERY_RESULT_BACKEND`, `CELERY_TASK_ALWAYS_EAGER`, `CELERY_TASK_EAGER_PROPAGATES`
- MinIO settings: `MINIO_ENDPOINT`, `MINIO_ACCESS_KEY`, `MINIO_SECRET_KEY`, `MINIO_SECURE`, bucket names
- Upload settings: `MSAP_PRESIGNED_URL_EXPIRES_SECONDS`, `MSAP_MAX_APK_SIZE_BYTES`, `MSAP_VERIFY_UPLOAD_WITH_HEAD`
- Analyzer settings: `ANALYZER_RULES_PATH`, `ANALYZER_WORKDIR`, `ANALYZER_TIMEOUT_SECONDS`

## Scope Note
This is backend cloud foundation only. It establishes metadata models, rule validation, MinIO presigned upload initiation, upload confirmation, and the asynchronous worker boundary before real analysis and reporting workflows are implemented.
