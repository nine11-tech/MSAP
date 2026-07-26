# MSAP Backend

This directory contains the backend foundation for MSAP. It includes Django settings, initial metadata models, YAML rule catalog validation, MinIO upload metadata, Celery orchestration, constrained APK manifest metadata extraction, deterministic manifest rule execution, scoring, and JSON/PDF audit reporting.

The backend does not implement Kimi AI, full APK/code analysis, full MASVS/ATT&CK catalog execution, MobSF, Frida, dynamic analysis, iOS analysis, malware classification, or malware sandboxing.

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
The current API is intentionally simple and does not implement authentication, raw file proxy uploads through Django, full APK/code analysis, full MASVS/ATT&CK catalog execution, or AI assistance.

Writable metadata endpoints:
- `GET /api/health/`
- `GET|POST /api/projects/`
- `GET|PUT|PATCH|DELETE /api/projects/{id}/`
- `GET|POST /api/audits/`
- `GET|PUT|PATCH|DELETE /api/audits/{id}/`
- `POST /api/audits/{id}/apk-upload/initiate/`
- `POST /api/audits/{id}/analysis/start/`
- `GET /api/audits/{id}/analysis/status/`
- `GET /api/audits/{id}/report/json/`
- `GET /api/audits/{id}/report/pdf/`
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

Finding, indicator, evidence, score, report, raw-result, and normalized-artifact list endpoints accept `?audit=<audit_id>` for audit-scoped retrieval.

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
# Optional browser-visible signing endpoint; defaults to MINIO_ENDPOINT.
MINIO_PUBLIC_ENDPOINT=http://localhost:9000
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
Server-side `head_object` and download calls always use `MINIO_ENDPOINT`.
Presigned upload and download URLs use `MINIO_PUBLIC_ENDPOINT`, allowing the
Compose backend to access `http://minio:9000` while returning
`http://localhost:9000` URLs to the browser.

## MinIO Download-to-Temporary-File Provider

APK binaries remain in MinIO-compatible object storage so application workers
do not rely on permanent shared disks and PostgreSQL remains limited to metadata.
Manifest parsers still require a seekable local APK path, so `APKFileProvider`
first checks the optional development/test mirror and otherwise downloads a
confirmed object into a secure temporary directory. Set `MSAP_TEMP_DIR` to use a
dedicated worker scratch location; when it is empty, the operating system's
temporary directory is used.

Analyzers obtain the path through a scoped context manager:

```python
with file_provider.open_apk_local_copy(apk_file) as apk_path:
    metadata = manifest_adapter.parse(apk_path)
```

The downloaded filename retains an `.apk` suffix. When
`MSAP_VERIFY_DOWNLOADED_APK_SHA256=true`, the provider calculates SHA-256 and
checks every available expected digest from `APKFile` and its
`ObjectStorageReference`. A mismatch fails analysis before parsing, protecting
the metadata-to-object trust boundary. If neither record contains a digest,
there is no expected value to compare; upload policy should normally ensure one
is recorded.

The context manager removes its entire temporary directory on normal return,
checksum failure, parser failure, or another exception. A configured local
development mirror is not provider-owned and is therefore not deleted. MinIO
exceptions are converted to clean provider errors without logging credentials or
raw client error details.

Tests generate tiny ZIP fixtures from repository-owned XML and mock MinIO
downloads. They require no MinIO server, never persist downloaded APKs, and do
not add third-party or malware binaries. This provider only supplies bytes to
the manifest metadata analyzer: it does not execute MASVS or ATT&CK rules, create
findings or indicators, or calculate risk scores.

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
  "expires_in": 900,
  "required_headers": {
    "Content-Type": "application/vnd.android.package-archive"
  }
}
```

The client uploads the APK bytes directly to `upload_url` with every header in `required_headers`. The signed `Content-Type` value must match exactly. V1.0 accepts `.apk` files only; `.aab` and `.ipa` are rejected. This endpoint does not parse the APK or start analysis.

For browser uploads, CORS must allow the exact Vite origin, `PUT` and `HEAD`,
and the `Content-Type` header. On an S3-compatible deployment that implements
bucket CORS, MinIO Client can apply the policy in `docker/minio/cors.xml` with:

```bash
mc cors set local/msap-apk-uploads cors.xml
```

Community MinIO does not implement that per-bucket API; configure its
`MINIO_API_CORS_ALLOW_ORIGIN` setting with the exact frontend origins instead.

The configured `MINIO_PUBLIC_ENDPOINT` must be browser-reachable because the
backend embeds it in the presigned URL. The root Compose stack configures this
as `http://localhost:9000` and sets Community MinIO's cluster-wide CORS origin
allowlist to the two exact Vite development origins. Community MinIO does not
implement the S3 per-bucket CORS API; `docker/minio/cors.xml` records the
intended narrower policy for compatible S3 deployments. See
`../frontend/README.md` for manual and Compose workflows.

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
After an audit has at least one `APKFile`, start analysis explicitly:

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

The Celery task calls the internal `AnalysisOrchestrator` and runs the registered analyzers in deterministic order. It marks the audit and `AnalysisJob` as running, persists raw analyzer statuses and any normalized artifacts, evaluates the implemented MASVS and ATT&CK Mobile manifest rules, then marks the job completed. The manifest analyzer parses only when the file provider can supply a local APK path.

## Analysis Orchestration
The Celery analysis task delegates internal work to `AnalysisOrchestrator`. The orchestrator loads the audit, selects the latest linked `APKFile`, verifies its object storage reference, and asks `AnalyzerRegistry` for supported analyzers. The default order is `PlaceholderMetadataAnalyzer` followed by `ManifestMetadataAnalyzer`.

Every invoked analyzer produces a `RawAnalyzerResult`, including `SKIPPED` and `FAILED` analyzers. A skipped manifest analyzer does not fail the audit or job. `NormalizedArtifact` rows are created only when an analyzer result contains normalized artifacts.

`NormalizedArtifact` represents canonical data that rule evaluators can consume without depending on parser-specific output. The placeholder analyzer creates `APK_METADATA`; successful manifest parsing creates `MANIFEST`. Analyzer summaries contain counts and status, not raw XML.

After analyzer execution, the orchestrator runs the focused MASVS and ATT&CK evaluators against the latest `MANIFEST` artifact for the audit, then calculates risk, MASVS compliance, and ATT&CK triage summaries. Evaluator summaries, scoring summaries, and aggregate finding, indicator, and evidence creation counts are included in `AnalysisJob.result_summary`. The orchestrator does not run apktool, jadx, MobSF, Frida, unimplemented catalog rules, or report generation.

This prepares the future pipeline by separating:
- analyzer plugin execution into the `apps.analyzers` contract,
- raw analyzer output into `RawAnalyzerResult`,
- canonical downstream inputs into `NormalizedArtifact`,
- job and audit lifecycle management into the Celery task and orchestrator boundary.

## Analyzer Registry and Normalization Contracts
`AnalyzerRegistry` is the deterministic discovery layer for analysis components. It returns registered analyzer instances, filters them with each analyzer's `supports(context)` method, and exposes read-only analyzer metadata through `GET /api/analyzers/`. The default registry registers `PlaceholderMetadataAnalyzer` and `ManifestMetadataAnalyzer` in that order.

Analyzers are registered instead of hardcoded in the orchestrator so future APK metadata, manifest, permissions, components, certificate, string, resource, and code reference analyzers can be added without rewriting the orchestration loop. The registry intentionally avoids dynamic imports; analyzers are added explicitly and run in stable order.

`RawAnalyzerResult` stores the analyzer-specific raw summary for each analyzer run. `NormalizedArtifact` stores stable, canonical payloads that MASVS and ATT&CK evaluators consume without depending on individual analyzer output formats.

Normalized artifact schema helpers live in `apps.normalization.services.schemas`. Current contracts include:
- `APK_METADATA`: populated from existing `APKFile` and storage reference metadata, with `schema_version`, package/version fields, hash, size, and storage location.
- `MANIFEST`: package/version fields, SDK levels, permissions, components, application flags, and `parsing_status` with stable empty-list/null defaults.
- `PERMISSIONS`: empty placeholder contract for future permission extraction.
- `COMPONENTS`: empty placeholder contract for future Android component extraction.

## Manifest Metadata Analyzer

`AndroidManifest.xml` declares an Android application's identity and runtime-facing configuration. Package and version identifiers, SDK compatibility, requested permissions, application security flags, and registered activities, services, receivers, and providers all originate there. The normalized fields are canonical inputs for the focused assessment and triage rules described below; other manifest fields do not become findings or indicators automatically.

An APK is a ZIP archive, but its `AndroidManifest.xml` is normally compiled Android binary XML rather than plain text XML. `ManifestMetadataAdapter` reads only a bounded manifest member from the archive. It accepts tiny plain-XML development fixtures and uses Androguard's AXML parser for compiled manifests. Archive size, manifest size, ZIP entry count, encryption, malformed XML, and missing manifest conditions are handled without persisting raw XML.

`ManifestMetadataAnalyzer` implements the existing analyzer contract with name `manifest_metadata_analyzer` and version `0.1.0`. It opens a scoped local copy through the file-provider interface, delegates parsing to the adapter, updates `APKFile.package_name` and `APKFile.version_name` when present, and emits a normalized `MANIFEST` artifact with:

- package name, version name, and version code;
- minimum and target SDK values;
- requested permission names;
- activity, activity-alias, service, receiver, and provider names;
- nullable `debuggable`, `allow_backup`, and `uses_cleartext_traffic` flags;
- `parsing_status: PARSED`.

`APKFileProvider` uses `MSAP_LOCAL_APK_ROOT` only when `MSAP_ENVIRONMENT` is `development`, `test`, or `testing`. It resolves object-storage metadata beneath that root as either `<root>/<bucket>/<object_key>` or `<root>/<object_key>`, rejecting paths outside the configured root. If no mirror file exists, an uploaded or verified MinIO object is downloaded to a checksum-verified temporary `.apk` path and deleted when parsing ends. Pending, failed, deleted, or missing object references are recorded as `SKIPPED`; download, checksum, and parsing failures are recorded as `FAILED`. No manifest artifact is emitted for either outcome.

The manifest analyzer itself only parses and normalizes metadata. The orchestrator invokes the separate rule evaluators and scoring services after analyzer execution. The analysis pipeline does not decompile code, classify malware, or generate reports; reports are requested separately from the API.

## First Rule Execution Foundation

This is deterministic rule execution over the latest `MANIFEST` `NormalizedArtifact` for an audit. It does not use Kimi AI or any other AI model.

`apps.appsec_rules.services.masvs_evaluator` loads the validated MASVS YAML catalog and currently evaluates only:

- `MSAP-AND-001`: creates a finding when `application.debuggable` is `true`;
- `MSAP-AND-002`: creates a finding when `application.allow_backup` is `true`.

`apps.triage_rules.services.attck_evaluator` loads the validated ATT&CK Mobile triage catalog and currently evaluates only:

- `MSAP-MOB-001`: creates a triage indicator for `READ_SMS`, `RECEIVE_SMS`, or `SEND_SMS` permissions;
- `MSAP-MOB-002`: creates a triage indicator for an accessibility service permission, name, or metadata signal.

Matched results receive a linked `Evidence` row with the audit, finding or indicator, catalog detection type and source, a short normalized snippet, and `redacted=false`. Full manifest XML is never stored as evidence. Reruns reuse existing findings and indicators for the same audit and rule identifier, and do not duplicate identical evidence.

ATT&CK indicators are cautious triage signals only. They require analyst context and do not classify an APK as malware. The remaining 12 MASVS rules and 13 ATT&CK indicators are validated catalog entries but are not executed. Dynamic analysis, malware sandboxing, and Kimi AI remain unimplemented.

Run the complete test suite from this directory with:

```bash
.venv/bin/pytest
```

The evaluator tests create `NormalizedArtifact` rows directly and require no real APK parsing, MinIO service, Redis broker, or Celery worker.

## Scoring and Security Reports

The risk scoring service reads findings and suspicious indicators for an audit. `Critical`, `High`, `Medium`, and `Low` records contribute weights of 10, 7, 4, and 1. The weights are summed, multiplied by 10, and capped at 100. The resulting severity is `Low` through 30, `Medium` through 60, `High` through 80, and `Critical` above 80. Each run creates or updates the audit's `RiskScore`.

MASVS compliance considers only `MSAP-AND-001` and `MSAP-AND-002`. Each corresponding finding is a failed evaluated rule, and the stored `ComplianceScore` uses `((evaluated rules - failed rules) / evaluated rules) * 100` with `standard="MASVS"`.

The ATT&CK Mobile summary counts suspicious indicators and returns `Low` for none, `Medium` for one, and `High` for two or more. This is a triage level only. It is not a malware score and produces no malicious or benign verdict.

Generate the current JSON report with:

```http
GET /api/audits/{audit_id}/report/json/
```

Download the current PDF report with:

```http
GET /api/audits/{audit_id}/report/pdf/
```

Both formats are assembled on demand from persisted audit results. The JSON
response contains audit, project, latest APK metadata, scoring summaries,
findings, indicators, evidence, normalized artifact counts, a bounded
analysis-job summary, and explicit limitations. The professional A4 PDF adds a
cover, executive summary, scope/methodology, APK metadata, risk and compliance,
structured findings and indicators, bounded evidence snippets, limitations, and
a concise technical appendix. Raw manifest XML, storage keys, presigned URLs,
credentials, and unbounded strings are excluded.

ReportLab builds PDF bytes entirely in memory with `BytesIO`; no browser,
Cairo, external report service, temporary file, or writable root filesystem is
required. An idempotent `Report` row records each generated format, but report
bytes are not stored in PostgreSQL or MinIO. Report content is deterministic
application logic based on persisted MSAP data: there is no AI-generated
content. Static analysis observes no runtime behavior, and ATT&CK mappings are
investigative signals rather than a malware verdict. Tests run without real
MinIO or Redis:

```bash
.venv/bin/pytest
```

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

The test settings run Celery tasks eagerly in-process and mock MinIO/boto3 access, so tests do not require Redis or MinIO. Manifest tests assemble a tiny synthetic ZIP from a repository-owned XML fixture; no third-party APK or malware sample is used.

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
- Manifest settings: `MSAP_LOCAL_APK_ROOT`, `MSAP_MAX_MANIFEST_SIZE_BYTES`, `MSAP_MAX_APK_ZIP_ENTRIES`
- Analyzer settings: `ANALYZER_RULES_PATH`, `ANALYZER_WORKDIR`, `ANALYZER_TIMEOUT_SECONDS`
- PDF metadata: `MSAP_REPORT_AUTHOR`, `MSAP_REPORT_ORGANIZATION`, `MSAP_REPORT_CLASSIFICATION`, `MSAP_REPORT_VERSION`

## Scope Note
This is a constrained backend analysis increment. It establishes safe manifest metadata extraction, four deterministic assessment and triage detections, simple scoring, and on-demand JSON/PDF reporting behind the existing worker boundary. Broader rule execution and broader application analysis remain out of scope.
