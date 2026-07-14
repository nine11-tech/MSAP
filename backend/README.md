# MSAP Backend

This directory contains the backend foundation for MSAP. It includes Django settings, initial metadata models, YAML rule catalog validation, and the first DRF API layer for metadata records.

This sprint does not implement React, Kubernetes manifests, Helm charts, Kimi AI, MinIO upload flows, Celery task execution, full APK analysis, MobSF, Frida, dynamic analysis, iOS analysis or malware sandboxing.

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
The current API is intentionally simple and does not implement authentication, file upload, MinIO calls, APK parsing, Celery execution, or AI assistance.

Writable metadata endpoints:
- `GET /api/health/`
- `GET|POST /api/projects/`
- `GET|PUT|PATCH|DELETE /api/projects/{id}/`
- `GET|POST /api/audits/`
- `GET|PUT|PATCH|DELETE /api/audits/{id}/`
- `GET|POST /api/apk-files/`
- `GET|PUT|PATCH|DELETE /api/apk-files/{id}/`
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
- MinIO settings: `MINIO_ENDPOINT`, `MINIO_ACCESS_KEY`, `MINIO_SECRET_KEY`, bucket names
- Analyzer settings: `ANALYZER_RULES_PATH`, `ANALYZER_WORKDIR`, `ANALYZER_TIMEOUT_SECONDS`

## Scope Note
This is backend cloud foundation only. It establishes metadata models and rule validation before object upload, asynchronous analysis and reporting workflows are implemented.
