# MSAP Backend

This directory contains the backend foundation for MSAP. It includes Django settings, initial metadata models, YAML rule catalog validation and test scaffolding only.

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

## Environment Variables
Core variables are documented in `.env.example` and include:
- Django settings: `DJANGO_SECRET_KEY`, `DJANGO_DEBUG`, `DJANGO_ALLOWED_HOSTS`
- Database settings: `DATABASE_URL` or `POSTGRES_*`
- Redis settings: `REDIS_URL`
- MinIO settings: `MINIO_ENDPOINT`, `MINIO_ACCESS_KEY`, `MINIO_SECRET_KEY`, bucket names
- Analyzer settings: `ANALYZER_RULES_PATH`, `ANALYZER_WORKDIR`, `ANALYZER_TIMEOUT_SECONDS`

## Scope Note
This is backend cloud foundation only. It establishes metadata models and rule validation before object upload, asynchronous analysis and reporting workflows are implemented.

