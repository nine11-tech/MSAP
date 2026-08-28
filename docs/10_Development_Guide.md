# Development Guide - MSAP

This document describes the implemented repository. Earlier build-order plans
under `docs/archive/` are historical context, not current instructions.

## Repository layout

| Path | Purpose |
| --- | --- |
| `backend/` | Django API, Celery tasks, analysis engines, reports, Host Agent |
| `frontend/` | React/TypeScript/Vite analyst interface and Playwright tests |
| `rules/` | Versioned deterministic MASVS and ATT&CK-oriented rule data |
| `agent_runtime/` | Optional ephemeral bounded execution-agent image |
| `scripts/demo/` | Local platform/demo lifecycle helpers |
| `scripts/dynamic-lab/` | Android lab bootstrap, restore, validation, and cleanup |
| `helm/msap/` | Kubernetes packaging |
| `docs/` | Active technical and operational documentation |

## Prerequisites

- Python 3.12 with `venv`
- Node.js 22 and npm
- Docker with Compose v2
- Git
- Helm 3 for chart validation
- Windows/WSL2 and Android SDK only for dynamic-lab work

## Initial setup

```bash
python3 -m venv backend/.venv
backend/.venv/bin/python -m pip install -r backend/requirements.txt
npm ci --prefix frontend
cp .env.compose.example .env
```

Replace development placeholders in `.env` when the services are reachable
outside the local machine. Keep `.env`, APKs, generated reports, evidence, and
runtime files untracked.

For the complete Android toolchain and Host Agent setup, follow
[21_Workstation_Recovery_Guide.md](21_Workstation_Recovery_Guide.md).

## Run the application

Containerized development/demo:

```bash
docker compose up --build
```

The managed direct-WSL demo (after local Python/npm and dynamic-lab setup):

```bash
scripts/demo/start-local-mvp-demo.sh up
scripts/demo/start-local-mvp-demo.sh status
scripts/demo/start-local-mvp-demo.sh down
```

## Validation commands

Run checks relevant to the files changed:

```bash
git diff --check
scripts/security/scan-secrets.sh

cd backend
.venv/bin/python manage.py check
.venv/bin/python manage.py validate_rules
.venv/bin/python manage.py makemigrations --check --dry-run
.venv/bin/pytest -q

cd ../frontend
npm run build

cd ..
docker compose config
helm lint --strict helm/msap
```

Dynamic tests require the dedicated local emulator and are intentionally not
part of a generic shared CI runner. Start from a restored snapshot and run:

```bash
scripts/dynamic-lab/lab-health.sh
```

## Implementation boundaries

- Treat every APK, archive entry, manifest value, DEX string, source document,
  log line, proxy flow, screenshot, and instrumentation message as untrusted.
- Enforce size, count, timeout, path, and output limits before expensive work.
- Store large objects in MinIO and keep bounded metadata/references in the
  relational database.
- Preserve tenant/project/audit authorization at every API and object boundary.
- Keep deterministic evidence as the source of truth. Optional AI components
  may plan or explain within their contracts but cannot create authoritative
  evidence or bypass approval.
- Keep the Host Agent allowlisted and token-authenticated. Do not add arbitrary
  shell, filesystem, Docker, environment, or unrestricted Frida execution.
- Never put backend credentials in frontend variables; `VITE_` values are
  compiled into browser-delivered code.
- Do not add real APKs, credentials, generated CA material, snapshots, or client
  evidence to fixtures or documentation.

## Schema and rule changes

Django model changes require a migration and a dry-run consistency check.
Rule changes must remain compatible with `docs/06_Rules_Schema.md`, pass
`manage.py validate_rules`, and retain deterministic IDs and evidence mapping.
Scoring or MASVS coverage changes must update the methodology documentation and
their regression tests in the same change.

## Documentation rule

Update operational documentation with the implementation. Commands in the
README and active runbooks must be runnable from the repository root and must
not depend on personal usernames, absolute clone locations, private helper
scripts, or machine-specific credentials.
