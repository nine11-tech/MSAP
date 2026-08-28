# Testing - MSAP

## Test layers

- Django unit, service, model, permission, API, report, scoring, redaction, Host
  Agent, and orchestration tests under `backend/tests/`.
- Rule-schema and migration-drift validation through Django management commands.
- Frontend TypeScript/production build and Playwright browser tests.
- Compose configuration and service-health checks.
- Helm lint/template checks for Kubernetes packaging.
- Hardware-dependent dynamic-lab preflight and Frida/mitmproxy/TLS smoke tests.

## Standard repository checks

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

Run the subset proportional to a change during development and the complete
available set before a release. Do not describe a skipped check as passing.

## Dynamic-lab acceptance

Dynamic checks run only on the isolated authorized lab, never a generic shared
runner:

```bash
scripts/dynamic-lab/restore-instrumented-snapshot.sh
scripts/dynamic-lab/lab-health.sh
```

Acceptance requires the expected API/ABI/build type, root ADB, SELinux
`Enforcing`, proxy off at rest, matching Frida versions, no unauthorized package,
no permanent MSAP CA, and Frida stopped after cleanup.

## Security regressions

- Raw APK bytes are not stored in PostgreSQL.
- Tenant/project/audit authorization prevents cross-scope access.
- Credentials, provider responses, and unredacted evidence are absent from logs
  and browser payloads.
- MinIO buckets remain private and presigned access is bounded.
- Archive/path/size/count/timeout limits hold for untrusted inputs.
- Optional AI components cannot bypass approval, capability, call, time,
  artifact, redaction, or evidence-authority boundaries.
- Host Agent endpoints require the shared token and expose only allowlisted
  operations.
