# MSAP Frontend

Professional React and TypeScript assessment workspace for MSAP. It provides
secure session login, role-aware navigation, live component status, project and
audit workflows, direct browser-to-MinIO upload, findings and ATT&CK triage,
coverage, scoring, and JSON/PDF reports.

## Requirements

- Node.js 22 or another version supported by Vite 8
- npm
- The MSAP Django backend running separately
- Redis and a Celery worker when backend eager-task mode is disabled

## Install and run

```bash
cd frontend
cp .env.example .env
npm install
npm run dev
```

Open `http://127.0.0.1:5173/`.

The frontend uses:

```env
VITE_API_BASE_URL=http://127.0.0.1:8000/api
```

Restart the Vite development server after changing environment variables.

Every API fetch uses `credentials: "include"`. The client initializes CSRF and
sends `X-CSRFToken` on unsafe requests. It stores neither authentication tokens
nor session identifiers in `localStorage` or `sessionStorage`; a 401 expires the
in-memory user state and returns to login.

## Run with the full development stack

From the repository root:

```bash
cp .env.compose.example .env
docker compose up --build
```

This starts the frontend at `http://localhost:5173` and provisions the backend,
worker, PostgreSQL, Redis, MinIO, required buckets, and APK upload CORS policy.
It is a development/demo environment only; Kubernetes remains the target
deployment platform.

## Run the backend

In another shell:

```bash
cd backend
source .venv/bin/activate
python manage.py migrate
python manage.py runserver 127.0.0.1:8000
```

When `CELERY_TASK_ALWAYS_EAGER=false`, start Redis and a Celery worker separately:

```bash
cd backend
source .venv/bin/activate
celery -A msap worker -l info
```

The backend allows the default Vite origins. Override `DJANGO_CORS_ALLOWED_ORIGINS` when using a different frontend origin.

## MinIO browser CORS

The browser uploads APK bytes directly to the presigned MinIO URL, so CORS must
allow `PUT` requests from the Vite origin and accept the signed `Content-Type`
header. The repository's controlled policy is:

```xml
<CORSConfiguration>
  <CORSRule>
    <AllowedOrigin>http://127.0.0.1:5173</AllowedOrigin>
    <AllowedOrigin>http://localhost:5173</AllowedOrigin>
    <AllowedMethod>PUT</AllowedMethod>
    <AllowedMethod>HEAD</AllowedMethod>
    <AllowedHeader>Content-Type</AllowedHeader>
    <AllowedHeader>x-amz-*</AllowedHeader>
    <ExposeHeader>ETag</ExposeHeader>
    <MaxAgeSeconds>3600</MaxAgeSeconds>
  </CORSRule>
</CORSConfiguration>
```

On an S3-compatible deployment that implements bucket CORS, apply it with a
configured MinIO Client alias:

```bash
mc cors set local/msap-apk-uploads cors.xml
```

Replace `local` and the bucket name for your environment. It configures CORS
only; the presigned URL still authorizes each upload. Community MinIO does not
implement this per-bucket API, so use `MINIO_API_CORS_ALLOW_ORIGIN` with exact
origins as the root Compose stack does.

`MINIO_PUBLIC_ENDPOINT` must be reachable from the user's browser because it is
embedded in the presigned URL. The Compose backend uses
`MINIO_ENDPOINT=http://minio:9000` internally and
`MINIO_PUBLIC_ENDPOINT=http://localhost:9000` for browser-facing signatures.
Community MinIO does not implement the S3 per-bucket CORS API, so Compose sets
its cluster-wide origin allowlist to exactly `http://localhost:5173` and
`http://127.0.0.1:5173`; it does not use a wildcard. The `minio-init` container
creates all required buckets without making them anonymous.

## Production build check

```bash
npm run build
```

The generated `dist/` directory and `node_modules/` are ignored by Git.

## Manual verification

1. Start the Django backend, Redis/Celery if required, and the Vite frontend.
2. Sign in with an administrator, analyst, or viewer account.
3. Confirm the architecture bar polls every five seconds while visible and
   supports manual refresh.
4. Open **Projects** and create a project with a name and description.
5. Open the project and create an audit.
6. Ensure the MinIO APK bucket has a CORS rule for the exact frontend origin.
7. Open the audit, choose an `.apk` file, then select **Upload and confirm APK**.
8. Observe the upload states, start analysis, and follow analyzer progress.
9. Review findings, ATT&CK triage, evidence, rule coverage, and scores.
10. Download and inspect the JSON and PDF reports.
11. Sign out, then verify viewer and analyst restrictions with role-specific users.

The PDF request is received as a browser `Blob`. The frontend creates a
short-lived object URL, triggers the attachment download, and revokes the URL.
The JSON report view remains available.

## Known limitations

- Native Fetch does not expose portable upload progress events, so the UI shows upload phases rather than a percentage.
- Browser SHA-256 calculation is deferred; server-side download verification still uses a digest when one is available.
- When running services manually, MinIO buckets and CORS must still be configured
  separately; the root Compose workflow automates both.
- A viewer cannot upload, start analysis, modify metadata, or access administration.
- Component status is bounded near-real-time polling, not streaming telemetry.
- Reports keep persisted evidence and analyst-visible provenance; optional AI
  explanations are explicitly labelled and never replace deterministic results.
- The Dynamic Lab and bounded assessment workflows require the separate local
  Host Agent/emulator setup. There is no iOS pipeline, unrestricted malware
  sandbox, or guaranteed malware classification.
- ATT&CK Mobile indicators are triage signals, not malware verdicts.

Playwright browser tests live under `frontend/e2e`; TypeScript/build checks
and the relevant browser workflow should be run for frontend changes.
