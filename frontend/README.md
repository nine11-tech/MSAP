# MSAP Frontend

Minimal React and TypeScript dashboard for the MSAP backend MVP. It supports project and audit creation, APK upload-contract initiation, manual upload confirmation, analysis controls, result review, scoring, and on-demand JSON reports.

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

## Production build check

```bash
npm run build
```

The generated `dist/` directory and `node_modules/` are ignored by Git.

## Manual verification

1. Start the Django backend, Redis/Celery if required, and the Vite frontend.
2. Open **Projects** and create a project with a name and description.
3. Open the project and create an audit.
4. Open the audit, enter APK filename, content type, size, and optional SHA-256, then select **Initiate upload**.
5. Review the returned MinIO bucket, object key, and presigned URL.
6. Upload the APK to the presigned URL externally if MinIO and CORS are configured, then use **Confirm upload metadata**.
7. Select **Start analysis**, then use **Refresh status and results**.
8. Review APK metadata, findings, ATT&CK indicators, evidence, risk, and MASVS compliance.
9. Open **View JSON report** and review the structured sections or formatted raw response.

## Known limitations

- Browser PUT of APK bytes to the MinIO presigned URL is deferred. The UI displays the contract and provides manual backend confirmation only.
- Analysis status refresh is manual; there is no polling or live task stream.
- The backend result list endpoints do not currently filter by audit, so the MVP client retrieves each list and filters it locally.
- Authentication and role-based access control are not implemented.
- There is no PDF report, dynamic analysis, iOS support, Kimi AI, malware sandbox, or malware classification.
- ATT&CK Mobile indicators are triage signals, not malware verdicts.

No frontend test framework was added in this sprint. `npm run build` provides TypeScript and production-bundle verification, followed by the manual workflow above.
