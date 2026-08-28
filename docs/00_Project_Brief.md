# Project Brief - MSAP

## Product identity

MSAP is a cloud-native Mobile Security Assessment and Triage Platform for the
authorized review of Android APKs. “Cloud-native” describes the deployment and
storage architecture, not the product name.

## Objective

MSAP provides a traceable assessment workflow from APK ingestion to analyst
review:

- securely upload APKs to private object storage;
- run bounded asynchronous static analyzers;
- normalize evidence and apply deterministic security rules;
- assess OWASP MASVS-oriented coverage and risk;
- map suspicious signals cautiously to MITRE ATT&CK Mobile;
- perform approved dynamic checks in an isolated Android lab;
- generate evidence-first JSON and PDF reports.

MSAP supports analysis; it does not guarantee a malware/benign verdict.

## Implemented scope

- React/TypeScript/Vite analyst interface.
- Django REST API with session authentication, CSRF protection, and RBAC.
- PostgreSQL metadata and MinIO object storage.
- Redis/Celery jobs and bounded analyzer workspaces.
- Android manifest, DEX, resources, certificates, strings, and optional JADX
  source indexing.
- Versioned YAML MASVS and ATT&CK-oriented rule catalogs.
- Evidence, scoring, audit history, and JSON/PDF reporting.
- Local dynamic lab with a rootable emulator, ADB, Frida, mitmproxy, runtime CA
  overlay, and token-authenticated allowlisted Host Agent.
- Deterministic assessment planning and adaptive decisions, with optional
  backend-only OpenAI providers subject to redaction, approval, and hard budgets.
- Docker Compose development/demo and Kubernetes/Helm packaging.

## Deliberate boundaries

- Android APK only; no iOS pipeline.
- No guaranteed malware classification or unrestricted malware sandbox.
- No offensive operation against third-party systems.
- No arbitrary shell, filesystem, Docker, or unrestricted Frida access through
  the Host Agent or execution agent.
- No raw APK or unredacted secret sent to an external AI provider.
- Dynamic hardware remains an isolated operator-managed lab, not a generic CI
  runner.

## Target stack

- Frontend: React, TypeScript, Vite, nginx production image.
- Backend: Django REST Framework and Celery.
- Data: PostgreSQL, Redis, MinIO.
- Mobile tooling: Android SDK/ADB, Androguard, optional JADX, Frida, mitmproxy.
- Deployment: Docker Compose locally; Kubernetes with Helm as the target.
