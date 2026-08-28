# MVP Freeze - MSAP

> Historical note: this file records the original V1 foundation freeze. It is
> not the current implementation-status document. Later phases added the
> frontend, broader static analysis, PDF reporting, the isolated dynamic lab,
> Frida/mitmproxy integration, and bounded deterministic/optional OpenAI agent
> workflows. Use the root README and active architecture/runbooks for current
> behavior.

## Final Objective
MSAP V1.0 delivers a cloud-native APK security assessment foundation: Django API, PostgreSQL metadata, MinIO object storage, Redis/Celery analysis, one basic worker, YAML security rules, evidence-first findings and JSON reporting.

## In Scope
- Django backend foundation.
- PostgreSQL metadata models.
- MinIO integration for APK uploads, artifacts, evidence, reports and exports.
- Redis/Celery task queue.
- One basic worker.
- YAML rule loading.
- First OWASP MASVS rules.
- First MITRE ATT&CK Mobile indicators.
- Evidence model.
- JSON export.
- Initial Helm chart or Kubernetes manifests.
- Docker Compose for development only.

## Out of Scope
- Kimi AI implementation.
- Dynamic analysis.
- MobSF integration.
- Frida integration.
- iOS analysis.
- Malware sandbox.
- Guaranteed malware classification.
- Advanced autoscaling.
- Full GitOps.
- Advanced observability.

## First Implementation Order
1. Django REST and PostgreSQL foundation.
2. Environment variable loading.
3. `ObjectStorageReference` model.
4. MinIO upload and object reference flow.
5. Redis/Celery worker foundation.
6. YAML rule loader.
7. Basic APK ingestion and asynchronous status.
8. MASVS/ATT&CK seed rules.
9. Evidence and JSON export.
10. Initial Kubernetes or Helm packaging.

## Acceptance Criteria
- V1.0 can ingest an APK and store it in MinIO.
- PostgreSQL stores metadata and object references, not raw APK payloads.
- A Celery task processes the uploaded APK asynchronously.
- Initial MASVS findings and ATT&CK indicators can be produced from YAML rules.
- Evidence records link findings or indicators to source artifacts.
- JSON export is generated and stored through the object storage contract.
- Kubernetes or Helm packaging exists for the MVP runtime.
- External AI integration remained outside this original V1.0 freeze.
