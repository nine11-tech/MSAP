# Cloud-Native MVP Freeze - MSAP

## Final MVP Objective
MSAP V1.0 delivers a cloud-native APK security assessment and triage foundation: Django API, PostgreSQL metadata, MinIO object storage, Redis/Celery asynchronous analysis, one basic worker, YAML security rules, evidence-first findings and JSON reporting. The MVP validates the platform architecture before adding advanced analysis and optional AI capabilities.

## In Scope for V1.0
- Django backend foundation.
- PostgreSQL metadata models.
- MinIO integration for APK uploads and reports.
- Redis/Celery task queue.
- One basic worker.
- YAML rule loading.
- First OWASP MASVS rules.
- First MITRE ATT&CK Mobile indicators.
- Evidence model.
- JSON report/export.
- Initial Helm chart or Kubernetes manifests.
- Docker Compose for development only.

## Out of Scope for V1.0
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

## Cloud-Native Components Required for MVP
- Django REST API for audits, APK metadata, findings, evidence and exports.
- PostgreSQL for metadata and object references.
- MinIO for APKs, artifacts, evidence, reports and exports.
- Redis as Celery broker.
- Celery worker for asynchronous APK analysis.
- YAML rule files for MASVS and ATT&CK seed rules.
- Kubernetes-ready runtime configuration.
- Helm-oriented configuration contract.

## Components Deferred to V1.1/V2
- Optional Kimi AI assistant using redacted post-analysis context.
- Dynamic analysis adapters.
- MobSF and Frida adapters.
- iOS support.
- Sandbox detonation workflows.
- Advanced autoscaling and queue-based scaling.
- Full GitOps delivery flow.
- Prometheus/Grafana dashboards and distributed tracing.

## First Backend Implementation Scope
- Create the Django project and API foundation.
- Implement authentication-ready project/audit boundaries.
- Implement metadata models for audits, APK files, object references, findings, evidence and reports.
- Expose minimal endpoints for APK upload, audit status and JSON export.
- Enforce that raw APK bytes are not stored in PostgreSQL.

## First Storage Implementation Scope
- Implement `ObjectStorageReference`.
- Configure MinIO client access through environment variables.
- Store APK uploads in `msap-apk-uploads`.
- Store JSON exports in `msap-exports`.
- Store generated report objects in `msap-reports` when PDF support is added.
- Validate hash, size and content type after upload.

## First Worker Implementation Scope
- Configure Redis/Celery.
- Create one basic worker queue.
- Load YAML MASVS and ATT&CK rules.
- Extract minimal APK metadata through a safe adapter boundary.
- Produce raw analyzer result, normalized artifact records, findings and evidence.
- Fail closed with auditable task status when analysis cannot complete.

## First Kubernetes/Helm Implementation Scope
- Start with the Helm values contract and environment variable contract.
- Add initial chart or manifests only after backend, storage and worker contracts are implemented.
- Include backend, worker, Redis, PostgreSQL and MinIO deployment configuration.
- Keep Docker Compose as development-only.
- Use Secrets for sensitive values and ConfigMaps for non-secret settings.

## Acceptance Criteria
- V1.0 can ingest an APK and store it in MinIO.
- PostgreSQL stores metadata and object references, not raw APK payloads.
- A Celery task processes the uploaded APK asynchronously.
- Initial MASVS findings and ATT&CK indicators can be produced from YAML rules.
- Evidence records link findings or indicators to source artifacts.
- JSON export is generated and stored through the object storage contract.
- Kubernetes or Helm packaging exists for the MVP runtime.
- Docker Compose remains limited to local development.
- Kimi AI remains disabled, optional and outside V1.0 implementation.
- Documentation clearly states that MSAP does not provide guaranteed malware classification.

## Risks and Mitigations
| Risk | Mitigation |
|---|---|
| Large APKs overload API pods | Stream uploads to MinIO and enforce size limits. |
| PostgreSQL grows with binary data | Store only metadata and `ObjectStorageReference` rows. |
| Analyzer tools execute on untrusted input | Run workers with least privilege, timeouts and constrained filesystem access. |
| ATT&CK mapping is misread as malware verdict | Use cautious language and evidence-first triage status. |
| Object references become orphaned | Add cleanup jobs and consistency checks between PostgreSQL and MinIO. |
| Secrets leak through logs or values | Store secrets in Kubernetes Secrets and redact logs. |
| Scope expands before MVP is stable | Keep AI, dynamic analysis, MobSF, Frida, iOS and advanced observability deferred. |
