# Test Strategy - MSAP Cloud

## Test scope
Tester le coeur cybersécurité et la plateforme cloud-native: ingestion APK, MinIO, PostgreSQL references, Redis/Celery workers, MASVS, ATT&CK Mobile, evidence, reporting, Kubernetes et Helm.

## Test categories
- Unit tests: engines, normalization, risk scoring, storage reference validation.
- API tests: auth, RBAC, upload, job status, report download.
- MinIO storage tests: bucket creation, object write/read, metadata consistency, lifecycle cleanup.
- Worker tests: queue processing, retries, failure states, artifact persistence.
- Kubernetes deployment tests: pods ready, Ingress, Secrets refs, Services, Jobs, probes.
- Helm tests: `helm lint`, `helm template`, install/upgrade/rollback on kind/K3s.
- Security tests: object access authorization, URL expiry, redaction, no secrets in logs.

## Constraints
No tests should imply guaranteed malware classification. Optional Kimi AI tests use redacted post-analysis context only.
