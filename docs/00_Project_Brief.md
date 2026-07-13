# Project Brief - MSAP

## Product Identity
MSAP is a cloud-native Mobile Security Assessment and Triage Platform for authorized Android APK review.

The application name is **MSAP**. "Cloud-native" describes the target architecture, not the product name.

## Objective
MSAP V1.0 provides a minimal but usable foundation for APK security assessment:
- Upload APKs.
- Store APKs and generated objects in MinIO.
- Store metadata and object references in PostgreSQL.
- Process analysis asynchronously with Redis and Celery.
- Evaluate initial OWASP MASVS rules.
- Map suspicious indicators cautiously to MITRE ATT&CK Mobile.
- Produce evidence-first findings and JSON exports.

## Positioning
MSAP supports application security review and analyst triage. It does not provide a guaranteed malware or benign verdict.

## V1.0 Scope
- Android APK static analysis only.
- Django REST API.
- PostgreSQL metadata.
- MinIO object storage.
- Redis/Celery worker queue.
- YAML rule loading.
- Evidence records.
- JSON report/export.
- Kubernetes-ready configuration.
- Docker Compose for local development only.

## Out of Scope for V1.0
- Kimi AI implementation.
- Dynamic analysis.
- MobSF integration.
- Frida integration.
- iOS analysis.
- Malware sandboxing.
- Guaranteed malware classification.
- Advanced autoscaling.
- Full GitOps.
- Advanced observability.

## Target Stack
- Frontend: React.
- Backend: Django REST Framework.
- Database: PostgreSQL.
- Queue: Redis and Celery.
- Object storage: MinIO.
- Deployment: Kubernetes and Helm.
- Local development: Docker Compose only.

