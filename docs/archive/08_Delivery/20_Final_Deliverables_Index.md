# Final Deliverables Index - MSAP

## Documentation deliverables
Cadrage cloud-native, SRS, traceability matrix, security methodology, evidence model, cloud architecture, Kubernetes deployment architecture, MinIO architecture, implementation boundaries, data flow, Kubernetes resource model, multi-tenant security model, ObjectStorageReference schema, Helm values contract, cloud-native MVP freeze, environment variables contract, testing strategy and acceptance criteria.

## Contract deliverables
- [Cloud-native implementation boundaries](../03_Architecture/17_Cloud_Native_Implementation_Boundaries.md).
- [ObjectStorageReference schema](../04_Design/22_ObjectStorageReference_Schema.md).
- [Helm values contract](../04_Design/23_Helm_Values_Contract.md).
- [Cloud-native MVP freeze](../04_Design/24_Cloud_Native_MVP_Freeze.md).
- [Environment variables contract](../07_Deployment/23_Environment_Variables_Contract.md).

## Deployment deliverables
- Kubernetes manifests plan.
- Helm chart strategy and values model.
- MinIO bucket strategy.
- PostgreSQL metadata/reference model.
- Redis/Celery worker strategy.
- Deployment guide for local K3s/kind, self-hosted Kubernetes and institutional clusters.
- Cloud DevSecOps strategy with Trivy, Helm lint and manifest validation.

## Demo deliverables
Kubernetes/K3s deployment, APK upload, MinIO object verification, worker analysis, MASVS/ATT&CK review, report generation and report download.

## Scope reminders
Docker Compose is development-only. MinIO is object storage, not application hosting. Kimi AI is optional post-analysis only. MSAP does not provide guaranteed malware classification.
