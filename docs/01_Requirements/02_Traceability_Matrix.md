# Matrice de Tracabilite - MSAP

| ID | Requirement | Design/Architecture | Validation |
|---|---|---|---|
| REQ-APK-001 | Upload APK securise | API Design, Cloud Data Flow | Test upload + hash |
| REQ-MINIO-001 | APK stocke dans MinIO | MinIO Architecture | Objet dans `msap-apk-uploads` |
| REQ-MINIO-002 | Artefacts/rapports/exports en object storage | Object Storage Architecture | Verification buckets |
| REQ-PG-001 | Metadonnees et references objet en PostgreSQL | Data Model | Tests ORM/API |
| REQ-REDIS-001 | Analyse asynchrone via Redis/Celery | Analysis Pipeline | Job status + worker test |
| REQ-WORKER-001 | Workers scalables ou Kubernetes Jobs | Kubernetes Deployment Architecture | Test worker/job |
| REQ-MASVS-001 | Findings mappes OWASP MASVS | Security Methodology | Tests de regles |
| REQ-ATTCK-001 | Triage MITRE ATT&CK Mobile prudent | ATT&CK Methodology | Tests indicateurs + wording |
| REQ-EVID-001 | Evidence-first audit model | Evidence Model | Trace audit -> preuve -> rapport |
| REQ-K8S-001 | Kubernetes cible de deploiement | Kubernetes Deployment Strategy | kind/K3s install |
| REQ-HELM-001 | Packaging Helm | Helm Chart Strategy | `helm lint`, install, rollback |
| REQ-SEC-001 | Secrets et TLS | Kubernetes Resource Model | Secret refs + Ingress TLS |
| REQ-MULTI-001 | Isolation multi-user/multi-project | Multi-Tenant Security Model | Tests autorisation |
| REQ-MON-001 | Monitoring optionnel | Cloud DevSecOps Strategy | Prometheus/Grafana optionnels |
| REQ-AI-001 | Kimi AI optionnel post-analyse | AI docs + Cloud Data Flow | Redaction + validation analyste |
