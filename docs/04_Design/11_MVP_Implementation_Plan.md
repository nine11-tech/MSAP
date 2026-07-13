# MVP Implementation Plan - MSAP

## MVP objective
Construire le socle cloud-native de MSAP sans perdre le coeur cybersécurité: analyse statique Android, MASVS, ATT&CK Mobile prudent, preuves et reporting.

## MVP scope
- Backend foundation Django REST + PostgreSQL.
- Environment variable contract.
- MinIO integration et ObjectStorageReference.
- Redis/Celery queue et worker foundation.
- APK ingestion et stockage objet.
- YAML rule loader.
- Analyse statique minimale et normalization.
- MASVS + ATT&CK engines initiaux.
- Evidence + Risk engines.
- Rapport PDF/JSON stocke dans MinIO.
- Kubernetes manifests et Helm chart comme artefacts de livraison.
- Docker Compose uniquement pour developpement local.

## Delivery artifacts
Documentation, schema de donnees, API design, chart Helm, manifests Kubernetes, strategie MinIO, tests de base et scenario demo Kubernetes/K3s.

## Implementation order
1. Backend foundation Django REST + PostgreSQL.
2. Environment contract from [Environment Variables Contract](../07_Deployment/23_Environment_Variables_Contract.md).
3. `ObjectStorageReference` model from [ObjectStorageReference Schema](22_ObjectStorageReference_Schema.md).
4. MinIO integration for APK uploads, artifacts, evidence, reports and exports.
5. Redis/Celery worker foundation.
6. YAML rule loader for MASVS and ATT&CK seed rules.
7. Basic APK ingestion workflow and asynchronous task status.
8. First normalization, evidence, finding and JSON export flow.

## MVP freeze reference
The V1.0 scope is frozen in [Cloud-Native MVP Freeze](24_Cloud_Native_MVP_Freeze.md). Kimi AI, dynamic analysis, MobSF, Frida, iOS, malware sandboxing, guaranteed malware classification, advanced autoscaling, full GitOps and advanced observability remain out of V1.0.
