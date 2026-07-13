# MSAP

Cloud-Native Mobile Security Assessment & Triage Platform

**Positionnement**: Plateforme cloud-native d'evaluation de securite mobile et de triage d'APK basee sur OWASP MASVS, MITRE ATT&CK Mobile, MinIO et Kubernetes.

## Executive Summary
MSAP est un projet d'ingenierie cybersécurité visant a fournir une plateforme cloud-native, auto-hebergeable et open-source pour l'audit applicatif mobile, le triage d'APK et la production de preuves techniques. Le coeur fonctionnel reste l'analyse statique Android, l'evaluation OWASP MASVS, le triage prudent MITRE ATT&CK Mobile, le scoring et le reporting.

MSAP ne fournit pas de verdict garanti malware/benin. Les indicateurs ATT&CK Mobile soutiennent une revue analyste evidence-first.

## Architecture cible
```mermaid
flowchart LR
    Auditor[Auditeur] --> ING[Ingress Controller + TLS]
    ING --> FE[React Frontend]
    FE --> API[Django REST API]
    API --> ORCH[Audit Orchestrator]
    ORCH --> REDIS[Redis Queue]
    REDIS --> WORKERS[Analyzer Workers / Kubernetes Jobs]
    WORKERS --> NORM[Normalization Layer]
    NORM --> MASVS[MASVS Engine]
    NORM --> ATTCK[ATT&CK Triage Engine]
    MASVS --> EVID[Evidence Engine]
    ATTCK --> EVID
    EVID --> RISK[Risk Engine]
    API --> PG[(PostgreSQL Metadata)]
    RISK --> PG
    EVID --> PG
    API --> MINIO[(MinIO Object Storage)]
    WORKERS --> MINIO
    RISK --> REPORT[Report Generator]
    REPORT --> MINIO
    EVID -. redacted post-analysis only .-> KIMI[Optional Kimi AI Assistant]
```


## Deploiement
Kubernetes est la plateforme cible de deploiement: namespace `msap`, Ingress HTTPS, Secrets, ConfigMaps, Services, Deployments, workers, Jobs, PVC, NetworkPolicies et packaging Helm. Docker Compose est conserve uniquement pour le developpement local et les tests rapides.

## Perimetre securite
- Android APK uniquement pour le MVP.
- Analyse statique comme coeur fonctionnel.
- OWASP MASVS comme standard d'evaluation AppSec.
- MITRE ATT&CK Mobile comme mapping prudent de triage.
- Evidence-first audit model.
- Pas d'exploitation offensive contre des systemes tiers.
- Pas de classification malware garantie.
- MobSF, Frida et analyse dynamique restent des plugins futurs optionnels.
- Kimi AI reste optionnel, post-analyse, apres redaction, sans acces aux APK bruts.

## Active documentation
The active implementation baseline is intentionally small:

- [Project brief](docs/00_Project_Brief.md)
- [Requirements](docs/01_Requirements.md)
- [Security methodology](docs/02_Methodology.md)
- [Architecture](docs/03_Architecture.md)
- [Data and storage model](docs/04_Data_Model.md)
- [API contract](docs/05_API_Contract.md)
- [Rules schema](docs/06_Rules_Schema.md)
- [MVP freeze](docs/07_MVP_Freeze.md)
- [Environment variables](docs/08_Environment_Variables.md)
- [Helm values contract](docs/09_Helm_Values.md)
- [Development guide](docs/10_Development_Guide.md)
- [Testing](docs/11_Testing.md)

Earlier detailed planning and diagram documents are preserved under [docs/archive](docs/archive/README.md) for reference only.

## Stack technique prevue
Frontend React, Backend Django REST Framework, PostgreSQL, Redis/Celery, workers scalables ou Kubernetes Jobs, MinIO object storage, Kubernetes + Helm. Docker Compose est uniquement un mode de developpement local. Options: Argo CD, Prometheus/Grafana, Trivy, Kimi AI post-analysis assistant.

## Roadmap 8 semaines
| Semaine | Objectif |
|---|---|
| S1 | Cadrage cloud-native & exigences |
| S2 | Architecture Kubernetes + MinIO + design |
| S3 | Backend foundation + PostgreSQL + MinIO integration |
| S4 | Queue + workers + APK ingestion |
| S5 | Analyse statique + normalization |
| S6 | MASVS + ATT&CK engines + evidence |
| S7 | Dashboard + reporting + object exports |
| S8 | Kubernetes deployment + tests + delivery |

## Authorized-Use Disclaimer
MSAP est une plateforme academique et institutionnelle d'audit cybersécurité. Elle doit etre utilisee uniquement pour analyser des APK avec autorisation explicite. Les resultats de triage ne constituent pas une classification definitive malware/benin et doivent etre interpretes par un analyste.
