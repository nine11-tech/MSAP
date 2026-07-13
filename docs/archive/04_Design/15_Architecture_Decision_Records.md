# Architecture Decision Records - MSAP

## ADR-001: Evidence-first static analysis core
**Status**: Accepted

MSAP garde l'analyse statique Android comme coeur fonctionnel. Chaque finding MASVS ou indicateur ATT&CK Mobile doit etre relie a une preuve technique sourcee.

## ADR-002: OWASP MASVS as AppSec assessment standard
**Status**: Accepted

OWASP MASVS structure les constats AppSec et les recommandations. Le scoring de conformite reste indicatif et auditable.

## ADR-003: MITRE ATT&CK Mobile as cautious triage mapping
**Status**: Accepted

MITRE ATT&CK Mobile sert a mapper des indicateurs statiques suspects. Il ne produit pas de verdict malware/benin garanti.

## ADR-004: PostgreSQL metadata database
**Status**: Accepted

PostgreSQL stocke utilisateurs, organisations, projets, audits, statuts, references MinIO, resultats normalises, findings, indicateurs, preuves, scores et rapports.

## ADR-005: Analyzer adapters remain modular
**Status**: Accepted

APKTool, JADX, Androguard et regles custom restent des adaptateurs remplaçables. MobSF, Frida et analyse dynamique restent des plugins futurs optionnels.

## ADR-006: AI optional post-analysis only
**Status**: Accepted

Kimi AI est optionnel, desactive par defaut et limite a un contexte post-analyse redige. Il ne traite pas d'APK brut, ne remplace pas les regles deterministes et ne modifie pas les scores.

## ADR-007: Multi-tenant isolation
**Status**: Accepted

Les donnees sont isolees par organisation, projet et audit. Les acces API et objets MinIO sont controles par RBAC, prefixes objet et audit logs.

## ADR-008: Ingress HTTPS and Kubernetes Secrets
**Status**: Accepted

Les acces utilisateurs passent par Ingress HTTPS. Les credentials PostgreSQL, MinIO, Django, Redis et AI optionnelle sont fournis via Kubernetes Secrets.

## ADR-009: Observability optional for MVP
**Status**: Accepted

Prometheus/Grafana sont optionnels pour le MVP, mais les metriques API, workers, queue, Jobs et stockage doivent rester compatibles avec une integration future.

## ADR-010: Cloud-native Kubernetes deployment
**Status**: Accepted

MSAP adopte Kubernetes comme cible de deploiement afin de supporter Ingress HTTPS, Secrets, Services, Deployments, Jobs, NetworkPolicies, probes et scaling des workers. Docker Compose est conserve uniquement pour le developpement local.

## ADR-011: MinIO object storage for APKs and reports
**Status**: Accepted

Les APK, artefacts, preuves volumineuses, rapports et exports sont stockes dans MinIO. PostgreSQL conserve les metadonnees et references objet. MinIO est un stockage objet, pas un hebergeur applicatif.

## ADR-012: Redis/Celery asynchronous analysis workers
**Status**: Accepted

Les analyses APK longues sont executees hors requete HTTP via Redis/Celery workers ou Kubernetes Jobs. Les jobs disposent de statuts, retries bornes et traces d'erreur.

## ADR-013: Helm chart packaging
**Status**: Accepted

Le packaging cible est un chart Helm avec values par environnement, templates Kubernetes, secrets references, ressources, probes et rollback.

## ADR-014: Docker Compose only for local development
**Status**: Accepted

Docker Compose n'est plus le mode principal de deploiement. Il sert au developpement local, aux tests rapides et a l'integration de base avant validation Kubernetes.
