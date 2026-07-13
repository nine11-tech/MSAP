# Cahier des Charges - MSAP

## Identite
MSAP est une plateforme cloud-native d'evaluation de securite mobile et de triage d'APK basee sur OWASP MASVS, MITRE ATT&CK Mobile, MinIO et Kubernetes.

## Objectifs
- Fournir une plateforme de security engineering pour APK Android.
- Executer une analyse statique evidence-first.
- Produire findings MASVS, indicateurs ATT&CK Mobile prudents, scores, rapports et exports.
- Stocker APK, artefacts, preuves, rapports et exports dans MinIO.
- Stocker metadonnees et references objet dans PostgreSQL.
- Executer les analyses via Redis/Celery workers ou Kubernetes Jobs.
- Deployer sur Kubernetes avec Helm.

## Fonctions attendues
| ID | Fonction | Priorite |
|---|---|---|
| F-01 | Gestion utilisateurs, organisations, projets et audits | Haute |
| F-02 | Upload APK securise | Haute |
| F-03 | Stockage APK dans MinIO | Haute |
| F-04 | Analyse statique Android asynchrone | Haute |
| F-05 | Normalisation des artefacts | Haute |
| F-06 | Mapping OWASP MASVS | Haute |
| F-07 | Triage MITRE ATT&CK Mobile prudent | Haute |
| F-08 | Evidence model avec references objet | Haute |
| F-09 | Rapport PDF et export JSON dans MinIO | Haute |
| F-10 | Deploiement Kubernetes/Helm | Haute |

## Contraintes techniques
Kubernetes est la cible de deploiement. Docker Compose est uniquement un mode de developpement local. MinIO est un stockage objet, PostgreSQL la base de metadonnees, Redis/Celery la file d'analyse asynchrone.

## Hors perimetre
MobSF obligatoire, Frida, analyse dynamique, malware sandbox, iOS/IPA, exploitation offensive, verdict garanti malware/benin, AI traitant des APK bruts.

## Securite
RBAC, isolation organisation/projet/audit, Ingress TLS, Kubernetes Secrets, buckets MinIO prives, redaction des secrets, audit logs, retention des objets et validation analyste.
