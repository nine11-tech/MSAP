# Software Requirements Specification - MSAP Cloud

## Scope
MSAP Cloud est une plateforme cloud-native pour l'analyse statique Android, l'evaluation OWASP MASVS, le triage MITRE ATT&CK Mobile, la gestion des preuves et le reporting. Kubernetes est la cible de deploiement; Docker Compose sert uniquement au developpement local.

## Functional requirements
- FR-001: creer organisations, projets et audits.
- FR-002: uploader un APK via backend-medie ou URL pre-signee controlee.
- FR-003: stocker l'APK dans MinIO et enregistrer sa reference dans PostgreSQL.
- FR-004: calculer SHA-256, taille et metadonnees de fichier.
- FR-005: placer les analyses dans une queue Redis/Celery.
- FR-006: executer les analyseurs via workers scalables ou Kubernetes Jobs.
- FR-007: extraire manifeste, permissions, composants, signatures, ressources, chaines, URLs, domaines, IPs et secrets potentiels.
- FR-008: normaliser les resultats et stocker les artefacts dans MinIO.
- FR-009: mapper les findings vers OWASP MASVS.
- FR-010: mapper prudemment les indicateurs vers MITRE ATT&CK Mobile sans verdict malware garanti.
- FR-011: maintenir une chaine de preuve evidence-first.
- FR-012: generer rapports PDF et exports JSON stockes dans MinIO.
- FR-013: exposer des endpoints de statut de job et de telechargement autorise.
- FR-014: isoler utilisateurs, organisations, projets et audits.

## Cloud deployment requirements
- CR-001: fournir manifests Kubernetes et chart Helm.
- CR-002: supporter namespace `msap`, Ingress HTTPS, Services, Deployments, Jobs, ConfigMaps, Secrets, PVC et NetworkPolicies.
- CR-003: fournir configuration par environnement via `values.yaml`.
- CR-004: permettre PostgreSQL/MinIO embarques ou externes.

## Object storage requirements
- OR-001: utiliser MinIO comme stockage objet S3-compatible.
- OR-002: buckets requis: `msap-apk-uploads`, `msap-artifacts`, `msap-reports`, `msap-exports`, `msap-evidence`.
- OR-003: ne pas stocker les binaires volumineux en PostgreSQL.
- OR-004: journaliser les acces objet et appliquer retention/lifecycle.

## Asynchronous analysis requirements
- AR-001: les analyses longues ne doivent pas bloquer les requetes HTTP.
- AR-002: les jobs doivent avoir statuts, retries bornes, erreurs explicites et idempotence raisonnable.
- AR-003: les workers doivent respecter requests/limits Kubernetes.

## Security requirements
RBAC applicatif, secrets Kubernetes, TLS via Ingress, buckets prives, URLs pre-signees courtes si utilisees, redaction des secrets, audit logs, pas d'exploitation offensive, pas de classification malware garantie, Kimi AI optionnel post-analyse uniquement sans APK brut.
