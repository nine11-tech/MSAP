# Scrum Project Management - MSAP Cloud

## Product goal
Livrer une plateforme cloud-native d'audit statique Android et de triage APK, orientee preuves, MASVS, ATT&CK Mobile, MinIO et Kubernetes.

## Sprint themes
- S1: Cadrage cloud-native, exigences, risques.
- S2: Architecture Kubernetes, MinIO, flux de donnees et modele securite.
- S3: Socle backend, PostgreSQL et references objet.
- S4: Redis/Celery, workers et ingestion APK.
- S5: Analyse statique et normalisation.
- S6: MASVS, ATT&CK Mobile, evidence et scoring.
- S7: Dashboard, rapports, exports objet.
- S8: Helm, Kubernetes, tests, demo et livraison.

## Definition of done
Chaque increment doit conserver le perimetre cybersécurité, ne pas promettre de classification malware garantie, documenter les preuves, et rester compatible Kubernetes cible. Les livrables infra incluent manifests, values Helm, Secrets references, MinIO buckets et validation worker.
