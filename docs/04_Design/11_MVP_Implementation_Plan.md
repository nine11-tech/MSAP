# MVP Implementation Plan - MSAP Cloud

## MVP objective
Construire le socle cloud-native de MSAP Cloud sans perdre le coeur cybersécurité: analyse statique Android, MASVS, ATT&CK Mobile prudent, preuves et reporting.

## MVP scope
- Backend foundation Django REST + PostgreSQL.
- MinIO integration et ObjectStorageReference.
- Redis/Celery queue et worker foundation.
- APK ingestion et stockage objet.
- Analyse statique minimale et normalization.
- MASVS + ATT&CK engines initiaux.
- Evidence + Risk engines.
- Rapport PDF/JSON stocke dans MinIO.
- Kubernetes manifests et Helm chart comme artefacts de livraison.
- Docker Compose uniquement pour developpement local.

## Delivery artifacts
Documentation, schema de donnees, API design, chart Helm, manifests Kubernetes, strategie MinIO, tests de base et scenario demo Kubernetes/K3s.
