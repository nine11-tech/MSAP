# API Design - MSAP

## Principles
L'API Django REST est l'intermediaire de confiance pour utilisateurs, audits, uploads, jobs, references MinIO, rapports et exports. Elle applique RBAC, isolation projet/audit et journalisation.

## Object access design
Deux modes sont acceptes:
- **Backend-mediated access**: le client envoie/recoit via l'API; le backend lit/ecrit MinIO.
- **Pre-signed access**: l'API genere une URL courte, limitee a un bucket/object key, apres autorisation.

Les buckets restent prives. Les URLs pre-signees sont expirees rapidement et journalisees.

## Key endpoints
- `POST /api/projects/`
- `POST /api/audits/`
- `POST /api/audits/{id}/apk-upload/`
- `POST /api/audits/{id}/apk-upload/presign/`
- `POST /api/audits/{id}/analysis-jobs/`
- `GET /api/analysis-jobs/{job_id}/status/`
- `GET /api/audits/{id}/findings/`
- `GET /api/audits/{id}/indicators/`
- `GET /api/audits/{id}/evidence/`
- `POST /api/audits/{id}/reports/`
- `GET /api/reports/{id}/download/`

## Job status model
Statuts: `queued`, `running`, `normalizing`, `scoring`, `reporting`, `completed`, `failed`, `cancelled`. Les erreurs techniques sont conservees sans exposer secrets ou extraits sensibles.

## AI endpoints optional
Les endpoints Kimi AI sont desactives par defaut et ne recoivent que du contexte post-analyse redige.
