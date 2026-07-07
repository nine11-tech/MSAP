# REST API Design V1 - MSAP

## Principles

- Prefix: `/api/v1`.
- Django REST Framework compatible.
- Authentification requise sauf login.
- Donnees et fichiers conserves localement.
- Les reponses exposent des identifiants applicatifs, pas de chemins absolus sensibles.

## Endpoints

| Method | URL | Purpose | Request Body | Response Body | Status Codes | Security Requirement |
|---|---|---|---|---|---|---|
| POST | `/auth/login` | Authentifier un utilisateur local. | `{"username":"...","password":"..."}` | Tokens et profil utilisateur. | 200, 400, 401 | Ne jamais journaliser le mot de passe. |
| POST | `/auth/logout` | Invalider la session. | `{"refresh_token":"..."}` | `{"status":"logged_out"}` | 200, 401 | Authentification requise. |
| GET | `/projects` | Lister les projets. | None | Liste de projets. | 200, 401 | Filtrer par utilisateur autorise. |
| POST | `/projects` | Creer un projet. | `{"name":"...","description":"..."}` | Projet cree. | 201, 400, 401 | Validation des champs. |
| GET | `/projects/{project_id}` | Detail projet. | None | Detail et synthese. | 200, 401, 403, 404 | Controle d'acces. |
| GET | `/projects/{project_id}/audits` | Lister audits. | None | Liste audits. | 200, 401, 403 | Controle d'acces projet. |
| POST | `/projects/{project_id}/audits` | Creer audit. | `{"name":"...","scope":"..."}` | Audit cree. | 201, 400, 401, 403 | Perimetre autorise requis. |
| POST | `/audits/{audit_id}/apk` | Upload APK. | `multipart/form-data file` | APKFile avec SHA-256. | 201, 400, 401, 403, 413 | Validation fichier, stockage local. |
| POST | `/audits/{audit_id}/analysis/start` | Lancer analyse. | `{"force":false}` | Analysis status. | 202, 400, 401, 403, 409 | APK requis, une analyse active max. |
| GET | `/audits/{audit_id}/analysis/status` | Statut pipeline. | None | Statut, etape, progression. | 200, 401, 403, 404 | Pas de fuite de chemins internes. |
| GET | `/audits/{audit_id}/artifacts` | Lister artefacts normalises. | Query `artifact_type` optionnel. | Liste NormalizedArtifact. | 200, 401, 403 | Snippets rediges si sensibles. |
| GET | `/audits/{audit_id}/findings` | Lister findings MASVS. | Query `severity`, `masvs_category`. | Liste findings. | 200, 401, 403 | Audit autorise uniquement. |
| GET | `/findings/{finding_id}` | Detail finding. | None | Finding avec preuves. | 200, 401, 403, 404 | Redaction secrets. |
| GET | `/audits/{audit_id}/indicators` | Lister indicateurs de triage. | Query `severity`, `tactic`, `confidence`. | Liste SuspiciousIndicator. | 200, 401, 403 | Wording non conclusif. |
| GET | `/indicators/{indicator_id}` | Detail indicateur. | None | Indicateur avec mapping ATT&CK et preuves. | 200, 401, 403, 404 | Afficher comme triage, pas verdict. |
| GET | `/audits/{audit_id}/evidence` | Lister preuves. | Query `finding_id`, `indicator_id`. | Liste Evidence. | 200, 401, 403 | Snippets limites et rediges. |
| GET | `/evidence/{evidence_id}` | Detail preuve. | None | Source, extrait, contexte. | 200, 401, 403, 404 | Masquage valeurs sensibles. |
| GET | `/audits/{audit_id}/masvs/summary` | Synthese MASVS. | None | Categories, counts, compliance. | 200, 401, 403 | Audit autorise. |
| GET | `/audits/{audit_id}/attck/summary` | Synthese ATT&CK Mobile. | None | Tactiques, techniques, indicateurs. | 200, 401, 403 | Preciser triage non definitif. |
| GET | `/audits/{audit_id}/risk/summary` | Synthese risque. | None | Risk score global et priorites. | 200, 401, 403 | Score indicatif. |
| GET | `/audits/{audit_id}/compliance/summary` | Synthese conformite. | None | Compliance score MASVS. | 200, 401, 403 | Pas une certification MASVS. |
| POST | `/audits/{audit_id}/reports/generate` | Generer rapport. | `{"format":"pdf"}` | Report metadata. | 201, 400, 401, 403, 409 | Generation locale. |
| GET | `/reports/{report_id}/download` | Telecharger rapport. | None | Fichier PDF. | 200, 401, 403, 404 | Controle d'acces rapport. |
| POST | `/audits/{audit_id}/exports/json` | Generer export JSON. | `{}` | Export metadata. | 201, 401, 403, 409 | Export local redige. |
| GET | `/exports/{export_id}/download` | Telecharger export JSON. | None | Fichier JSON. | 200, 401, 403, 404 | Ne pas exposer chemins absolus. |

## Notes de Securite

- Toutes les operations d'audit exigent authentification.
- Les uploads doivent limiter taille et type.
- Les snippets contenant des secrets sont tronques.
- Les endpoints ATT&CK doivent utiliser un vocabulaire de triage prudent.
