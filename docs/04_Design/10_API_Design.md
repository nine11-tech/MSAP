# Design API REST V1 - MSAP

## Principes API

- API locale exposee par Django REST Framework.
- Prefixe recommande: `/api/v1`.
- Authentification obligatoire sauf endpoint de login.
- Toutes les operations concernent des audits autorises et locaux.
- Les APK et rapports restent stockes localement.
- Les reponses doivent eviter d'exposer des chemins absolus internes lorsque ce n'est pas necessaire.

## Endpoints

### Authentication - Login

| Champ | Valeur |
|---|---|
| HTTP method | `POST` |
| URL | `/api/v1/auth/login` |
| Purpose | Authentifier un utilisateur local. |
| Request body | `{"username": "auditor", "password": "********"}` |
| Response body | `{"access_token": "...", "refresh_token": "...", "user": {"id": "...", "username": "auditor", "role": "auditor"}}` |
| Status codes | `200 OK`, `400 Bad Request`, `401 Unauthorized` |
| Security requirement | Transport local, mot de passe jamais journalise, limitation des messages d'erreur. |

### Authentication - Logout

| Champ | Valeur |
|---|---|
| HTTP method | `POST` |
| URL | `/api/v1/auth/logout` |
| Purpose | Invalider la session ou le refresh token. |
| Request body | `{"refresh_token": "..."}` |
| Response body | `{"status": "logged_out"}` |
| Status codes | `200 OK`, `401 Unauthorized` |
| Security requirement | Authentification requise. |

### Projects - List

| Champ | Valeur |
|---|---|
| HTTP method | `GET` |
| URL | `/api/v1/projects` |
| Purpose | Lister les projets accessibles a l'utilisateur. |
| Request body | Aucun. |
| Response body | `{"items": [{"id": "...", "name": "Audit Mobile", "description": "...", "created_at": "..."}]}` |
| Status codes | `200 OK`, `401 Unauthorized` |
| Security requirement | Retourner uniquement les projets autorises. |

### Projects - Create

| Champ | Valeur |
|---|---|
| HTTP method | `POST` |
| URL | `/api/v1/projects` |
| Purpose | Creer un projet d'audit local. |
| Request body | `{"name": "Projet Android", "description": "Analyse statique APK", "client_or_context": "PFA"}` |
| Response body | `{"id": "...", "name": "Projet Android", "created_at": "..."}` |
| Status codes | `201 Created`, `400 Bad Request`, `401 Unauthorized` |
| Security requirement | Authentification requise, validation des champs texte. |

### Projects - Detail

| Champ | Valeur |
|---|---|
| HTTP method | `GET` |
| URL | `/api/v1/projects/{project_id}` |
| Purpose | Consulter un projet et sa synthese. |
| Request body | Aucun. |
| Response body | `{"id": "...", "name": "...", "description": "...", "audit_count": 2}` |
| Status codes | `200 OK`, `401 Unauthorized`, `403 Forbidden`, `404 Not Found` |
| Security requirement | Verifier l'acces au projet. |

### Audits - List

| Champ | Valeur |
|---|---|
| HTTP method | `GET` |
| URL | `/api/v1/projects/{project_id}/audits` |
| Purpose | Lister les audits d'un projet. |
| Request body | Aucun. |
| Response body | `{"items": [{"id": "...", "name": "...", "status": "completed", "created_at": "..."}]}` |
| Status codes | `200 OK`, `401 Unauthorized`, `403 Forbidden`, `404 Not Found` |
| Security requirement | Verifier l'acces au projet. |

### Audits - Create

| Champ | Valeur |
|---|---|
| HTTP method | `POST` |
| URL | `/api/v1/projects/{project_id}/audits` |
| Purpose | Creer un audit statique Android dans un projet. |
| Request body | `{"name": "Audit APK v1", "scope": "Analyse statique APK autorisee"}` |
| Response body | `{"id": "...", "project_id": "...", "status": "created"}` |
| Status codes | `201 Created`, `400 Bad Request`, `401 Unauthorized`, `403 Forbidden` |
| Security requirement | Authentification et controle d'acces projet. |

### APK Upload

| Champ | Valeur |
|---|---|
| HTTP method | `POST` |
| URL | `/api/v1/audits/{audit_id}/apk` |
| Purpose | Deposer un APK localement pour un audit. |
| Request body | `multipart/form-data` avec champ `file`. |
| Response body | `{"apk_file_id": "...", "original_filename": "app.apk", "sha256": "...", "size_bytes": 123456}` |
| Status codes | `201 Created`, `400 Bad Request`, `401 Unauthorized`, `403 Forbidden`, `413 Payload Too Large` |
| Security requirement | Validation de type et taille, stockage local controle, ne jamais executer le fichier. |

### Start Analysis

| Champ | Valeur |
|---|---|
| HTTP method | `POST` |
| URL | `/api/v1/audits/{audit_id}/analysis/start` |
| Purpose | Lancer le pipeline d'analyse statique. |
| Request body | `{"force": false}` |
| Response body | `{"analysis_result_id": "...", "status": "running"}` |
| Status codes | `202 Accepted`, `400 Bad Request`, `401 Unauthorized`, `403 Forbidden`, `409 Conflict` |
| Security requirement | APK requis, une seule analyse active par audit dans le MVP. |

### Get Analysis Status

| Champ | Valeur |
|---|---|
| HTTP method | `GET` |
| URL | `/api/v1/audits/{audit_id}/analysis/status` |
| Purpose | Consulter l'etat courant de l'analyse. |
| Request body | Aucun. |
| Response body | `{"analysis_result_id": "...", "status": "running", "current_step": "rule_execution", "progress": 70}` |
| Status codes | `200 OK`, `401 Unauthorized`, `403 Forbidden`, `404 Not Found` |
| Security requirement | Ne pas exposer de chemins internes sensibles dans les erreurs. |

### List Findings

| Champ | Valeur |
|---|---|
| HTTP method | `GET` |
| URL | `/api/v1/audits/{audit_id}/findings` |
| Purpose | Lister les findings d'un audit. |
| Request body | Aucun. Query params optionnels: `severity`, `masvs_category`, `status`. |
| Response body | `{"items": [{"id": "...", "rule_id": "MSAP-AND-003", "title": "Cleartext traffic allowed", "severity": "High", "masvs_category": "MASVS-NETWORK"}]}` |
| Status codes | `200 OK`, `401 Unauthorized`, `403 Forbidden`, `404 Not Found` |
| Security requirement | Retourner uniquement les resultats de l'audit autorise. |

### Get Finding Details

| Champ | Valeur |
|---|---|
| HTTP method | `GET` |
| URL | `/api/v1/findings/{finding_id}` |
| Purpose | Consulter le detail d'un finding et ses preuves. |
| Request body | Aucun. |
| Response body | `{"id": "...", "rule_id": "MSAP-AND-001", "title": "...", "description": "...", "severity": "High", "impact": "...", "recommendation": "...", "evidence": [{"source": "AndroidManifest.xml", "file_path": "AndroidManifest.xml", "snippet": "..."}]}` |
| Status codes | `200 OK`, `401 Unauthorized`, `403 Forbidden`, `404 Not Found` |
| Security requirement | Masquer ou tronquer les snippets contenant des secrets potentiels. |

### MASVS Compliance Summary

| Champ | Valeur |
|---|---|
| HTTP method | `GET` |
| URL | `/api/v1/audits/{audit_id}/masvs/summary` |
| Purpose | Fournir une synthese par categorie MASVS. |
| Request body | Aucun. |
| Response body | `{"categories": [{"code": "MASVS-NETWORK", "finding_count": 3, "highest_severity": "High"}], "total_findings": 10}` |
| Status codes | `200 OK`, `401 Unauthorized`, `403 Forbidden`, `404 Not Found` |
| Security requirement | Synthese limitee a l'audit autorise. |

### Generate Report

| Champ | Valeur |
|---|---|
| HTTP method | `POST` |
| URL | `/api/v1/audits/{audit_id}/reports/generate` |
| Purpose | Generer un rapport local pour l'audit. |
| Request body | `{"format": "pdf"}` ou `{"format": "html"}` selon le MVP. |
| Response body | `{"report_id": "...", "status": "generated", "format": "pdf"}` |
| Status codes | `201 Created`, `400 Bad Request`, `401 Unauthorized`, `403 Forbidden`, `409 Conflict` |
| Security requirement | Rapport genere localement, validation du format, controle d'acces. |

### Download Report

| Champ | Valeur |
|---|---|
| HTTP method | `GET` |
| URL | `/api/v1/reports/{report_id}/download` |
| Purpose | Telecharger un rapport genere. |
| Request body | Aucun. |
| Response body | Fichier binaire ou contenu du rapport avec headers de telechargement. |
| Status codes | `200 OK`, `401 Unauthorized`, `403 Forbidden`, `404 Not Found` |
| Security requirement | Verifier l'acces au rapport, ne pas exposer le chemin local absolu. |
