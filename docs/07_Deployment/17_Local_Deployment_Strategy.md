# Strategie de Deploiement Local - MSAP

## Local Deployment Goals

Permettre l'execution de MSAP sur un poste institutionnel, avec stockage local des APK, artefacts, preuves, rapports et base de donnees.

## Docker Compose Architecture

Services prevus:

- `frontend`
- `backend`
- `postgres`
- volumes locaux pour uploads, artifacts, reports, exports

## Volumes

- `msap_uploads`
- `msap_artifacts`
- `msap_reports`
- `msap_exports`
- `postgres_data`

## Environment Variables

- `DATABASE_URL`
- `MSAP_UPLOAD_DIR`
- `MSAP_ARTIFACT_DIR`
- `MSAP_REPORT_DIR`
- `MSAP_EXPORT_DIR`
- `MSAP_MAX_APK_SIZE`
- `MSAP_SECRET_KEY`

## Local Storage

Les chemins doivent etre relatifs aux volumes Docker ou a un repertoire institutionnel controle.

## Data Confidentiality

Les APK et preuves restent locaux. Les sauvegardes doivent etre chiffrees ou stockees dans un espace institutionnel controle.

## Backup Considerations

- Sauvegarder PostgreSQL.
- Sauvegarder rapports et exports.
- Definir une politique de retention des APK.

## Installation Workflow

1. Verifier Docker Compose.
2. Configurer `.env`.
3. Monter volumes locaux.
4. Demarrer services.
5. Executer migrations.
6. Creer utilisateur local.
7. Lancer analyse de demonstration.

## Institutional Workstation Usage

MSAP doit fonctionner sans service distant et respecter les politiques locales de confidentialite.

## Optional AI External Dependency

Kimi AI is an optional V1.1 external dependency and is disabled by default. The local-first mode remains the default deployment mode, and no-AI mode works offline for APK analysis, evidence, scoring and reporting.

Kimi configuration is allowed only if the institution permits external AI use. When enabled, MSAP must send only redacted post-analysis context and must never send raw APK files or full decompiled source code.

## ARM64 Constraints and Mitigations

- Preferer images multi-arch.
- Tester outils Java localement.
- Garder YARA optionnel.
- Documenter alternatives si un outil n'est pas disponible.
