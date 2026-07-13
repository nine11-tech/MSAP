# Requirements - MSAP

## Functional Requirements
- Users can create or access projects and audits.
- Users can upload APK files for authorized assessment.
- The backend records APK metadata, hash, size, content type and object reference.
- APK payloads are stored in MinIO, not PostgreSQL.
- A Celery task processes each uploaded APK asynchronously.
- Workers produce raw analyzer results, normalized artifacts, findings, indicators and evidence.
- MASVS findings are generated from YAML rules.
- ATT&CK Mobile indicators are generated as cautious triage signals.
- Users can view audit status, findings, indicators and evidence.
- Users can generate and retrieve JSON exports.

## Security Requirements
- All APK analysis must assume untrusted input.
- Buckets must be private.
- Authorization is enforced by the backend, not by MinIO object names alone.
- Secrets must come from environment variables or Kubernetes Secrets.
- Logs must not contain APK contents, secrets or unredacted evidence.
- Optional AI must not receive raw APKs or unredacted evidence.
- Results must avoid guaranteed malware classification language.

## Deployment Requirements
- Kubernetes is the production target.
- Helm values define runtime configuration.
- ConfigMaps hold non-secret settings.
- Secrets hold passwords, API keys and cryptographic values.
- Docker Compose is only for development and quick local testing.

## Non-Functional Requirements
- Large APK uploads should be streamed or bounded by size limits.
- Worker tasks must have timeouts.
- Failed analysis must leave an auditable status.
- Object references must support cleanup and retention policies.
- Reports and exports must be reproducible from stored audit state.

