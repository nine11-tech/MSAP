# Testing - MSAP

## Test Categories
- Model tests for metadata and object references.
- Storage tests for MinIO upload, hash validation and bucket mapping.
- API tests for project authorization, upload, audit status and exports.
- Worker tests for task state transitions and failure handling.
- Rule loader tests for valid and invalid YAML rules.
- Evidence tests for traceability and redaction status.
- Report tests for JSON export generation.

## Acceptance Tests
- Upload an APK and verify it is stored in `msap-apk-uploads`.
- Verify PostgreSQL stores metadata and object references only.
- Queue and complete a Celery analysis task.
- Produce at least one MASVS finding from YAML rules.
- Produce at least one ATT&CK Mobile indicator from YAML rules.
- Link evidence to the source artifact.
- Generate a JSON export and store it in `msap-exports`.
- Confirm Kimi AI is disabled and unused in V1.0.

## Security Regression Tests
- Raw APK bytes are not written to PostgreSQL.
- Secrets are not logged.
- Users cannot access another project's audit data.
- MinIO buckets are not assumed public.
- Pre-signed URLs expire quickly when implemented.

