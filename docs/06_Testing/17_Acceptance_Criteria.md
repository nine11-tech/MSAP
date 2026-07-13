# Acceptance Criteria - MSAP Cloud

- APK upload is accepted only for authorized users.
- APK is stored in MinIO bucket `msap-apk-uploads`.
- PostgreSQL stores ObjectStorageReference, hash and audit metadata.
- Worker processes an analysis job from Redis/Celery or Kubernetes Job.
- Analysis artifacts are stored in MinIO.
- MASVS findings and ATT&CK Mobile indicators are generated with evidence.
- No result claims guaranteed malware/benign classification.
- Report PDF is generated and stored in MinIO bucket `msap-reports`.
- JSON export is stored in MinIO bucket `msap-exports`.
- Kubernetes deployment works on kind/K3s or target cluster.
- Helm chart installs successfully and supports rollback.
- Docker Compose is documented only as development mode.
- Kimi AI, if enabled, uses only redacted post-analysis context.
