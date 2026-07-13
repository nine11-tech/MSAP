# Development Guide - MSAP

## First Coding Target
Start with the backend and storage foundation:
1. Create the Django project.
2. Configure environment loading.
3. Add PostgreSQL models.
4. Implement `ObjectStorageReference`.
5. Add MinIO client integration.
6. Implement APK upload metadata and object storage.
7. Add Redis/Celery.
8. Add the first worker task.
9. Add YAML rule loading.
10. Add JSON export.

## Suggested Django Apps
- `accounts`
- `projects`
- `audits`
- `storage`
- `apk_files`
- `analysis`
- `rules`
- `findings`
- `evidence`
- `reports`

## Local Development
Docker Compose may be used for local PostgreSQL, Redis and MinIO. It must not become the production deployment model.

## Worker Safety
- Treat APKs as untrusted input.
- Use a scratch directory.
- Enforce timeouts and size limits.
- Store large outputs in MinIO.
- Keep errors bounded and safe for logs.

## Implementation Rule
Build only what is required by the MVP freeze before adding optional AI, dynamic analysis, MobSF, Frida, iOS or advanced observability.

