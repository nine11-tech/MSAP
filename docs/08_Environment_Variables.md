# Environment Variables - MSAP

## Django
| Variable | Required | Secret |
|---|---|---|
| `DJANGO_SETTINGS_MODULE` | Yes | No |
| `DJANGO_SECRET_KEY` | Yes | Yes |
| `DJANGO_DEBUG` | Yes | No |
| `DJANGO_ALLOWED_HOSTS` | Yes | No |
| `DJANGO_CSRF_TRUSTED_ORIGINS` | For ingress | No |
| `MSAP_ENVIRONMENT` | Yes | No |
| `SESSION_COOKIE_AGE` | Yes (default 28800) | No |
| `MSAP_PASSWORD_MIN_LENGTH` | Yes (default 12) | No |
| `AXES_FAILURE_LIMIT` | Yes (default 5) | No |
| `AXES_COOLOFF_MINUTES` | Yes (default 15) | No |
| `MSAP_TRUST_PROXY_HEADERS` | Production proxy-specific | No |
| `AXES_IPWARE_PROXY_COUNT` | Trusted proxy mode | No |
| `AXES_IPWARE_PROXY_TRUSTED_IPS` | Trusted proxy mode | No |

## PostgreSQL
| Variable | Required | Secret |
|---|---|---|
| `POSTGRES_HOST` | Yes | No |
| `POSTGRES_PORT` | Yes | No |
| `POSTGRES_DB` | Yes | No |
| `POSTGRES_USER` | Yes | Yes |
| `POSTGRES_PASSWORD` | Yes | Yes |
| `POSTGRES_SSLMODE` | Production | No |

## Redis and Celery
| Variable | Required | Secret |
|---|---|---|
| `REDIS_HOST` | Yes | No |
| `REDIS_PORT` | Yes | No |
| `REDIS_DB` | Yes | No |
| `REDIS_PASSWORD` | Optional | Yes |
| `CELERY_BROKER_URL` | Yes | Maybe |
| `CELERY_RESULT_BACKEND` | Yes | Maybe |
| `CELERY_TASK_DEFAULT_QUEUE` | Yes | No |
| `CELERY_WORKER_CONCURRENCY` | Workers | No |
| `CELERY_TASK_TIME_LIMIT` | Yes | No |

## MinIO
| Variable | Required | Secret |
|---|---|---|
| `MINIO_ENDPOINT` | Yes | No |
| `MINIO_PUBLIC_ENDPOINT` | Browser presigned URLs | No |
| `MINIO_ACCESS_KEY` | Yes | Yes |
| `MINIO_SECRET_KEY` | Yes | Yes |
| `MINIO_REGION` | Optional | No |
| `MINIO_SECURE` | Production | No |
| `MINIO_BUCKET_APK_UPLOADS` | Yes | No |
| `MINIO_BUCKET_ARTIFACTS` | Yes | No |
| `MINIO_BUCKET_EVIDENCE` | Yes | No |
| `MINIO_BUCKET_REPORTS` | Yes | No |
| `MINIO_BUCKET_EXPORTS` | Yes | No |

## MSAP Controls
| Variable | Required | Secret |
|---|---|---|
| `MSAP_MAX_APK_SIZE_BYTES` | Yes | No |
| `MSAP_UPLOAD_REQUIRE_SHA256` | Yes | No |
| `MSAP_PRESIGNED_URL_TTL_SECONDS` | Yes | No |
| `MSAP_DEFAULT_RETENTION_POLICY` | Yes | No |
| `MSAP_LOG_LEVEL` | Yes | No |
| `MSAP_REDACTION_ENABLED` | Yes | No |
| `MSAP_STATUS_CACHE_SECONDS` | Yes (default 5) | No |
| `MSAP_STATUS_TIMEOUT_SECONDS` | Yes (default 1.5) | No |
| `MSAP_APPLICATION_VERSION` | Optional | No |
| `MSAP_MAX_APK_ZIP_ENTRIES` | Yes | No |
| `MSAP_MAX_APK_UNCOMPRESSED_BYTES` | Yes | No |
| `MSAP_MAX_APK_ENTRY_BYTES` | Yes | No |
| `MSAP_MAX_APK_COMPRESSION_RATIO` | Yes | No |
| `MSAP_MAX_DEX_BYTES` | Yes | No |
| `MSAP_MAX_NORMALIZED_MATCHES` | Yes | No |

## Analyzer and Reports
| Variable | Required | Secret |
|---|---|---|
| `ANALYZER_RULES_PATH` | Workers | No |
| `ANALYZER_WORKDIR` | Workers | No |
| `APKTOOL_PATH` | Optional | No |
| `JADX_PATH` | Optional | No |
| `ANALYZER_TIMEOUT_SECONDS` | Workers | No |
| `REPORT_DEFAULT_FORMAT` | Yes | No |
| `REPORT_BUCKET` | Yes | No |
| `EXPORT_BUCKET` | Yes | No |
| `REPORT_INCLUDE_EVIDENCE` | Yes | No |
| `REPORT_REDACTION_REQUIRED` | Yes | No |
| `MSAP_REPORT_AUTHOR` | Optional (`MSAP Analyst`) | No |
| `MSAP_REPORT_ORGANIZATION` | Optional (`MSAP`) | No |
| `MSAP_REPORT_CLASSIFICATION` | Optional (`Security Assessment Report`) | No |
| `MSAP_REPORT_VERSION` | Optional (`1.0`) | No |

The `MSAP_REPORT_*` values populate the deterministic PDF cover, metadata, and
header/footer. They are presentation metadata, not secrets. PDF content is
assembled in memory from persisted audit results and does not require a
temporary directory or external report service.

## Optional AI
AI variables are reserved for V1.1 or later and must default to disabled:
- `AI_ASSISTANT_ENABLED=false`
- `AI_PROVIDER`
- `KIMI_API_KEY`
- `KIMI_MODEL`
- `AI_REDACTION_ENABLED=true`
- `AI_MAX_FINDINGS_CONTEXT`
- `AI_TIMEOUT_SECONDS`
