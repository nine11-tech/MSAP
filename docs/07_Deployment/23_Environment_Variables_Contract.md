# Environment Variables Contract - MSAP

## Purpose
This document defines the runtime environment variables expected by the future MSAP implementation. Values are supplied by Helm values, Kubernetes ConfigMaps and Kubernetes Secrets. This is a contract only; no application code or manifests are created here.

## Django
| Variable | Purpose | Example | Required | Secret | Kubernetes source |
|---|---|---|---|---|---|
| `DJANGO_SETTINGS_MODULE` | Django settings module | `msap.settings.production` | Required | No | ConfigMap / Helm value |
| `DJANGO_SECRET_KEY` | Django cryptographic secret | `change-me-from-secret` | Required | Yes | Secret |
| `DJANGO_DEBUG` | Enable debug mode | `false` | Required | No | ConfigMap / Helm value |
| `DJANGO_ALLOWED_HOSTS` | Allowed hostnames | `msap.example.local` | Required | No | ConfigMap / Helm value |
| `DJANGO_CSRF_TRUSTED_ORIGINS` | Trusted CSRF origins | `https://msap.example.local` | Required for ingress | No | ConfigMap / Helm value |
| `MSAP_ENVIRONMENT` | Runtime environment label | `production` | Required | No | ConfigMap / Helm value |

## PostgreSQL
| Variable | Purpose | Example | Required | Secret | Kubernetes source |
|---|---|---|---|---|---|
| `POSTGRES_HOST` | PostgreSQL hostname | `msap-postgresql` | Required | No | ConfigMap / Helm value |
| `POSTGRES_PORT` | PostgreSQL port | `5432` | Required | No | ConfigMap / Helm value |
| `POSTGRES_DB` | Database name | `msap` | Required | No | ConfigMap / Helm value |
| `POSTGRES_USER` | Database username | `msap_app` | Required | Yes | Secret |
| `POSTGRES_PASSWORD` | Database password | `example-password` | Required | Yes | Secret |
| `POSTGRES_SSLMODE` | TLS mode | `require` | Required for production | No | ConfigMap / Helm value |

## Redis
| Variable | Purpose | Example | Required | Secret | Kubernetes source |
|---|---|---|---|---|---|
| `REDIS_HOST` | Redis hostname | `msap-redis` | Required | No | ConfigMap / Helm value |
| `REDIS_PORT` | Redis port | `6379` | Required | No | ConfigMap / Helm value |
| `REDIS_DB` | Redis database index | `0` | Required | No | ConfigMap / Helm value |
| `REDIS_PASSWORD` | Redis password | `example-password` | Optional | Yes | Secret |
| `REDIS_TLS_ENABLED` | Enable Redis TLS | `false` | Optional | No | ConfigMap / Helm value |

## MinIO
| Variable | Purpose | Example | Required | Secret | Kubernetes source |
|---|---|---|---|---|---|
| `MINIO_ENDPOINT` | S3-compatible endpoint | `http://msap-minio:9000` | Required | No | ConfigMap / Helm value |
| `MINIO_ACCESS_KEY` | MinIO access key | `msap-access` | Required | Yes | Secret |
| `MINIO_SECRET_KEY` | MinIO secret key | `example-secret` | Required | Yes | Secret |
| `MINIO_REGION` | S3 region label | `us-east-1` | Optional | No | ConfigMap / Helm value |
| `MINIO_SECURE` | Use HTTPS for MinIO | `true` | Required for production | No | ConfigMap / Helm value |
| `MINIO_BUCKET_APK_UPLOADS` | APK upload bucket | `msap-apk-uploads` | Required | No | ConfigMap / Helm value |
| `MINIO_BUCKET_ARTIFACTS` | Analyzer artifact bucket | `msap-artifacts` | Required | No | ConfigMap / Helm value |
| `MINIO_BUCKET_EVIDENCE` | Evidence bucket | `msap-evidence` | Required | No | ConfigMap / Helm value |
| `MINIO_BUCKET_REPORTS` | Report bucket | `msap-reports` | Required | No | ConfigMap / Helm value |
| `MINIO_BUCKET_EXPORTS` | Export bucket | `msap-exports` | Required | No | ConfigMap / Helm value |

## Celery
| Variable | Purpose | Example | Required | Secret | Kubernetes source |
|---|---|---|---|---|---|
| `CELERY_BROKER_URL` | Broker URL | `redis://msap-redis:6379/0` | Required | May include secret | Secret or ConfigMap |
| `CELERY_RESULT_BACKEND` | Result backend URL | `redis://msap-redis:6379/1` | Required | May include secret | Secret or ConfigMap |
| `CELERY_TASK_DEFAULT_QUEUE` | Default queue | `analysis` | Required | No | ConfigMap / Helm value |
| `CELERY_WORKER_CONCURRENCY` | Worker concurrency | `2` | Required for workers | No | ConfigMap / Helm value |
| `CELERY_TASK_TIME_LIMIT` | Hard task timeout seconds | `900` | Required | No | ConfigMap / Helm value |

## Security
| Variable | Purpose | Example | Required | Secret | Kubernetes source |
|---|---|---|---|---|---|
| `MSAP_MAX_APK_SIZE_BYTES` | Upload size limit | `524288000` | Required | No | ConfigMap / Helm value |
| `MSAP_UPLOAD_REQUIRE_SHA256` | Require upload hash verification | `true` | Required | No | ConfigMap / Helm value |
| `MSAP_PRESIGNED_URL_TTL_SECONDS` | Download URL lifetime | `300` | Required | No | ConfigMap / Helm value |
| `MSAP_DEFAULT_RETENTION_POLICY` | Default retention class | `active_audit` | Required | No | ConfigMap / Helm value |
| `MSAP_LOG_LEVEL` | Application log level | `INFO` | Required | No | ConfigMap / Helm value |
| `MSAP_REDACTION_ENABLED` | Enable evidence redaction controls | `true` | Required | No | ConfigMap / Helm value |

## Kubernetes
| Variable | Purpose | Example | Required | Secret | Kubernetes source |
|---|---|---|---|---|---|
| `KUBERNETES_NAMESPACE` | Runtime namespace | `msap` | Required | No | ConfigMap / Helm value |
| `MSAP_SERVICE_NAME` | Logical service name | `msap-backend` | Optional | No | ConfigMap / Helm value |
| `MSAP_PUBLIC_BASE_URL` | Public application URL | `https://msap.example.local` | Required for ingress | No | ConfigMap / Helm value |
| `MSAP_ENABLE_K8S_JOBS` | Allow analyzer Kubernetes Jobs later | `false` | Optional | No | ConfigMap / Helm value |

## Optional Kimi AI
| Variable | Purpose | Example | Required | Secret | Kubernetes source |
|---|---|---|---|---|---|
| `AI_ASSISTANT_ENABLED` | Enable optional AI assistant | `false` | Optional | No | ConfigMap / Helm value |
| `AI_PROVIDER` | AI provider name | `kimi` | Optional | No | ConfigMap / Helm value |
| `KIMI_API_KEY` | Kimi API key | `example-key` | Optional | Yes | Secret |
| `KIMI_MODEL` | Kimi model name | `kimi-latest` | Optional | No | ConfigMap / Helm value |
| `AI_REDACTION_ENABLED` | Require redaction before AI context | `true` | Optional | No | ConfigMap / Helm value |
| `AI_MAX_FINDINGS_CONTEXT` | Maximum findings sent per request | `20` | Optional | No | ConfigMap / Helm value |
| `AI_TIMEOUT_SECONDS` | AI request timeout | `30` | Optional | No | ConfigMap / Helm value |

## Analyzer Paths
| Variable | Purpose | Example | Required | Secret | Kubernetes source |
|---|---|---|---|---|---|
| `ANALYZER_RULES_PATH` | YAML rules directory | `/app/rules` | Required for workers | No | ConfigMap / Helm value |
| `ANALYZER_WORKDIR` | Worker scratch directory | `/tmp/msap-analysis` | Required for workers | No | ConfigMap / Helm value |
| `APKTOOL_PATH` | Future apktool executable path | `/opt/tools/apktool` | Optional | No | ConfigMap / Helm value |
| `JADX_PATH` | Future jadx executable path | `/opt/tools/jadx` | Optional | No | ConfigMap / Helm value |
| `ANALYZER_TIMEOUT_SECONDS` | Analyzer timeout | `600` | Required for workers | No | ConfigMap / Helm value |

## Report Generation
| Variable | Purpose | Example | Required | Secret | Kubernetes source |
|---|---|---|---|---|---|
| `REPORT_DEFAULT_FORMAT` | Default report/export format | `json` | Required | No | ConfigMap / Helm value |
| `REPORT_BUCKET` | Report bucket | `msap-reports` | Required | No | ConfigMap / Helm value |
| `EXPORT_BUCKET` | JSON export bucket | `msap-exports` | Required | No | ConfigMap / Helm value |
| `REPORT_INCLUDE_EVIDENCE` | Include evidence in report output | `true` | Required | No | ConfigMap / Helm value |
| `REPORT_REDACTION_REQUIRED` | Require report redaction controls | `true` | Required | No | ConfigMap / Helm value |
