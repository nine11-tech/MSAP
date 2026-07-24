# Helm Values Contract - MSAP

## Purpose
This contract is implemented by the baseline chart in `helm/msap/`. The chart
intentionally covers the current application, worker, stateful-service,
persistence, ingress, migration, and MinIO initialization needs; advanced
autoscaling, AI, and optional analyzers remain deferred.

## Sections
- `global`
- `image`
- `frontend`
- `backend`
- `worker`
- `redis`
- `postgresql`
- `minio`
- `ingress`
- `tls`
- `secrets`
- `persistence`
- `resources`
- `autoscaling`
- `securityContext`
- `networkPolicy`
- `observability`
- `aiAssistant`
- `analyzerTools`

## Minimal Example
```yaml
global:
  environment: production
  namespace: msap

image:
  registry: ghcr.io/example
  pullPolicy: IfNotPresent

backend:
  replicas: 2
  service:
    port: 8000

worker:
  replicas: 1
  queue: analysis

postgresql:
  enabled: true
  host: msap-postgresql
  port: 5432
  database: msap

redis:
  enabled: true
  host: msap-redis
  port: 6379

minio:
  enabled: true
  endpoint: http://msap-minio:9000
  buckets:
    - msap-apk-uploads
    - msap-artifacts
    - msap-evidence
    - msap-reports
    - msap-exports

aiAssistant:
  enabled: false
```

## Security Defaults
- Use Secrets for credentials.
- Use ConfigMaps for non-secret settings.
- Keep MinIO, PostgreSQL and Redis private.
- Enable TLS for production ingress.
- Prefer non-root containers and no privilege escalation.
- Keep AI disabled by default.
