# Helm Values Contract - MSAP

## Purpose
This document defines the future `values.yaml` contract for the MSAP Helm chart. It is a design-level contract only; it does not create chart templates or Kubernetes manifests.

## Contract Sections

### `global`
Purpose: shared deployment metadata.
Expected fields: `environment`, `namespace`, `domain`, `imagePullSecrets`, `storageClass`.
Example:
```yaml
global:
  environment: dev
  namespace: msap
  domain: msap.local
  imagePullSecrets: []
  storageClass: standard
```
Required: required for deployed environments.
Security notes: namespace and domain must not encode secrets.

### `image`
Purpose: default image registry, repository and tag behavior.
Expected fields: `registry`, `pullPolicy`, `tag`.
Example:
```yaml
image:
  registry: registry.example.local
  pullPolicy: IfNotPresent
  tag: "1.0.0"
```
Required: required.
Security notes: production must pin immutable tags or digests and avoid `latest`.

### `frontend`
Purpose: configure the future React frontend deployment.
Expected fields: `enabled`, `replicaCount`, `image.repository`, `service.port`, `env`.
Example:
```yaml
frontend:
  enabled: true
  replicaCount: 1
  image:
    repository: msap/frontend
  service:
    port: 80
  env:
    API_BASE_URL: /api
```
Required: optional for API-only deployments.
Security notes: frontend values must contain non-secret runtime configuration only.

### `backend`
Purpose: configure Django API pods.
Expected fields: `enabled`, `replicaCount`, `image.repository`, `service.port`, `gunicornWorkers`, `env`.
Example:
```yaml
backend:
  enabled: true
  replicaCount: 2
  image:
    repository: msap/backend
  service:
    port: 8000
  gunicornWorkers: 3
```
Required: required.
Security notes: Django secret key and database password must come from Kubernetes Secrets.

### `worker`
Purpose: configure Celery analyzer workers.
Expected fields: `enabled`, `replicaCount`, `image.repository`, `queues`, `concurrency`.
Example:
```yaml
worker:
  enabled: true
  replicaCount: 1
  image:
    repository: msap/worker
  queues:
    - analysis
  concurrency: 2
```
Required: required for analysis.
Security notes: workers must use least-privilege MinIO credentials and must not expose HTTP ingress.

### `redis`
Purpose: configure Redis as Celery broker/result backend for local or embedded deployments.
Expected fields: `enabled`, `externalHost`, `authSecretName`, `persistence.enabled`.
Example:
```yaml
redis:
  enabled: true
  externalHost: ""
  authSecretName: msap-redis-secret
  persistence:
    enabled: false
```
Required: required as a service, embedded or external.
Security notes: Redis must not be exposed publicly.

### `postgresql`
Purpose: configure PostgreSQL metadata storage.
Expected fields: `enabled`, `host`, `port`, `database`, `userSecretName`, `passwordSecretName`, `sslMode`.
Example:
```yaml
postgresql:
  enabled: true
  host: msap-postgresql
  port: 5432
  database: msap
  userSecretName: msap-postgres-user
  passwordSecretName: msap-postgres-password
  sslMode: require
```
Required: required.
Security notes: PostgreSQL stores metadata and MinIO references only, not raw APK payloads.

### `minio`
Purpose: configure object storage for APKs, artifacts, evidence, reports and exports.
Expected fields: `enabled`, `endpoint`, `accessKeySecretName`, `secretKeySecretName`, `buckets`.
Example:
```yaml
minio:
  enabled: true
  endpoint: http://msap-minio:9000
  accessKeySecretName: msap-minio-access-key
  secretKeySecretName: msap-minio-secret-key
  buckets:
    - msap-apk-uploads
    - msap-artifacts
    - msap-evidence
    - msap-reports
    - msap-exports
```
Required: required, embedded or external S3-compatible endpoint.
Security notes: MinIO is object storage, not application hosting. Buckets must remain private.

### `ingress`
Purpose: expose frontend and API through Kubernetes ingress.
Expected fields: `enabled`, `className`, `hosts`, `annotations`.
Example:
```yaml
ingress:
  enabled: true
  className: nginx
  hosts:
    - host: msap.example.local
      paths:
        - path: /
          service: frontend
        - path: /api
          service: backend
  annotations: {}
```
Required: optional for local port-forward deployments.
Security notes: production ingress must use TLS and avoid exposing internal services.

### `tls`
Purpose: configure TLS references for ingress.
Expected fields: `enabled`, `secretName`, `issuerRef`.
Example:
```yaml
tls:
  enabled: true
  secretName: msap-tls
  issuerRef: letsencrypt-prod
```
Required: required for production.
Security notes: certificates and private keys must be stored in Secrets or managed by cert-manager.

### `secrets`
Purpose: name existing Kubernetes Secrets used by the chart.
Expected fields: `djangoSecretName`, `databaseSecretName`, `redisSecretName`, `minioSecretName`, `aiSecretName`.
Example:
```yaml
secrets:
  djangoSecretName: msap-django-secret
  databaseSecretName: msap-postgres-secret
  redisSecretName: msap-redis-secret
  minioSecretName: msap-minio-secret
  aiSecretName: msap-ai-secret
```
Required: required for production; development may generate local equivalents later.
Security notes: chart values must reference secret names, not inline secret values.

### `persistence`
Purpose: configure persistent storage for embedded stateful services.
Expected fields: `postgresql.size`, `minio.size`, `redis.size`, `storageClass`.
Example:
```yaml
persistence:
  storageClass: standard
  postgresql:
    size: 20Gi
  minio:
    size: 100Gi
  redis:
    size: 1Gi
```
Required: optional when using external managed services.
Security notes: persistent volumes must align with institutional backup and encryption requirements.

### `resources`
Purpose: define pod resource requests and limits.
Expected fields: per-component `requests` and `limits`.
Example:
```yaml
resources:
  backend:
    requests:
      cpu: 250m
      memory: 512Mi
    limits:
      cpu: "1"
      memory: 1Gi
```
Required: required for production.
Security notes: resource limits reduce denial-of-service blast radius from large APK analysis.

### `autoscaling`
Purpose: configure future HPA/KEDA-style scaling.
Expected fields: `enabled`, per-component min/max replicas and metrics.
Example:
```yaml
autoscaling:
  enabled: false
  worker:
    minReplicas: 1
    maxReplicas: 5
    queueLengthTarget: 10
```
Required: optional.
Security notes: advanced autoscaling is deferred from V1.0.

### `securityContext`
Purpose: configure pod and container hardening defaults.
Expected fields: `runAsNonRoot`, `readOnlyRootFilesystem`, `allowPrivilegeEscalation`, `fsGroup`.
Example:
```yaml
securityContext:
  runAsNonRoot: true
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  fsGroup: 10001
```
Required: required for production.
Security notes: analyzer tools may need explicit exceptions documented per adapter.

### `networkPolicy`
Purpose: define network isolation behavior.
Expected fields: `enabled`, `allowIngressFrom`, `allowEgressTo`.
Example:
```yaml
networkPolicy:
  enabled: true
  allowIngressFrom:
    - ingress-controller
  allowEgressTo:
    - postgresql
    - redis
    - minio
```
Required: required for production.
Security notes: workers should not have unrestricted outbound access by default.

### `observability`
Purpose: configure logs, metrics and tracing hooks.
Expected fields: `metrics.enabled`, `serviceMonitor.enabled`, `logLevel`, `tracing.enabled`.
Example:
```yaml
observability:
  logLevel: INFO
  metrics:
    enabled: true
  serviceMonitor:
    enabled: false
  tracing:
    enabled: false
```
Required: optional for V1.0.
Security notes: logs must not include APK contents, secrets or unredacted evidence.

### `aiAssistant`
Purpose: configure optional post-analysis AI assistance.
Expected fields: `enabled`, `provider`, `apiKeySecretName`, `model`, `redactionEnabled`, `maxFindingsContext`, `timeoutSeconds`.
Example:
```yaml
aiAssistant:
  enabled: false
  provider: kimi
  apiKeySecretName: msap-kimi-api-key
  model: kimi-latest
  redactionEnabled: true
  maxFindingsContext: 20
  timeoutSeconds: 30
```
Required: optional and out of V1.0 implementation.
Security notes: Kimi AI must receive redacted post-analysis context only and never raw APKs.

### `analyzerTools`
Purpose: configure future analyzer tool paths and adapter behavior.
Expected fields: `apktoolPath`, `jadxPath`, `timeoutSeconds`, `maxApkSizeBytes`, `rulesMountPath`.
Example:
```yaml
analyzerTools:
  apktoolPath: /opt/tools/apktool
  jadxPath: /opt/tools/jadx
  timeoutSeconds: 600
  maxApkSizeBytes: 524288000
  rulesMountPath: /app/rules
```
Required: required once workers are implemented.
Security notes: analyzer adapters must treat APKs as untrusted input and run with constrained filesystem and network access.
