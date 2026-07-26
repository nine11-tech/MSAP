# MSAP Helm chart

This chart installs the first Kubernetes baseline for MSAP. It includes the
Django API, Celery worker, React/nginx frontend, optional single-instance
PostgreSQL, Redis and MinIO, migration and bucket-initialization Jobs, Services,
persistence, and optional Ingress resources.

Docker Compose remains the development workflow. Helm is the cloud-native
installation method.

## Prerequisites

- Kubernetes 1.27 or newer
- Helm 3
- A default StorageClass when embedded persistence is enabled
- An Ingress controller only when `ingress.enabled=true`
- Backend and frontend images accessible to cluster nodes

No cert-manager, service mesh, operator, Role, or ClusterRole is installed.

## Build and publish images

From the repository root:

```bash
docker build -f backend/Dockerfile -t registry.example.com/msap-backend:1.0.0 .
docker build -f frontend/Dockerfile -t registry.example.com/msap-frontend:1.0.0 frontend
docker push registry.example.com/msap-backend:1.0.0
docker push registry.example.com/msap-frontend:1.0.0
```

Override `backend.image`, `worker.image`, and `frontend.image` for your registry.
The worker intentionally reuses the backend image.

## Install and upgrade

The requested baseline interface is:

```bash
helm upgrade --install msap ./helm/msap \
  --namespace msap \
  --create-namespace
```

For an actual deployment, replace the demonstration credentials and image
repositories:

```bash
helm upgrade --install msap ./helm/msap \
  --namespace msap \
  --create-namespace \
  --set backend.image.repository=registry.example.com/msap-backend \
  --set worker.image.repository=registry.example.com/msap-backend \
  --set frontend.image.repository=registry.example.com/msap-frontend \
  --set secrets.existingSecret=msap-runtime-secrets
```

Use `-f my-values.yaml` for repeatable environment configuration.

## Secrets

The inline `CHANGE-ME` values are demonstration defaults only. Production
installations should create a Secret outside Git and set
`secrets.existingSecret`. It must contain:

- `DJANGO_SECRET_KEY`
- `POSTGRES_USER`
- `POSTGRES_PASSWORD`
- `MINIO_ACCESS_KEY`
- `MINIO_SECRET_KEY`
- `DATABASE_URL` when `postgresql.enabled=false`
- `CELERY_BROKER_URL` and `CELERY_RESULT_BACKEND` when `redis.enabled=false`

Use registry pull secrets through `global.imagePullSecrets`.

## Migrations

A single Helm post-install/post-upgrade hook Job runs:

```text
python manage.py migrate --noinput
python manage.py validate_rules
python manage.py bootstrap_roles
```

The Job uses the backend image and shared configuration, preventing migration
races across backend replicas. Successful hook Jobs are deleted; failed Jobs
remain available for inspection.

The role bootstrap never creates a user. Create the first administrator with a
one-shot pod using the deployed backend image, or interactively:

```bash
kubectl exec -n msap deployment/msap-backend -- python manage.py createsuperuser
```

No default administrator password is present in the chart.

## MinIO initialization and endpoints

The post-install/post-upgrade MinIO hook waits with a bounded retry loop and
idempotently creates:

- `msap-apk-uploads`
- `msap-artifacts`
- `msap-evidence`
- `msap-reports`
- `msap-exports`

Embedded Community MinIO uses its exact-origin global CORS setting. Compatible
external S3 implementations can enable `minio.init.applyBucketCors`.
Buckets remain private and the console is never exposed by the chart's Ingress.

`MINIO_ENDPOINT` is computed from the internal Kubernetes Service when embedded.
`minio.publicEndpoint` is used for presigned URLs and must be reachable by the
user's browser. It must not be a cluster-only hostname.

## External services

Disable embedded components and provide:

```yaml
postgresql:
  enabled: false
  externalDatabaseUrl: postgresql://user:password@postgres.example:5432/msap

redis:
  enabled: false
  externalBrokerUrl: redis://redis.example:6379/0
  externalResultBackend: redis://redis.example:6379/1

minio:
  enabled: false
  externalEndpoint: https://s3.internal.example
  publicEndpoint: https://storage.example.com
  secure: true
```

Prefer `secrets.existingSecret` instead of storing credential-bearing URLs in a
values file.

Embedded PostgreSQL is single-replica and intended for demonstrations or small
installations. Production should use managed or separately operated PostgreSQL
with backups. Redis has no Sentinel/Cluster mode, and embedded MinIO is
single-replica.

## Persistence

PostgreSQL and MinIO persistence are enabled by default. Redis persistence is
optional. Configure each under `persistence` with `enabled`, `storageClass`,
`accessModes`, and `size`.

PVC data may remain after Helm uninstall depending on the StatefulSet and
cluster retention behavior. Inspect PVCs before deleting them.

## Local Kubernetes

Build images with local tags:

```bash
docker build -f backend/Dockerfile -t msap-backend:local .
docker build -f frontend/Dockerfile -t msap-frontend:local frontend
```

Load them into kind or minikube as appropriate, then install:

```bash
helm upgrade --install msap ./helm/msap \
  --namespace msap \
  --create-namespace \
  -f helm/msap/values-local.yaml
```

With Ingress disabled:

```bash
kubectl -n msap port-forward svc/msap-frontend 8080:8080
kubectl -n msap port-forward svc/msap-minio 9000:9000
```

Open `http://localhost:8080`. Both port-forwards are required for browser APK
uploads because local values sign MinIO URLs with `http://localhost:9000`.

## Ingress and TLS

Enable application Ingress with `ingress.enabled`. It routes `/api` to Django
and `/` to the frontend. `ingress.storage.enabled` creates a separate MinIO API
hostname; it never exposes the administrative console. Supply TLS Secret names
through the respective `tls` arrays. The chart does not install cert-manager.

## Worker scaling

Set `worker.replicaCount` and `worker.concurrency`. Workers handle SIGTERM with a
configurable termination grace period. No worker Service is created.

## Uninstall

```bash
helm uninstall msap --namespace msap
```

Review retained PVCs separately:

```bash
kubectl get pvc --namespace msap
```

## Verification

```bash
helm lint helm/msap
helm template msap helm/msap --namespace msap
helm template msap helm/msap --namespace msap -f helm/msap/values-local.yaml
```

## Current limitations

- Session authentication and group RBAC are application-wide, not multi-tenant project ACLs
- No HA PostgreSQL, Redis Sentinel/Cluster, or distributed MinIO
- No autoscaling controller or NetworkPolicy baseline yet
- No AI, dynamic analysis, service mesh, or operator
- Presigned storage URLs require a separately reachable public MinIO endpoint
- Static analysis does not execute APKs, observe dynamic behavior, or classify malware
