# Modele de Ressources Kubernetes - MSAP

## Planned Kubernetes manifests
Namespace, Deployments, Services, Ingress, ConfigMaps, Secrets, PVC, Jobs, CronJobs, NetworkPolicies, ServiceAccounts et RBAC minimal.

## Helm chart structure
```text
charts/msap/
  Chart.yaml
  values.yaml
  templates/
    namespace.yaml
    frontend-deployment.yaml
    frontend-service.yaml
    backend-deployment.yaml
    backend-service.yaml
    worker-deployment.yaml
    ingress.yaml
    configmap.yaml
    secret.yaml
    redis.yaml
    postgresql.yaml
    minio.yaml
    pvc.yaml
    job-analyzer.yaml
    cronjob-cleanup.yaml
    networkpolicy.yaml
    serviceaccount.yaml
```

## values.yaml configuration
`values.yaml` configure images, tags, replicas, ressources, endpoints PostgreSQL/Redis/MinIO, buckets, Ingress host, TLS, probes, autoscaling, retention et activation optionnelle de Kimi AI.

## Resource requests/limits
API et frontend ont des limites modestes. Les workers ont des requests/limits plus eleves, car APKTool/JADX/Androguard peuvent consommer CPU et RAM. Les Jobs d'analyse peuvent avoir des classes de ressources par taille APK.

## Health checks and probes
Frontend: endpoint HTTP statique. API: `/healthz` pour liveness et `/readyz` pour readiness. Worker: heartbeat Celery ou controle de queue. MinIO/PostgreSQL/Redis: probes natives ou chart.

## Autoscaling assumptions
Frontend et API scalent par CPU/RAM et latence. Workers scalent selon profondeur de queue et temps d'attente. HPA/KEDA sont compatibles mais optionnels pour le MVP.

## Secret management and ConfigMaps
Secrets pour mots de passe, access keys, tokens et cles applicatives. ConfigMaps pour configuration non sensible. Aucun secret ne doit etre commite en clair.
