# Non-Functional Design - MSAP Cloud

## Scalability
API, frontend et workers doivent scaler horizontalement. Les workers supportent Kubernetes Jobs ou replicas Celery selon taille et volume des APK.

## Availability
Ingress HTTPS, probes readiness/liveness, retries bornes, statuts persistants et stockage objet separe reduisent l'impact des pannes partielles.

## Security
RBAC applicatif, isolation organisation/projet/audit, Kubernetes Secrets, TLS, NetworkPolicies, buckets MinIO prives, URLs pre-signees courtes, logs rediges et audit logs.

## Object storage
MinIO stocke APK, artefacts, preuves, rapports et exports. PostgreSQL stocke les references et metadonnees. MinIO n'heberge pas l'application.

## Observability
Prometheus/Grafana sont optionnels pour metriques API, queue, workers, Jobs, latence d'analyse, erreurs et taille objets. Les logs ne doivent pas exposer secrets ni APK.

## Compliance and safety
MSAP Cloud reste un outil d'audit autorise. Il ne promet pas de classification malware garantie et ne fournit pas d'exploitation offensive contre des systemes tiers.
