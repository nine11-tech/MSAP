# Strategie Helm Chart - MSAP

## Helm chart purpose
Le chart Helm est le packaging cible de MSAP. Il rend le deploiement Kubernetes reproductible, configurable et compatible local K3s/kind, self-hosted et cluster institutionnel.

## Chart directory structure
```text
charts/msap/
  Chart.yaml
  values.yaml
  values-dev.yaml
  values-k3s.yaml
  values-prod.example.yaml
  templates/
  README.md
```

## Templates required
Namespace, Deployments frontend/API/worker, Services, Ingress, ConfigMaps, references Secrets, Redis, PostgreSQL optionnel, MinIO optionnel, PVC, Jobs de migration/analyse, CronJob de nettoyage, NetworkPolicies, ServiceAccounts et RBAC minimal.

## values.yaml and environment values
`values.yaml` definit images, tags, replicas, ressources, probes, endpoints, buckets MinIO, hosts Ingress, TLS, retention, monitoring optionnel, AI optionnelle et politiques workers. Les fichiers dev, k3s et prod adaptent ressources, TLS, services embarques ou externes.

Le contrat de reference pour le futur `values.yaml` est defini dans [Helm Values Contract](../04_Design/23_Helm_Values_Contract.md). Les templates Helm devront rester compatibles avec ces sections: `global`, `image`, `frontend`, `backend`, `worker`, `redis`, `postgresql`, `minio`, `ingress`, `tls`, `secrets`, `persistence`, `resources`, `autoscaling`, `securityContext`, `networkPolicy`, `observability`, `aiAssistant` et `analyzerTools`.

## Install/upgrade/rollback workflow
```bash
helm lint charts/msap
helm install msap charts/msap -n msap --create-namespace -f values-dev.yaml
helm upgrade msap charts/msap -n msap -f values-prod.yaml
helm rollback msap <revision> -n msap
```

## Versioning strategy
Le chart suit SemVer. Les versions d'image applicative sont explicites et jamais forcees a `latest` pour une livraison institutionnelle.
