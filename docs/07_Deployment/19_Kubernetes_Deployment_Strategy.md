# Strategie de Deploiement Kubernetes - MSAP

## Target deployment modes
- **Local development with Docker Compose**: iteration rapide, non cible production.
- **Local Kubernetes with kind or K3s**: validation des manifests, Ingress, Secrets, MinIO et workers.
- **Self-hosted Kubernetes**: deploiement open-source controle par l'equipe.
- **Institutional Kubernetes cluster**: cible de production avec politiques reseau, TLS, sauvegarde et observabilite.

## Installation workflow
Prerequis: cluster Kubernetes, kubectl, Helm, Ingress Controller, classe de stockage, certificats TLS, registre d'images, credentials PostgreSQL/MinIO et politique de sauvegarde. Creer le namespace `msap`, creer les Secrets, deployer ou connecter PostgreSQL, MinIO et Redis, installer MSAP via Helm, executer migrations et checks de sante.

## Setup details
- **Namespace setup**: `kubectl create namespace msap` ou via Helm.
- **Secrets setup**: Django secret, DB password, MinIO access/secret keys, Redis auth si activee, Kimi optionnel.
- **MinIO setup**: endpoint prive, buckets, policies minimales, TLS selon environnement.
- **PostgreSQL setup**: base, utilisateur, migrations, sauvegarde.
- **Application deployment**: Helm install/upgrade avec values par environnement.

## Validation commands
```bash
kubectl get pods -n msap
kubectl get svc -n msap
kubectl get ingress -n msap
kubectl logs -n msap deploy/backend-api
kubectl logs -n msap deploy/worker
helm status msap -n msap
```

## Rollback strategy
Utiliser `helm rollback msap <revision> -n msap`. Les migrations doivent etre compatibles rollback ou documentees comme irreversibles. Les objets MinIO ne doivent pas etre supprimes automatiquement pendant un rollback applicatif.
