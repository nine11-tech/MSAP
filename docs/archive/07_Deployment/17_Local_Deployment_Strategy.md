# Local Development Deployment Strategy - MSAP

## Purpose
Docker Compose is retained only for local development, fast integration checks and developer onboarding. It is not the primary deployment target.

## Local development stack
A development Compose file may run API, frontend, PostgreSQL, Redis, MinIO and a worker with reduced resources. This mode helps validate API flows before Kubernetes packaging.

## Target deployment
Kubernetes is the target deployment platform for MSAP. Production-like validation must use kind, K3s, self-hosted Kubernetes or an institutional cluster with Helm.

## Boundaries
Local Compose must not define the security posture of the product. Ingress TLS, Kubernetes Secrets, NetworkPolicies, PVC, Jobs and Helm rollback are validated in Kubernetes-specific documentation and tests.
