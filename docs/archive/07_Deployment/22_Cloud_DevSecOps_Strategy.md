# Strategie Cloud DevSecOps - MSAP

## CI/CD pipeline
Le pipeline cible valide le code, les images et les artefacts Kubernetes avant livraison. Il produit des images versionnees et un chart Helm lintable, sans secrets embarques.

## Pipeline steps
Docker image build pour frontend/API/worker, Trivy scan, unit tests, YAML validation, Helm lint, Kubernetes manifest validation via `helm template`, tests de deploiement sur kind/K3s, publication d'images taguees et chart versionne.

## Future supply chain controls
La signature d'images et la generation SBOM sont des objectifs futurs. Les tags immuables sont preferes, et les images ne doivent pas utiliser `latest` en production.

## Optional GitOps and observability
Argo CD peut synchroniser le chart Helm vers un cluster cible. Prometheus/Grafana peuvent collecter metriques API, workers, queue Redis, latence d'analyse, erreurs, taille objets et etat des Jobs. Les logs ne doivent pas contenir secrets, APK ou extraits sensibles non rediges.
