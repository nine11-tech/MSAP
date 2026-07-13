# Initial Backlog - MSAP Cloud

| Epic | Story | Acceptance criteria | Priority |
|---|---|---|---|
| Cloud architecture | Definir Kubernetes + MinIO + PostgreSQL + Redis | Architecture et diagrammes valides | High |
| APK ingestion | Upload APK securise | APK stocke dans MinIO, hash en PostgreSQL | High |
| Object storage | Gerer ObjectStorageReference | Buckets, object keys et retention documentes | High |
| Async analysis | Traiter un job worker | Redis/Celery ou Kubernetes Job execute l'analyse | High |
| Static analysis | Extraire artefacts Android | Artefacts stockes dans MinIO et normalises | High |
| MASVS | Produire findings AppSec | Findings relies a preuves | High |
| ATT&CK Mobile | Produire triage prudent | Aucun verdict malware garanti | High |
| Reporting | Generer PDF/JSON | Rapports stockes dans MinIO | Medium |
| Deployment | Helm + Kubernetes | Chart installe sur kind/K3s | High |
| Dev mode | Compose developpement | Compose documente comme dev-only | Medium |
