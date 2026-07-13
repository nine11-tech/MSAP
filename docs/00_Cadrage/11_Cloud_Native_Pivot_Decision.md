# Decision de Pivot Cloud-Native - MSAP

## Raison du pivot
MSAP evolue vers une plateforme cloud-native afin de supporter des usages multi-utilisateurs, des analyses asynchrones, une conservation controlee des artefacts et un deploiement institutionnel reproductible. Le besoin n'est plus seulement d'executer une analyse sur un poste local, mais de fournir une plateforme de security engineering exploitable dans un environnement Kubernetes auto-heberge.

## Ancien positionnement
L'ancien cadrage etait centre sur l'execution locale sur poste institutionnel, l'absence de services distants, Docker Compose comme mode principal, le stockage sur disque local et une analyse statique Android mono-instance. Ce positionnement reste utile pour le developpement local, mais il n'est plus la cible de deploiement principale.

## Nouveau positionnement
MSAP est une plateforme cloud-native d'evaluation de securite mobile et de triage d'APK basee sur OWASP MASVS, MITRE ATT&CK Mobile, MinIO et Kubernetes. Elle reste auto-hebergeable et open-source, avec Kubernetes comme cible de production, MinIO pour les objets, PostgreSQL pour les metadonnees et Redis/Celery pour l'analyse asynchrone.

## Pourquoi Kubernetes
Kubernetes apporte l'isolation par namespace, la scalabilite des workers, la gestion declarative des deploiements, les Secrets, l'Ingress HTTPS, les Jobs d'analyse, les probes de sante et une base compatible GitOps. Ce choix aligne MSAP avec les pratiques DevSecOps institutionnelles sans transformer le projet en simple application web.

## Pourquoi MinIO
MinIO fournit un stockage objet S3-compatible auto-heberge. Il est adapte aux APK, artefacts d'analyse, preuves, rapports et exports, qui ne doivent pas etre stockes comme simples fichiers locaux applicatifs. PostgreSQL conserve les metadonnees, les statuts et les references objet; MinIO conserve les binaires et artefacts volumineux.

## Impacts
- **Scope**: le coeur reste analyse statique Android, MASVS, ATT&CK Mobile, preuves et reporting; l'infrastructure ajoute MinIO, Redis, workers, Kubernetes, Helm et tests de deploiement.
- **Architecture**: User/Auditor -> Ingress TLS -> React Frontend -> Django REST API -> Audit Orchestrator -> Redis Queue -> Analyzer Workers ou Kubernetes Jobs -> Normalization Layer -> MASVS Engine + ATT&CK Triage Engine -> Evidence Engine + Risk Engine -> PostgreSQL -> Report Generator -> MinIO Object Storage.
- **Security**: surface reseau accrue, donc TLS, RBAC, Secrets, NetworkPolicies, policies MinIO, journalisation et retention deviennent obligatoires.
- **Roadmap**: Kubernetes, MinIO, Redis, workers et Helm sont integres des les premieres semaines; Docker Compose devient uniquement un mode de developpement local.

## Risques introduits
Complexite Kubernetes, mauvaise configuration MinIO, exposition d'objets sensibles, fuite de Secrets, limites CPU/RAM insuffisantes, pannes workers, cout d'infrastructure et exposition reseau via Ingress.

## Risques reduits
Reduction de la dependance au disque local applicatif, meilleure scalabilite des analyses longues, deploiement reproductible, separation metadonnees/objets, meilleure compatibilite sauvegarde, monitoring et GitOps.

## Decision finale
MSAP garde officiellement le nom applicatif **MSAP**. Kubernetes est la cible de deploiement, MinIO est le stockage objet, PostgreSQL conserve les metadonnees, Redis/Celery pilote les analyses asynchrones, et Docker Compose est limite au developpement local.
