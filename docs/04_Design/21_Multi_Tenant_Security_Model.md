# Modele de Securite Multi-Tenant - MSAP Cloud

## User roles
Admin, Lead Auditor, Auditor et Viewer. Les droits couvrent creation de projets, upload APK, lancement d'analyse, consultation, export, validation et administration.

## Organization/project isolation
Les donnees sont partitionnees par organisation, projet et audit. Chaque requete API verifie appartenance et role. Les objets MinIO utilisent des prefixes `organization/project/audit` pour faciliter controle, retention et audit.

## Audit isolation
Un audit ne doit pas lire les artefacts d'un autre audit. Les workers recoivent des identifiants internes et recuperent les objets autorises. Les resultats sont rattaches a un audit unique.

## RBAC and API authorization
Le RBAC applicatif controle creation, lecture, modification, suppression, export et validation. Les endpoints de telechargement verifient les droits avant de retourner un objet ou une URL pre-signee.

## MinIO bucket/object access model
Buckets prives. Acces direct utilisateur evite par defaut. Policies applicatives separent upload, lecture d'analyse, ecriture de rapports et nettoyage. URLs pre-signees courtes et journalisees.

## Audit logs and data retention
Journaliser login, upload, analyse, acces objet, telechargement rapport, role changes, suppression, URL pre-signee, activation AI et validation analyste. La retention s'applique par organisation aux APK, artefacts, preuves et rapports.

## Threat model summary
Risques: exposition d'APK sensibles, mauvaise isolation projet, fuite de Secrets, URL pre-signee permissive, worker compromis, logs contenant secrets, Ingress/TLS mal configure et confusion triage/verdict. Controles: RBAC, NetworkPolicies, Secrets, redaction, policies MinIO, retention, journalisation et wording prudent.
