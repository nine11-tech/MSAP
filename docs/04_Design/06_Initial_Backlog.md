# Backlog Initial - MSAP V1

| Epic | Feature | User Story | Priority | Acceptance Criteria |
|---|---|---|---|---|
| Project setup | Structure et documentation | En tant qu'etudiant, je veux une base projet claire afin de presenter une demarche d'ingenierie cybersécurité. | High | Les dossiers, documents et catalogues de regles existent. |
| User and audit management | Gestion projets/audits | En tant qu'auditeur, je veux organiser les APK par projet et audit. | High | Un projet contient plusieurs audits avec statut. |
| APK ingestion | Upload local | En tant qu'auditeur, je veux importer un APK sans l'envoyer a un service distant. | High | L'APK est valide, stocke localement et hashe SHA-256. |
| Static analysis | Extraction artefacts | En tant qu'auditeur, je veux extraire manifeste, permissions, signatures, ressources et code lorsque possible. | High | Les artefacts principaux sont disponibles pour analyse. |
| Normalization layer | Schema interne | En tant que developpeur, je veux normaliser les resultats bruts afin d'executer plusieurs moteurs. | High | Les artefacts normalises sont persistables et exploitables. |
| AppSec detection | Regles MASVS | En tant qu'auditeur, je veux detecter des faiblesses AppSec. | High | Les regles MASVS initiales produisent des findings. |
| Threat triage | Indicateurs suspects | En tant qu'analyste, je veux voir des indicateurs suspects sans verdict automatique. | High | Les indicateurs sont affiches avec confiance et interpretation prudente. |
| MASVS mapping | Categories MASVS | En tant qu'auditeur, je veux mapper les findings vers OWASP MASVS. | High | Chaque finding possede une categorie MASVS. |
| ATT&CK Mobile mapping | Tactiques et techniques | En tant qu'analyste, je veux mapper les indicateurs vers MITRE ATT&CK Mobile. | High | Chaque indicateur applicable contient tactique et technique. |
| Risk and compliance scoring | Scores | En tant qu'auditeur, je veux prioriser les resultats et mesurer la conformite indicative. | High | Risk score et compliance score sont calcules. |
| Evidence management | Preuves | En tant qu'auditeur, je veux consulter les preuves de chaque resultat. | High | Chaque finding/indicateur a une preuve sourcee et tronquee si sensible. |
| Report generation | PDF et JSON | En tant qu'auditeur, je veux exporter un rapport et un JSON technique. | Medium | PDF et JSON sont generables localement. |
| Dashboard | Vue audit | En tant qu'utilisateur, je veux un dashboard AppSec + triage. | Medium | La synthese affiche severites, MASVS, ATT&CK et scores. |
| Local deployment | Docker Compose | En tant qu'institution, je veux deployer MSAP localement. | Medium | Le deploiement local est documente et sans service distant. |
| Testing and validation | Tests regles | En tant qu'encadrant, je veux verifier les detections et faux positifs. | High | Tests unitaires, integration et validation regles sont definis. |
| Documentation and delivery | Livrables PFA | En tant que jury, je veux des livrables coherents et verifiables. | High | Documentation, demo et checklist finale sont disponibles. |
