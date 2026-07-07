# Backlog Initial - MSAP

| Epic | Feature | User Story | Priority | Acceptance Criteria |
|---|---|---|---|---|
| Project setup | Structure projet | En tant qu'etudiant, je veux une structure claire afin d'organiser le projet comme une plateforme d'audit. | High | Les dossiers principaux et documents initiaux sont crees. |
| Project setup | Documentation initiale | En tant qu'encadrant, je veux une documentation de cadrage afin de valider le perimetre. | High | La note de cadrage, les exigences et l'architecture sont disponibles. |
| User and audit management | Creation d'audit | En tant qu'auditeur, je veux creer un audit local afin de regrouper les resultats d'une application. | High | Un audit possede un nom, une date, un statut et un APK associe. |
| User and audit management | Historique local | En tant qu'auditeur, je veux consulter les audits precedents afin de comparer les resultats. | Medium | La liste des audits locaux est consultable. |
| APK upload | Depot APK | En tant qu'auditeur, je veux importer un APK afin de lancer une analyse statique. | High | Le fichier est stocke localement et valide comme APK. |
| APK upload | Metadonnees APK | En tant qu'auditeur, je veux voir les metadonnees de base afin d'identifier l'application analysee. | Medium | Le nom de package, la version et le hash sont affiches. |
| Static analysis | Extraction manifeste | En tant qu'auditeur, je veux extraire le manifeste afin d'analyser la configuration Android. | High | Le manifeste est extrait et parse localement. |
| Static analysis | Analyse code decompile | En tant qu'auditeur, je veux inspecter le code decompile afin de rechercher des motifs de risque. | High | Les chaines et motifs cibles sont analysables. |
| Static analysis | Analyse ressources | En tant qu'auditeur, je veux analyser les ressources afin de detecter URLs et secrets potentiels. | Medium | Les ressources textuelles sont parcourues et indexees. |
| MASVS mapping | Catalogue de regles | En tant qu'auditeur, je veux appliquer des regles MASVS afin de structurer les constats. | High | Les regles YAML sont chargees et appliquees. |
| MASVS mapping | Association finding-MASVS | En tant qu'auditeur, je veux relier chaque finding a MASVS afin de faciliter le reporting. | High | Chaque finding contient une categorie MASVS. |
| Risk scoring | Severite initiale | En tant qu'auditeur, je veux une severite par finding afin de prioriser les corrections. | High | Chaque finding possede une severite justifiee. |
| Risk scoring | Score audit | En tant qu'auditeur, je veux un score global indicatif afin de synthetiser l'exposition. | Medium | Un score global est calcule a partir des findings. |
| Report generation | Rapport detaille | En tant qu'auditeur, je veux generer un rapport afin de partager les resultats autorises. | High | Le rapport contient synthese, perimetre, findings, preuves et recommandations. |
| Report generation | Export local | En tant qu'auditeur, je veux exporter le rapport localement afin de l'inclure dans le livrable PFA. | Medium | Un export local est disponible. |
| Dashboard | Vue synthese | En tant qu'auditeur, je veux un tableau de bord afin de voir rapidement les risques principaux. | Medium | Le dashboard affiche nombre de findings, severites et categories MASVS. |
| Dashboard | Filtrage | En tant qu'auditeur, je veux filtrer les findings afin de cibler une categorie ou une severite. | Low | Les resultats sont filtrables par severite et categorie MASVS. |
| Local deployment | Docker local | En tant qu'utilisateur, je veux lancer MSAP localement afin de respecter les contraintes de confidentialite. | Medium | Une configuration Docker locale est documentee. |
| Local deployment | Configuration | En tant qu'utilisateur, je veux configurer les chemins locaux afin de controler le stockage. | Medium | Les chemins APK, rapports et artefacts sont configurables. |
| Testing and documentation | Tests fonctionnels | En tant qu'encadrant, je veux des tests de base afin de verifier le comportement attendu. | High | Les cas principaux d'import, analyse et reporting sont couverts. |
| Testing and documentation | Documentation finale | En tant que jury, je veux une documentation claire afin d'evaluer la demarche d'ingenierie. | High | Les documents de conception, test, deploiement et livraison sont finalises. |
