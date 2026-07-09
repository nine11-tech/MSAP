# WBS - Work Breakdown Structure MSAP

## 1.0 Project Management

- 1.1 Definir le perimetre PFA.
- 1.2 Planifier les 8 semaines.
- 1.3 Suivre les risques.
- 1.4 Organiser les revues avec encadrants.
- 1.5 Preparer les jalons de livraison.

## 2.0 Requirements Engineering

- 2.1 Rediger le cahier des charges.
- 2.2 Formaliser les exigences fonctionnelles.
- 2.3 Formaliser les exigences non fonctionnelles.
- 2.4 Construire la matrice de tracabilite.
- 2.5 Valider les contraintes V1.

## 3.0 Security Analysis and Methodology

- 3.1 Definir la methodologie OWASP MASVS.
- 3.2 Definir la methodologie MITRE ATT&CK Mobile.
- 3.3 Definir le modele de preuve.
- 3.4 Definir le scoring risque et conformite.
- 3.5 Documenter les limites de l'analyse statique.

## 4.0 Architecture and Design

- 4.1 Definir l'architecture logique.
- 4.2 Definir le modele de donnees.
- 4.3 Definir le pipeline d'analyse.
- 4.4 Definir l'API REST.
- 4.5 Produire les diagrammes UML.
- 4.6 Rediger les ADR.

## 5.0 Backend Implementation

- 5.1 Initialiser le backend.
- 5.2 Implementer les modeles.
- 5.3 Implementer les endpoints projets/audits.
- 5.4 Implementer l'ingestion APK.
- 5.5 Implementer les services de scoring et reporting.

## 6.0 Frontend Implementation

- 6.1 Initialiser le frontend.
- 6.2 Implementer l'authentification.
- 6.3 Implementer pages projets/audits.
- 6.4 Implementer dashboard.
- 6.5 Implementer vues findings, indicateurs et preuves.

## 7.0 Static Analysis Engine

- 7.1 Definir le contrat plugin.
- 7.2 Integrer APKTool adapter.
- 7.3 Integrer JADX adapter.
- 7.4 Integrer Androguard adapter.
- 7.5 Integrer regex/YARA optionnel.
- 7.6 Normaliser les artefacts.

## 8.0 MASVS and ATT&CK Engines

- 8.1 Charger et valider `masvs_static_rules.yaml`.
- 8.2 Charger et valider `attck_mobile_triage_rules.yaml`.
- 8.3 Executer les regles MASVS.
- 8.4 Executer les regles ATT&CK triage.
- 8.5 Gerer faux positifs et statuts analyste.

## 9.0 Reporting

- 9.1 Definir le template PDF.
- 9.2 Generer le rapport PDF.
- 9.3 Generer l'export JSON.
- 9.4 Integrer les disclaimers.
- 9.5 Valider la lisibilite du rapport.

## 10.0 Testing and Validation

- 10.1 Tests unitaires.
- 10.2 Tests integration.
- 10.3 Tests regles.
- 10.4 Tests faux positifs.
- 10.5 Tests de deploiement.
- 10.6 Tests d'acceptation.

## 11.0 Deployment

- 11.1 Preparer Docker Compose.
- 11.2 Configurer volumes locaux.
- 11.3 Configurer variables d'environnement.
- 11.4 Tester poste institutionnel.
- 11.5 Documenter contraintes ARM64.

## 12.0 Documentation and Delivery

- 12.1 Finaliser documentation.
- 12.2 Preparer scenario demo.
- 12.3 Preparer livrables.
- 12.4 Revue finale.
- 12.5 Soutenance et livraison.
