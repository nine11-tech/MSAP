# Software Requirements Specification - MSAP V1

## Introduction

Ce document specifie les exigences de MSAP - Mobile Security Assessment & Triage Platform. La Version 1 couvre l'analyse statique locale d'APK Android, avec evaluation OWASP MASVS et triage MITRE ATT&CK Mobile.

## Vision

MSAP doit permettre a un auditeur autorise d'importer un APK localement, d'executer une analyse statique, d'obtenir des findings AppSec, des indicateurs suspects de triage, des preuves, des scores et un rapport exploitable.

## Stakeholders

- Etudiant porteur du PFA.
- Encadrant academique.
- Jury.
- Auditeurs securite.
- Institution ou laboratoire utilisant un poste local.

## Functional Requirements

| ID | Requirement | Module | Priority |
|---|---|---|---|
| FR-01 | Creer et gerer des projets d'audit | Project and audit management | High |
| FR-02 | Creer un audit APK autorise | Project and audit management | High |
| FR-03 | Importer un APK localement | APK ingestion | High |
| FR-04 | Valider type, taille et lisibilite du fichier | APK ingestion | High |
| FR-05 | Calculer SHA-256 | APK ingestion | High |
| FR-06 | Extraire les metadonnees APK | Static analysis | High |
| FR-07 | Extraire manifeste, permissions et composants | Static analysis | High |
| FR-08 | Extraire certificat et metadonnees signature | Static analysis | Medium |
| FR-09 | Extraire ressources, chaines, URLs, IPs et domaines | Static analysis | High |
| FR-10 | Inspecter le code decompile lorsque possible | Static analysis | Medium |
| FR-11 | Executer les regles AppSec | AppSec detection | High |
| FR-12 | Executer les regles de triage menace | Threat triage | High |
| FR-13 | Mapper les findings vers OWASP MASVS | MASVS mapping | High |
| FR-14 | Mapper les indicateurs vers MITRE ATT&CK Mobile | ATT&CK Mobile mapping | High |
| FR-15 | Collecter et afficher les preuves | Evidence management | High |
| FR-16 | Gerer les faux positifs et statuts analyste | False-positive handling | Medium |
| FR-17 | Calculer un risk score | Risk scoring | High |
| FR-18 | Calculer un compliance score MASVS | Compliance scoring | Medium |
| FR-19 | Generer un rapport PDF | Reporting | Medium |
| FR-20 | Generer un export JSON | Reporting | Medium |

## Non-Functional Requirements

- Fonctionnement local sans service distant.
- Architecture modulaire par plugins d'analyse.
- Resultats reproductibles.
- Conservation des preuves.
- Interface claire orientee audit et triage.
- Performances suffisantes pour des APK de taille raisonnable sur poste institutionnel.
- Deploiement Docker Compose local.

## Security Requirements

- Les APK ne doivent jamais etre envoyes a un service distant.
- Les chemins de stockage doivent etre controles.
- Les snippets de secrets doivent etre tronques ou masques.
- Les erreurs ne doivent pas exposer de donnees sensibles.
- L'utilisateur doit confirmer que l'analyse est autorisee.
- Les rapports doivent inclure un disclaimer sur les limites du triage.

## Audit and Triage Requirements

- Chaque finding doit etre lie a une regle MASVS.
- Chaque indicateur suspect doit etre lie a une regle de triage.
- Chaque mapping ATT&CK doit etre prudent et non conclusif.
- Chaque element doit disposer d'une preuve et d'un niveau de confiance.
- Les faux positifs doivent pouvoir etre marques par un analyste.

## Reporting Requirements

- Synthese executive.
- Perimetre et limites.
- Score de risque.
- Score de conformite MASVS.
- Synthese ATT&CK Mobile.
- Findings AppSec.
- Indicateurs suspects.
- Preuves et recommandations.
- Export JSON technique.

## Deployment Requirements

- Docker Compose local.
- Volumes pour APK, artefacts et rapports.
- Variables d'environnement documentees.
- Compatibilite Ubuntu WSL.
- Prise en compte ARM64 lorsque possible.
- Aucune dependance a MobSF ou a un emulateur.

## Authorized-Use Constraints

MSAP doit etre utilise uniquement sur des APK pour lesquels l'utilisateur dispose d'une autorisation. La plateforme ne doit pas fournir de fonctions d'exploitation offensive contre des systemes tiers.

## Acceptance Criteria

- Un APK peut etre importe, valide et hashe localement.
- Les artefacts statiques principaux sont extraits.
- Les catalogues MASVS et ATT&CK sont charges et valides.
- Les findings et indicateurs incluent preuve, standard, severite et confiance.
- Les rapports ne presentent pas les indicateurs comme verdict malware.
- Le deploiement local est documente.
