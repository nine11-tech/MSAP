# MVP Implementation Plan - MSAP V1

## Objective

Construire un MVP local, realiste pour un PFA de deux mois, couvrant ingestion APK, analyse statique, MASVS AppSec, ATT&CK Mobile triage, evidence, scoring, reporting et dashboard.

## Milestones

| Milestone | Goal | Tasks | Expected Output | Acceptance Criteria |
|---|---|---|---|---|
| Backend foundation | Socle API local. | Initialiser Django REST, settings, erreurs, logs. | Backend demarrable. | Aucun service distant requis. |
| Database models | Schema persistant. | Creer modeles audit, APK, artefacts, findings, indicators, scores, reports. | Migrations coherentes. | Relations principales testees. |
| APK ingestion | Depot local controle. | Upload, validation, stockage, SHA-256. | APKFile persiste. | APK valide accepte, invalide rejete. |
| Analyzer plugin architecture | Adaptateurs extensibles. | Interface plugin, APKTool/JADX/Androguard/Regex placeholders. | Plugin manager. | Plugin failures controles. |
| Normalization layer | Schema commun. | Transformer raw results en NormalizedArtifact. | Artefacts normalises. | MASVS et ATT&CK consomment le meme schema. |
| Static analysis MVP | Extraction de base. | Manifest, permissions, components, strings, signatures. | Resultats bruts et normalises. | Artefacts critiques disponibles. |
| MASVS rule engine | Findings AppSec. | Loader YAML, validation, execution regles initiales. | Findings MASVS. | 14 regles chargees et executables progressivement. |
| ATT&CK triage engine | Indicateurs suspects. | Loader YAML triage, detection indicateurs, mapping techniques. | SuspiciousIndicators. | Wording non conclusif et confiance presente. |
| Evidence engine | Tracabilite. | Creer preuves, redaction, liens artefacts/regles. | Evidence persistée. | Chaque resultat a au moins une preuve. |
| Risk and compliance scoring | Priorisation. | Risk score, MASVS compliance, ATT&CK triage score. | Scores affichables. | Calculs reproductibles. |
| Reporting | PDF et JSON. | Templates, generation locale, telechargement. | Rapport et export. | Rapport contient limites et disclaimers. |
| Frontend dashboard | UI audit. | Pages projets, audits, upload, resultats, scores. | Dashboard MVP. | Flux principal utilisable. |
| Testing | Validation. | Tests loader, upload, rules, scoring, report. | Suite de tests initiale. | Cas critiques couverts. |
| Docker deployment | Deploiement local. | Compose, volumes, variables, docs. | Environnement local. | Donnees restent sur machine. |

## Priorisation

1. Backend, modele de donnees, ingestion.
2. Normalisation et extraction manifeste.
3. MASVS + ATT&CK rule loaders.
4. Premieres detections et preuves.
5. Scoring, reporting, dashboard.
6. Tests, Docker, livraison.
