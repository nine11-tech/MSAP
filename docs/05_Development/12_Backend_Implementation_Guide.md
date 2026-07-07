# Backend Implementation Guide - MSAP V1

## Objectif

Ce guide prepare l'implementation backend Django REST sans generer encore de code. Il definit les modules applicatifs et leurs responsabilites.

## Backend Modules

### accounts

Gestion des utilisateurs locaux, roles, authentification et permissions.

### projects

Gestion des projets, contexte d'audit et controle d'acces.

### audits

Gestion du cycle de vie d'un audit: creation, statut, lancement analyse, synthese.

### apk_files

Upload, validation, stockage local, hash SHA-256 et metadonnees APK.

### analyzers

Gestionnaire de plugins et adaptateurs APKTool, JADX, Androguard, regex/YARA.

### normalization

Transformation des resultats bruts en artefacts internes communs.

### appsec_rules

Chargement, validation et execution des regles OWASP MASVS.

### triage_rules

Chargement, validation et execution des regles MITRE ATT&CK Mobile.

### findings

Gestion des findings AppSec, statuts analyste et mapping MASVS.

### indicators

Gestion des indicateurs suspects, mapping ATT&CK, confiance et interpretation.

### evidence

Creation, redaction, stockage et consultation des preuves.

### scoring

Risk score, compliance score MASVS et triage score.

### reports

Generation PDF, export JSON et telechargement local.

## Service Boundaries

- Les vues API appellent des services applicatifs.
- Les services d'analyse ne doivent pas connaitre le frontend.
- Les moteurs de regles consomment uniquement des artefacts normalises.
- Les rapports consomment les donnees persistées et non les fichiers bruts directement.

## Implementation Order

1. accounts, projects, audits.
2. apk_files.
3. analyzers et normalization.
4. appsec_rules et triage_rules.
5. findings, indicators, evidence.
6. scoring.
7. reports.
