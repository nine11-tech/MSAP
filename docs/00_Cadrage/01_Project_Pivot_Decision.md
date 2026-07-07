# Decision de Pivot Projet - MSAP

## Why the Project Pivoted

Le projet a pivote pour renforcer son positionnement cybersécurité. Une plateforme centree uniquement sur l'audit AppSec risquait d'etre percue comme limitee. L'ajout d'un triage MITRE ATT&CK Mobile apporte une dimension menace, sans elargir le perimetre au-dela de l'analyse statique locale.

## Old Positioning

MSAP - Mobile Security Assessment Platform: plateforme locale d'analyse statique Android basee principalement sur OWASP MASVS.

## New Positioning

MSAP - Mobile Security Assessment & Triage Platform: plateforme locale d'evaluation de securite mobile et de triage d'APK basee sur OWASP MASVS et MITRE ATT&CK Mobile.

## Benefits of the New Hybrid Approach

- Meilleur alignement avec security engineering.
- Couverture AppSec et threat triage.
- Rapports plus riches.
- Meilleure valeur pedagogique.
- Architecture plus professionnelle.

## Impact on Scope

Le perimetre reste Android APK statique local. Le pivot ajoute un moteur de triage et un catalogue d'indicateurs, sans ajouter analyse dynamique, sandbox ou verdict malware.

## Impact on Architecture

Ajout de:

- Analyzer Plugin Manager.
- Normalization Layer.
- ATT&CK Triage Engine.
- TriageRule et SuspiciousIndicator.
- Scores triage et compliance.

## Impact on Deliverables

La documentation doit inclure methodologie ATT&CK, modele de scoring, modele de preuve, API triage, schemas de regles et rapports hybrides.

## Risks Introduced

- Confusion entre indicateur et verdict.
- Faux positifs de triage.
- Complexite documentaire accrue.

## Risks Reduced

- Risque de projet trop "web app".
- Risque de valeur cybersécurité insuffisante.
- Risque d'architecture peu extensible.

## Final Decision

Le projet adopte officiellement le positionnement hybride MASVS + MITRE ATT&CK Mobile, en conservant une Version 1 locale, statique et realiste.
