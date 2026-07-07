# Project Charter - MSAP

## Project Name

MSAP - Mobile Security Assessment & Triage Platform

## Sponsor / Academic Context

Placeholder: encadrant academique, institution, filiere et annee universitaire.

## Purpose

Concevoir une plateforme locale d'audit AppSec mobile et de triage d'APK pour un PFA d'ingenierie cybersécurité.

## Objectives

- Analyser statiquement des APK Android.
- Mapper les findings vers OWASP MASVS.
- Mapper les indicateurs suspects vers MITRE ATT&CK Mobile.
- Produire preuves, scores, rapport PDF et export JSON.

## Scope

Android APK, analyse statique locale, ingestion, extraction, detection, scoring, reporting, Docker Compose.

## Out of Scope

Toute dependance a MobSF, Frida, emulateur, analyse dynamique, sandbox malware, verdict malware garanti, iOS et exploitation offensive.

## Stakeholders

- Etudiant.
- Encadrant.
- Jury.
- Auditeur utilisateur.
- Institution hebergeant le poste local.

## Constraints

- Duree PFA de deux mois.
- Aucun service distant.
- Confidentialite des APK.
- Compatibilite locale et ARM64-friendly lorsque possible.

## Assumptions

- Les APK analyses sont autorises.
- Les outils Android locaux sont disponibles ou installables.
- Le MVP privilegie la qualite des preuves et du design.

## Risks

- Faux positifs.
- Limites statiques.
- Contraintes outils.
- Confusion triage/verdict.

## Success Criteria

- Pipeline local demonstrable.
- Regles MASVS et ATT&CK chargees.
- Findings et indicateurs avec preuves.
- Rapport PDF/JSON.
- Documentation coherente.

## Deliverables

Documentation, catalogues YAML, code MVP, tests, Docker Compose, rapport final et demo.

## Approval Section

| Role | Name | Signature | Date |
|---|---|---|---|
| Student | TBD | TBD | TBD |
| Supervisor | TBD | TBD | TBD |
| Academic Reviewer | TBD | TBD | TBD |
