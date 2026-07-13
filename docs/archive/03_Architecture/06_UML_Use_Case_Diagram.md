# Diagramme UML des Cas d'Utilisation - MSAP

## Vue d'ensemble

Cette vue presente les interactions principales entre les acteurs et la plateforme MSAP. Elle reste volontairement simple afin de clarifier le perimetre fonctionnel de la Version 1: analyse statique locale d'APK Android, evaluation OWASP MASVS, triage MITRE ATT&CK Mobile, preuves, scoring et reporting.

## Acteurs

- **Auditeur securite**: utilisateur principal qui cree les audits, importe les APK et consulte les resultats.
- **Administrateur**: gere les utilisateurs, les projets et les catalogues de regles.
- **Moteur d'analyse MSAP**: composant systeme qui execute le pipeline d'analyse, la normalisation, les mappings et le scoring.

## Cas d'utilisation principaux

- S'authentifier.
- Gerer les projets.
- Creer un audit.
- Importer un APK.
- Lancer une analyse statique.
- Consulter les findings AppSec.
- Consulter les indicateurs de triage ATT&CK Mobile.
- Consulter les preuves.
- Consulter les scores.
- Generer un rapport PDF.
- Exporter les resultats JSON.
- Administrer les regles.

## Diagramme

```mermaid
flowchart LR
    Auditor[Auditeur securite]
    Admin[Administrateur]
    Engine[Moteur d'analyse MSAP]

    subgraph MSAP[MSAP - Cas d'utilisation V1]
        UC1[S'authentifier]
        UC2[Gerer les projets]
        UC3[Creer un audit]
        UC4[Importer un APK]
        UC5[Lancer une analyse statique]
        UC6[Consulter les findings AppSec]
        UC7[Consulter les indicateurs ATT&CK Mobile]
        UC8[Consulter les preuves]
        UC9[Consulter les scores]
        UC10[Generer un rapport PDF]
        UC11[Exporter les resultats JSON]
        UC12[Administrer les regles]
        UC13[Executer extraction statique]
        UC14[Executer mappings MASVS et ATT&CK]
        UC15[Calculer scores]
    end

    Auditor --> UC1
    Auditor --> UC2
    Auditor --> UC3
    Auditor --> UC4
    Auditor --> UC5
    Auditor --> UC6
    Auditor --> UC7
    Auditor --> UC8
    Auditor --> UC9
    Auditor --> UC10
    Auditor --> UC11

    Admin --> UC1
    Admin --> UC2
    Admin --> UC12

    UC5 --> Engine
    Engine --> UC13
    Engine --> UC14
    Engine --> UC15
```
