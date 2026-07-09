# Diagramme UML d'Etat - Cycle de Vie d'un Audit

## Objectif

Ce diagramme represente les etats principaux d'un audit MSAP, depuis sa creation jusqu'a son archivage.

## Logique de transition

- Un audit commence en `Draft`.
- Apres upload et validation de l'APK, il passe a `APK Uploaded`.
- Le lancement de l'analyse le place en `Pending Analysis`, puis `Running`.
- Le pipeline progresse vers normalisation, mapping, scoring, puis completion.
- Toute erreur bloquante conduit a `Failed`.
- Un rapport peut etre genere apres completion.
- Un audit termine peut etre archive.

```mermaid
stateDiagram-v2
    [*] --> Draft
    Draft --> APK_Uploaded: APK valide importe
    APK_Uploaded --> Pending_Analysis: Analyse demandee
    Pending_Analysis --> Running: Orchestrateur demarre
    Running --> Normalizing_Results: Extraction terminee
    Normalizing_Results --> Mapping_Standards: Artefacts normalises
    Mapping_Standards --> Scoring: Findings et indicateurs mappes
    Scoring --> Completed: Scores calcules
    Completed --> Report_Generated: Rapport PDF/JSON genere
    Report_Generated --> Archived: Archivage demande
    Completed --> Archived: Archivage sans nouveau rapport

    Draft --> Failed: Erreur creation
    APK_Uploaded --> Failed: APK invalide detecte
    Pending_Analysis --> Failed: Regles invalides
    Running --> Failed: Erreur outil critique
    Normalizing_Results --> Failed: Normalisation impossible
    Mapping_Standards --> Failed: Mapping impossible
    Scoring --> Failed: Scoring impossible
    Failed --> Pending_Analysis: Relance apres correction
```
