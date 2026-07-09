# Diagramme UML d'Activite - Workflow APK MSAP

## Objectif

Ce diagramme decrit le workflow complet d'evaluation statique et de triage d'un APK Android dans MSAP V1, avec les principaux chemins d'erreur.

```mermaid
flowchart TD
    A([Debut]) --> B[Connexion utilisateur]
    B --> C[Selection du projet]
    C --> D[Creation de l'audit]
    D --> E[Upload APK]
    E --> F{APK valide ?}
    F -- Non --> F1[Rejeter APK et afficher erreur]
    F1 --> Z([Fin en erreur])
    F -- Oui --> G[Calcul SHA-256]
    G --> H[Extraction statique]
    H --> H1{Erreur outil ?}
    H1 -- Oui --> H2[Journaliser erreur outil]
    H2 --> H3{Artefacts critiques disponibles ?}
    H3 -- Non --> Z
    H3 -- Oui --> I[Normalisation partielle]
    H1 -- Non --> I[Normalisation]
    I --> J[Validation catalogues de regles]
    J --> J1{Regles valides ?}
    J1 -- Non --> J2[Arreter analyse et signaler erreur regles]
    J2 --> Z
    J1 -- Oui --> K[Execution regles MASVS]
    K --> L[Execution regles ATT&CK triage]
    L --> M[Collecte des preuves]
    M --> N[Scoring risque et conformite]
    N --> O[Persistance des resultats]
    O --> P[Visualisation dashboard]
    P --> Q[Generation rapport PDF / export JSON]
    Q --> R([Fin completed])
```
