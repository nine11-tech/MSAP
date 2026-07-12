# Diagramme des Packages et Modules - MSAP

## Objectif

Ce diagramme presente l'organisation logique cible du projet. Les modules sont separes pour maintenir un couplage faible entre interface, API, ingestion APK, analyse, normalisation, regles, preuves, scoring et reporting.

```mermaid
flowchart LR
    FE[frontend]

    subgraph BE[backend]
        ACC[accounts]
        PROJ[projects]
        AUD[audits]
        APK[apk_files]
        AN[analyzers]
        NORM[normalization]
        APP[appsec_rules]
        TRI[triage_rules]
        FIND[findings]
        IND[indicators]
        EVID[evidence]
        SCORE[scoring]
        REP[reports]
        subgraph AI[ai_assistant optional V1.1]
            AICB[context_builder]
            AIR[redaction]
            KCON[kimi_connector]
            AIV[validation_workflow]
        end
    end

    RULES[rules]
    DOCS[docs]

    FE --> AUD
    ACC --> PROJ
    PROJ --> AUD
    AUD --> APK
    AUD --> AN
    AN --> NORM
    NORM --> APP
    NORM --> TRI
    APP --> FIND
    TRI --> IND
    FIND --> EVID
    IND --> EVID
    EVID --> SCORE
    SCORE --> REP
    SCORE -. optional .-> AICB
    EVID -. optional .-> AICB
    AICB --> AIR
    AIR --> KCON
    KCON --> AIV
    AIV -. accepted text .-> REP
    RULES --> APP
    RULES --> TRI
    DOCS -. guide .-> BE
```

## Principes de dependance

- `frontend` consomme uniquement l'API.
- `analyzers` produit des resultats bruts, sans logique MASVS/ATT&CK.
- `normalization` isole les moteurs de regles des formats outils.
- `appsec_rules` et `triage_rules` restent separes.
- `evidence` centralise la preuve pour findings et indicateurs.
- `reports` lit les resultats persistés et ne relance pas l'analyse.
- `ai_assistant` est optionnel V1.1, desactive par defaut, et consomme seulement des resultats post-analyse rediges.
