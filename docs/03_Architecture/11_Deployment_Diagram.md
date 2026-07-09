# Diagramme de Deploiement Local - MSAP

## Objectif

MSAP V1 cible un deploiement local sur poste institutionnel via Docker Compose. Aucun service distant n'est requis pour l'analyse, le stockage, le reporting ou le triage.

## Contraintes

- Local-first.
- ARM64-friendly lorsque possible.
- Volumes locaux pour APK, artefacts, rapports et exports.
- Catalogues de regles locaux.
- Pas de dependance MobSF, emulateur ou analyse dynamique.

```mermaid
flowchart TB
    subgraph WS[Poste institutionnel local]
        subgraph DC[Docker Compose]
            FE[Frontend container\nReact]
            BE[Backend container\nDjango REST API]
            PG[(PostgreSQL container)]
        end

        subgraph VOL[Volumes locaux]
            UP[APK uploads]
            ART[Artefacts extraits]
            REP[Rapports PDF]
            EXP[Exports JSON]
            RULES[Catalogues rules/*.yaml]
        end

        TOOLS[Outils locaux\nJava / APKTool / JADX / Androguard]
    end

    User[Auditeur] --> FE
    FE --> BE
    BE --> PG
    BE --> UP
    BE --> ART
    BE --> REP
    BE --> EXP
    BE --> RULES
    BE --> TOOLS
```

## Notes de deploiement

Les images Docker et outils doivent etre testes sur l'environnement cible. Si un outil n'est pas disponible en ARM64, il doit etre documente comme optionnel ou remplace par une alternative compatible.
