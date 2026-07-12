# Design Non Fonctionnel - MSAP V1

## Security

MSAP doit appliquer une authentification locale, un controle d'acces par projet/audit et une validation stricte des uploads. Les erreurs ne doivent pas exposer de chemins sensibles ou de secrets.

## Confidentiality of APKs

Les APK analyses peuvent etre proprietaires ou sensibles. Ils restent dans des volumes locaux et ne sont jamais transmis a des services distants.

## Local Storage

Les fichiers volumineux sont stockes sur disque local: uploads, artefacts, rapports et exports. PostgreSQL stocke les metadonnees, preuves, mappings et scores.

## Performance Expectations

Le MVP doit traiter des APK de taille raisonnable sur poste institutionnel. Les analyses longues doivent exposer un statut clair.

## Maintainability

Les modules doivent etre separes par responsabilite: ingestion, analyse, normalisation, regles, preuves, scoring, reporting.

## Extensibility

L'architecture par plugins permet d'ajouter de nouveaux analyseurs ou types de regles sans reecrire le pipeline.

## Auditability

Chaque resultat doit pouvoir etre justifie par une preuve, une regle, un standard, un niveau de confiance et un score.

## Traceability

La trace attendue est:

```text
APK -> artefact -> regle -> finding/indicateur -> mapping standard -> score -> rapport
```

## Reliability

Les erreurs partielles d'outils doivent etre gerees sans perdre tout l'audit lorsque les artefacts critiques restent disponibles.

## Error Handling

Les erreurs sont classees: upload invalide, outil indisponible, regle invalide, extraction partielle, generation rapport echouee.

## Logging

Les logs doivent inclure audit ID, etape, duree et statut. Ils ne doivent pas contenir de secrets complets.

## Portability

Le deploiement cible Docker Compose local, avec attention aux environnements Ubuntu WSL et ARM64.

## Usability

L'interface doit etre sobre, lisible et orientee decision d'audit: scores, severites, preuves, recommandations.

## Deployment Constraints

Toute dependance a MobSF est exclue en V1, ainsi que l'emulateur, l'analyse dynamique et les services distants. Les catalogues YAML restent locaux et versionnables.

## Optional AI Non-Functional Requirements - V1.1

- Privacy: AI receives only minimized, redacted post-analysis context.
- Redaction: secrets, tokens, credentials, URLs, domains, emails and personal data are masked before AI calls.
- API key security: Kimi keys are environment-only, never committed and never logged.
- Audit logging: AI requests record purpose, provider, model, context hash, redaction summary, status and reviewer state without secrets.
- Availability fallback: if AI is disabled, offline or failing, MSAP continues in no-AI mode.
- Non-determinism management: AI output is draft text, not a deterministic result.
- Human validation: accepted analyst review is required before report inclusion.
