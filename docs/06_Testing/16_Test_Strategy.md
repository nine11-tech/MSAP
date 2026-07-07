# Test Strategy - MSAP V1

## Test Objectives

Verifier que MSAP analyse localement des APK autorises, produit des preuves fiables, limite les faux positifs et genere des rapports coherents.

## Unit Tests

- Validation YAML.
- Scoring.
- Redaction de secrets.
- Mapping MASVS et ATT&CK.

## Integration Tests

- Upload APK -> extraction -> normalisation.
- Normalisation -> MASVS engine.
- Normalisation -> ATT&CK triage engine.
- Resultats -> reporting.

## Functional Tests

- Creation projet/audit.
- Upload APK.
- Lancement analyse.
- Consultation findings, indicateurs, preuves et scores.
- Telechargement PDF/JSON.

## Static Analysis Validation Tests

Fixtures manifest, permissions, composants, ressources et code snippets.

## Rule Validation Tests

Chaque regle critique doit avoir au moins un cas positif et un cas negatif.

## False Positive Tests

Verifier que des usages legitimes frequents ne sont pas presentes comme verdicts malveillants.

## Report Validation Tests

Le rapport doit inclure perimetre, limites, scores, preuves, recommandations et disclaimer.

## Security Tests

- Upload invalide.
- Path traversal.
- Snippet redaction.
- Controle d'acces projet/audit.

## Deployment Tests

- Docker Compose local.
- Volumes persistants.
- PostgreSQL accessible localement.
- Pas de dependance reseau externe obligatoire.

## Acceptance Criteria

- Tests critiques passent.
- YAML parse correctement.
- Aucun verdict malware garanti.
- Aucun envoi distant d'APK.
