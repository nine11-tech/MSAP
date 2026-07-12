# Project Setup Guide - MSAP V1

## Environment Target

- Ubuntu WSL ou Linux local.
- Poste institutionnel.
- Developpement local-first.
- ARM64-friendly lorsque possible.

## Constraints

- Pas de dependance MobSF.
- Pas de dependance Android Emulator.
- Pas de service distant obligatoire.
- Pas d'analyse dynamique en V1.

## Planned Tools

- Python.
- Django REST Framework.
- PostgreSQL.
- Node.js et React.
- Docker et Docker Compose.
- Java.
- apktool.
- JADX.
- Androguard.
- Regex custom.
- YARA optionnel selon disponibilite.

## ARM64 Considerations

- Verifier la disponibilite des images Docker.
- Preferer des dependances Python compatibles.
- Documenter les outils Java multiplateformes.
- Garder YARA optionnel si la compilation locale est bloquante.

## Local-First Development

Les APK, artefacts et rapports doivent rester dans des volumes locaux. Les tests doivent utiliser des APK ou fixtures autorises.

## Setup Phases

1. Installer les pre-requis systeme.
2. Creer environnements backend/frontend.
3. Configurer PostgreSQL local.
4. Ajouter outils Android.
5. Configurer volumes locaux.
6. Lancer tests de validation.

## Optional AI Environment Variables - V1.1

These variables are documented for the future optional Kimi AI assistant. They are disabled by default and are not required for V1 setup.

```env
AI_ASSISTANT_ENABLED=false
AI_PROVIDER=kimi
KIMI_API_KEY=
KIMI_MODEL=
AI_REDACTION_ENABLED=true
AI_MAX_FINDINGS_CONTEXT=
AI_TIMEOUT_SECONDS=
```

Real API keys must not be committed to Git or logged. Enabling external AI requires institutional approval.
