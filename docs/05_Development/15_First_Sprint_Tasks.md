# First Sprint Tasks - MSAP

## Sprint Goal

Preparer le socle de developpement MVP sans chercher a couvrir tout le pipeline.

## Tasks

| Task | Output | Acceptance Criteria |
|---|---|---|
| Project setup | Structure backend/frontend prete a scaffolder | Pas de dependance distante obligatoire |
| Backend foundation | Projet Django REST initialise lors du sprint code | API healthcheck locale |
| Rules loading | Loader YAML MASVS + ATT&CK | Les deux fichiers YAML parse et valident |
| First MASVS rule | `MSAP-AND-001` executable | Detecte `android:debuggable=true` dans fixture |
| First ATT&CK triage rule | `MSAP-MOB-001` executable | Detecte permission SMS dans fixture |
| Normalization schema | Modele interne minimal | Manifest attributes et permissions normalises |
| APK upload placeholder | Endpoint upload minimal | APK stocke localement avec SHA-256 |
| First manifest parser placeholder | Extraction manifest basique | Fixture manifest exploitable |
| First tests | Tests unitaires initiaux | Loader, upload et deux regles couverts |

## Definition of Done

- Tests critiques passent localement.
- Aucune integration MobSF, emulateur ou dynamique.
- Les resultats restent locaux.
- Le wording triage reste non conclusif.
