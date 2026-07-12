# Scenario de Demonstration Finale - MSAP

## Demo Objective

Demontrer que MSAP est une plateforme locale d'evaluation de securite mobile et de triage d'APK, orientee preuves, standards et reporting.

## Demo Environment

- Poste local ou WSL.
- Docker Compose.
- Backend Django REST.
- Frontend React.
- PostgreSQL local.
- Catalogues YAML locaux.

## Test APK Assumptions

L'APK de demonstration doit etre autorise. Il peut etre une application de test ou une fixture construite pour declencher certains findings et indicateurs.

## Steps

1. Login.
2. Create project.
3. Create audit.
4. Upload APK.
5. Launch analysis.
6. View dashboard.
7. Inspect MASVS finding.
8. Inspect ATT&CK triage indicator.
9. View evidence.
10. Generate PDF report.
11. Export JSON.

## Expected Results

- APK valide et SHA-256 calcule.
- Metadonnees APK visibles.
- Findings MASVS affiches avec severite et preuve.
- Indicateurs ATT&CK affiches avec confiance et interpretation prudente.
- Risk score et compliance summary visibles.
- Rapport PDF et export JSON generes localement.

## Optional AI Demo Section - V1.1

This section is optional and should be shown only if Kimi AI is explicitly enabled and institutionally approved.

1. Generate an AI executive summary from deterministic results.
2. Explain one existing MASVS finding using its evidence IDs.
3. Contextualize one existing ATT&CK Mobile indicator with cautious wording.
4. Show analyst validation: draft, accepted or rejected.
5. Confirm that no raw APK, full decompiled source or malware verdict is sent or produced.

## What to Say During Demo

- MSAP est un projet d'ingenierie cybersécurité, pas une simple application web.
- L'analyse est locale et statique en Version 1.
- OWASP MASVS couvre l'evaluation AppSec.
- MITRE ATT&CK Mobile soutient le triage d'indicateurs suspects.
- Les indicateurs ne constituent pas une classification definitive malware/benin.
- Les preuves assurent la tracabilite et la qualite du rapport.
- L'assistance AI, si activee, reste optionnelle, redigee et validee par un analyste.
