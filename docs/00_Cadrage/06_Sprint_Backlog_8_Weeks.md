# Sprint Backlog 8 Semaines - MSAP

## Sprint 1 - Cadrage & exigences

**Sprint goal**: valider le positionnement hybride et le cahier des charges.

**User stories**: en tant qu'encadrant, je veux comprendre le perimetre et les contraintes.

**Technical tasks**: structure documentaire, requirements, traceability matrix.

**Security tasks**: definir MASVS + ATT&CK Mobile, exclusions V1.

**Documentation tasks**: cadrage, cahier des charges, project charter.

**Expected deliverables**: documents de cadrage et exigences.

**Acceptance criteria**: scope V1 clair, exclusions explicites.

## Sprint 2 - Architecture & design

**Sprint goal**: finaliser l'architecture avant code.

**User stories**: en tant qu'auditeur, je veux une architecture locale et tracable.

**Technical tasks**: modele donnees, API, pipeline, UML.

**Security tasks**: evidence model, scoring model, regles.

**Documentation tasks**: architecture, design, ADR.

**Expected deliverables**: architecture validee.

**Acceptance criteria**: diagrams lisibles, modules coherents.

## Sprint 3 - Socle backend/frontend

**Sprint goal**: preparer le socle technique.

**User stories**: en tant qu'utilisateur, je veux me connecter et creer un audit.

**Technical tasks**: backend foundation, frontend foundation, DB.

**Security tasks**: auth locale, controle acces.

**Documentation tasks**: setup guide actualise.

**Expected deliverables**: socle local operationnel.

**Acceptance criteria**: aucune dependance distante.

## Sprint 4 - Analyse APK locale

**Sprint goal**: extraire les premiers artefacts APK.

**User stories**: en tant qu'auditeur, je veux uploader un APK et obtenir SHA-256.

**Technical tasks**: upload, validation, hash, manifest parser, normalization.

**Security tasks**: stockage local, redaction.

**Documentation tasks**: guide analyzers.

**Expected deliverables**: extraction locale fonctionnelle.

**Acceptance criteria**: manifest et permissions exploitables.

## Sprint 5 - Detections AppSec

**Sprint goal**: produire les premiers findings MASVS.

**User stories**: en tant qu'auditeur, je veux voir les faiblesses AppSec.

**Technical tasks**: loader MASVS, rule execution, findings.

**Security tasks**: preuves et recommandations.

**Documentation tasks**: tests de regles.

**Expected deliverables**: findings MASVS initiaux.

**Acceptance criteria**: au moins plusieurs regles MASVS fonctionnent.

## Sprint 6 - MASVS + ATT&CK engines

**Sprint goal**: ajouter le triage ATT&CK et les scores.

**User stories**: en tant qu'analyste, je veux consulter des indicateurs suspects non conclusifs.

**Technical tasks**: loader triage, indicators, mapping, scoring.

**Security tasks**: wording prudent, gestion faux positifs.

**Documentation tasks**: scoring et triage actualises.

**Expected deliverables**: moteurs MASVS + ATT&CK operationnels.

**Acceptance criteria**: indicateurs avec preuves et confiance.

## Sprint 7 - Dashboard & reporting

**Sprint goal**: rendre les resultats exploitables.

**User stories**: en tant qu'auditeur, je veux un dashboard et un rapport.

**Technical tasks**: dashboard, PDF, JSON export.

**Security tasks**: redaction secrets, disclaimer.

**Documentation tasks**: demo scenario.

**Expected deliverables**: rapport PDF et export JSON.

**Acceptance criteria**: rapport genere localement.

## Sprint 8 - Qualite & livraison

**Sprint goal**: stabiliser et livrer.

**User stories**: en tant que jury, je veux une demo claire et des livrables complets.

**Technical tasks**: tests, Docker Compose, fixes.

**Security tasks**: verification exclusions V1, confidentialite.

**Documentation tasks**: delivery checklist, final index.

**Expected deliverables**: version candidate et package final.

**Acceptance criteria**: demo reproductible, documentation complete.
