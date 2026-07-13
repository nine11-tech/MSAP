# Wireframes UI/UX - MSAP V1

## Objectif

Ces wireframes textuels decrivent une interface simple, orientee audit cybersécurité. L'objectif est de soutenir le flux principal: connexion, projet, audit, upload APK, analyse, consultation des resultats, preuves et reporting.

## Login Page

**Purpose**: authentifier un utilisateur local.

**Main components**: formulaire login, message d'erreur, rappel usage autorise.

**Data displayed**: aucun resultat technique.

**User actions**: saisir identifiants, se connecter.

```text
+--------------------------------+
| MSAP                           |
| Mobile Security Assessment     |
| & Triage Platform              |
|                                |
| Username [________________]    |
| Password [________________]    |
| [ Login ]                      |
| Authorized use only            |
+--------------------------------+
```

## Dashboard

**Purpose**: donner une vue globale des audits et risques.

**Main components**: cartes scores, derniers audits, repartition MASVS, synthese ATT&CK.

**Data displayed**: risk score, compliance score, nombre de findings, indicateurs.

**User actions**: ouvrir un audit, creer un projet, filtrer.

```text
+---------------------------------------------------+
| Dashboard                                         |
| Risk Score | Compliance | MASVS Findings | ATT&CK |
| Recent audits                                     |
| - Audit APK A   Completed   High findings: 2      |
| - Audit APK B   Running                           |
+---------------------------------------------------+
```

## Projects Page

**Purpose**: gerer les projets d'audit.

**Main components**: liste projets, bouton creation, nombre d'audits.

**Data displayed**: nom, contexte, date, nombre d'audits.

**User actions**: creer, ouvrir, modifier un projet.

## Audit Detail Page

**Purpose**: centraliser les informations d'un audit.

**Main components**: statut, APK, metadonnees, boutons analyse/rapport, onglets resultats.

**Data displayed**: statut, SHA-256, package, version, scores, resume.

**User actions**: lancer analyse, consulter findings, generer rapport.

```text
+---------------------------------------------------+
| Audit: APK suspect autorise                       |
| Status: Completed    SHA-256: abcd...             |
| [Start Analysis] [Generate PDF] [Export JSON]     |
| Tabs: Overview | Findings | ATT&CK | Evidence     |
+---------------------------------------------------+
```

## APK Upload Page

**Purpose**: importer un APK dans un audit.

**Main components**: zone upload, validation, contraintes, resultat hash.

**Data displayed**: nom fichier, taille, SHA-256 apres upload.

**User actions**: selectionner APK, confirmer usage autorise, envoyer.

## Findings Page

**Purpose**: consulter les faiblesses AppSec mappees OWASP MASVS.

**Main components**: table findings, filtres severite/categorie, detail.

**Data displayed**: rule ID, titre, MASVS category, severite, confiance, statut.

**User actions**: filtrer, ouvrir detail, marquer faux positif.

## ATT&CK Triage Indicators Page

**Purpose**: consulter les indicateurs suspects mappees MITRE ATT&CK Mobile.

**Main components**: table indicateurs, filtres tactique/severite/confiance.

**Data displayed**: indicator ID, tactique, technique, severite, confiance, interpretation.

**User actions**: ouvrir detail, annoter, marquer faux positif.

## Evidence Detail Page

**Purpose**: afficher la preuve qui justifie un finding ou indicateur.

**Main components**: source, fichier, extrait, statut redaction, contexte.

**Data displayed**: artifact type, file path, line, snippet, confidence.

**User actions**: revenir au resultat, copier reference, changer statut analyste.

## Report Page

**Purpose**: generer et telecharger les livrables.

**Main components**: generation PDF, export JSON, historique rapports.

**Data displayed**: format, date, statut, taille.

**User actions**: generer PDF, exporter JSON, telecharger.
