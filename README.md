# MSAP - Mobile Security Assessment & Triage Platform

**Sous-titre**: Plateforme locale d'evaluation de securite mobile et de triage d'APK basee sur OWASP MASVS et MITRE ATT&CK Mobile.

## Executive Summary

MSAP est un projet d'ingenierie cybersécurité visant a fournir une plateforme locale d'audit applicatif mobile et de triage d'APK. La Version 1 se concentre sur l'analyse statique Android afin d'identifier des faiblesses AppSec, des indicateurs suspects et des preuves techniques exploitables dans un rapport d'audit.

La plateforme combine deux angles complementaires:

- **OWASP MASVS** pour l'evaluation de securite applicative mobile.
- **MITRE ATT&CK Mobile** pour le triage oriente menace d'indicateurs observables dans un APK.

MSAP ne fournit pas un verdict garanti malware/benin. Les indicateurs ATT&CK Mobile servent a soutenir une revue analyste.

## Optional Kimi AI Extension

Kimi AI is documented as an optional V1.1 extension for AI-assisted triage and audit reporting. It is not part of the deterministic V1 core, is disabled by default, and is not required for MSAP to work.

The AI layer may draft executive summaries, explain existing MASVS findings, contextualize existing ATT&CK Mobile indicators, suggest remediation wording and improve report readability. It does not process raw APK files, does not receive full decompiled source code, does not replace deterministic rules or scores, and does not generate guaranteed malware or benign verdicts. All AI-generated text requires analyst validation before final report inclusion.

## Problem Statement

Les equipes academiques et institutionnelles ont besoin d'un environnement local pour analyser des APK sans exposer les fichiers a des services distants. Les outils existants peuvent etre puissants, mais ils sont parfois trop larges, dependants de plateformes externes ou insuffisamment adaptes a une demarche structuree autour de preuves, scoring, conformite et triage.

MSAP repond a ce besoin en proposant une architecture locale, modulaire et documentee pour conduire une analyse statique Android reproductible.

## Positionnement Cybersécurité

MSAP est positionne comme une plateforme de security engineering, pas comme un simple projet web. Les priorites sont:

- audit applicatif mobile;
- analyse statique Android;
- triage d'APK suspects;
- evidence-based audit;
- mapping OWASP MASVS;
- mapping MITRE ATT&CK Mobile;
- risk scoring et compliance scoring;
- deploiement local sur poste institutionnel.

## Perimetre Version 1

- Android APK uniquement.
- Analyse statique uniquement.
- Analyse locale sans service distant.
- Upload et validation d'APK.
- Calcul SHA-256.
- Extraction des metadonnees APK.
- Analyse `AndroidManifest.xml`.
- Extraction des permissions.
- Detection des composants exportes.
- Extraction des metadonnees certificat et signature.
- Extraction des ressources, chaines, URLs, IPs, domaines et secrets potentiels.
- Inspection du code decompile lorsque possible.
- Findings AppSec mappes OWASP MASVS.
- Indicateurs suspects mappes MITRE ATT&CK Mobile lorsque applicable.
- Evidence, risk score, compliance score.
- Rapport PDF et export JSON.
- Deploiement Docker Compose local.

## Hors Perimetre V1

- Toute dependance a MobSF.
- Frida.
- Android Emulator.
- Analyse dynamique.
- Malware sandbox.
- Classification garantie malware/benin.
- Support iOS/IPA.
- Exploitation offensive ou tests intrusifs contre des systemes tiers.

## Approche Hybride

### OWASP MASVS

Le moteur MASVS structure les constats de securite applicative: stockage, reseau, crypto, plateforme, code, confidentialite, authentification et resilience.

### MITRE ATT&CK Mobile

Le moteur ATT&CK Triage mappe certains indicateurs statiques vers des tactiques et techniques mobiles. Ces indicateurs peuvent appuyer une priorisation analyste, mais ne constituent pas une preuve definitive de malveillance.

## Architecture Overview

```mermaid
flowchart LR
    Auditor[Auditeur] --> Frontend[React Frontend]
    Frontend --> API[Django REST API]
    API --> Orchestrator[Audit Orchestrator]
    Orchestrator --> Plugins[Analyzer Plugins]
    Plugins --> Normalize[Normalization Layer]
    Normalize --> MASVS[MASVS Engine]
    Normalize --> ATTCK[ATT&CK Triage Engine]
    MASVS --> Risk[Risk Engine]
    ATTCK --> Risk
    Normalize --> Evidence[Evidence Engine]
    Risk --> DB[(PostgreSQL)]
    Evidence --> DB
    Risk -. optional V1.1 .-> AICTX[AI Context Builder]
    Evidence -. optional V1.1 .-> AICTX
    AICTX -. redacted context .-> AIRED[AI Redaction Layer]
    AIRED -. optional external call .-> KIMI[Kimi AI Connector]
    KIMI -. draft text .-> AIA[AI Triage & Audit Assistant]
    AIA -. reviewed text .-> Report
    Risk --> Report[Report Generator]
    Report --> Exports[PDF Report / JSON Export]
```

## Modules Fonctionnels

1. Project and audit management.
2. APK ingestion.
3. Local Android static analysis.
4. AppSec detection engine.
5. Threat triage engine.
6. MASVS mapping engine.
7. MITRE ATT&CK Mobile mapping engine.
8. Risk engine.
9. Evidence engine.
10. Reporting engine.
11. Optional V1.1 AI triage and audit reporting assistant.

## Documentation Structure

```text
docs/
├── 00_Cadrage/
├── 01_Requirements/
├── 02_Security_Methodology/
├── 03_Architecture/
├── 04_Design/
├── 05_Development/
├── 06_Testing/
├── 07_Deployment/
└── 08_Delivery/
```

## Documents Cles

### Cadrage et Gestion de Projet

- [Note de cadrage](docs/00_Cadrage/00_Note_de_Cadrage_MSAP.md)
- [Cahier des charges](docs/01_Requirements/03_Cahier_des_Charges_MSAP.md)
- [WBS - Work Breakdown Structure](docs/00_Cadrage/03_WBS_Work_Breakdown_Structure.md)
- [Gantt 8 semaines](docs/00_Cadrage/04_Gantt_8_Weeks.md)
- [Scrum project management](docs/00_Cadrage/05_Scrum_Project_Management.md)
- [Sprint backlog 8 semaines](docs/00_Cadrage/06_Sprint_Backlog_8_Weeks.md)
- [Matrice RACI](docs/00_Cadrage/07_RACI_Matrix.md)
- [Registre des risques](docs/00_Cadrage/08_Risk_Register.md)

### Architecture et Conception

- [Software Architecture Document](docs/03_Architecture/04_Software_Architecture_Document.md)
- [Component diagram](docs/03_Architecture/05_Component_Diagram.md)
- [UML use case diagram](docs/03_Architecture/06_UML_Use_Case_Diagram.md)
- [UML class diagram](docs/03_Architecture/07_UML_Class_Diagram.md)
- [UML sequence diagrams](docs/03_Architecture/08_UML_Sequence_Diagrams.md)
- [UML activity diagram](docs/03_Architecture/09_UML_Activity_Diagram.md)
- [UML state diagram](docs/03_Architecture/10_UML_State_Diagram.md)
- [Deployment diagram](docs/03_Architecture/11_Deployment_Diagram.md)
- [Package/module diagram](docs/03_Architecture/12_Package_Module_Diagram.md)
- [UI/UX wireframes](docs/04_Design/13_UI_UX_Wireframes.md)
- [Non-functional design](docs/04_Design/14_Non_Functional_Design.md)
- [Architecture Decision Records](docs/04_Design/15_Architecture_Decision_Records.md)

### Optional AI Assistance

- [AI integration decision](docs/00_Cadrage/10_AI_Integration_Decision.md)
- [AI-assisted triage methodology](docs/02_Security_Methodology/07_AI_Assisted_Triage_Methodology.md)
- [AI assistant architecture](docs/03_Architecture/13_AI_Assistant_Architecture.md)
- [AI context and redaction model](docs/04_Design/16_AI_Context_and_Redaction_Model.md)
- [AI prompt templates](docs/04_Design/17_AI_Prompt_Templates.md)
- [AI human validation workflow](docs/04_Design/18_AI_Human_Validation_Workflow.md)
- [AI optional configuration](docs/07_Deployment/18_AI_Optional_Configuration.md)

### Validation et Livraison

- [Test strategy](docs/06_Testing/16_Test_Strategy.md)
- [Acceptance criteria](docs/06_Testing/17_Acceptance_Criteria.md)
- [Local deployment strategy](docs/07_Deployment/17_Local_Deployment_Strategy.md)
- [Delivery checklist](docs/08_Delivery/18_Delivery_Checklist.md)
- [Demo scenario](docs/08_Delivery/19_Demo_Scenario.md)
- [Final deliverables index](docs/08_Delivery/20_Final_Deliverables_Index.md)

## Stack Technique Prevue

- Frontend: React.
- Backend: Django REST Framework.
- Base locale: PostgreSQL.
- Analyse Android: APKTool, JADX, Androguard, regles regex/YARA optionnelles.
- Reporting: PDF et JSON.
- Deploiement: Docker Compose local.
- Optional V1.1 AI: Kimi AI connector disabled by default, using redacted post-analysis context only.

## Contraintes Local-First 

MSAP doit rester deployable sur un poste institutionnel, y compris en environnement WSL et machines ARM64 lorsque possible. Les dependances doivent etre choisies avec prudence, sans imposer MobSF, emulateur Android ou service externe. 

Kimi AI does not change the local-first V1 baseline. It is an optional V1.1 external service integration that requires explicit configuration and institutional approval.

## Roadmap Summary

| Semaine | Objectif |
|---|---|
| S1 | Cadrage & exigences |
| S2 | Architecture & design |
| S3 | Socle backend/frontend |
| S4 | Analyse APK locale |
| S5 | Detections AppSec |
| S6 | MASVS + ATT&CK engines |
| S7 | Dashboard & reporting |
| S8 | Qualite & livraison |
| Post-V1.0 / V1.1 | Optional Kimi AI assistant for redacted report drafting and analyst-reviewed triage text |

## Authorized-Use Disclaimer

MSAP est une plateforme academique et institutionnelle d'audit cybersécurité. Elle doit etre utilisee uniquement pour analyser des APK avec autorisation explicite. Les resultats de triage ne constituent pas une classification definitive malware/benin et doivent etre interpretes par un analyste.
