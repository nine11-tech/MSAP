# Modele de Flux de Donnees Cloud - MSAP

## Upload flow
L'auditeur cree un audit puis transmet un APK via l'API. Deux modeles sont acceptables: upload backend-medie ou URL pre-signee courte. L'objet final est stocke dans `msap-apk-uploads`, et PostgreSQL conserve la reference MinIO, le hash, la taille, le proprietaire, le projet et le statut.

## Analysis flow
L'API place une tache dans Redis. Un worker ou Kubernetes Job recupere l'APK depuis MinIO, execute les analyseurs statiques, depose les artefacts dans `msap-artifacts`, normalise les resultats, cree les findings MASVS, les indicateurs ATT&CK Mobile, les preuves et les scores.

## Report generation flow
Le generateur lit les donnees normalisees et les preuves referencees, produit un PDF et un export JSON, puis les stocke dans `msap-reports` et `msap-exports`. PostgreSQL stocke les references et statuts de generation.

## References and traceability
PostgreSQL est la source de verite pour l'etat metier. MinIO est la source de verite pour les binaires et artefacts volumineux. Chaque preuve relie audit, regle, artefact normalise, reference objet, emplacement, confiance et statut de redaction.

## AI redaction flow if enabled
Kimi AI recoit uniquement un contexte post-analyse minimal et redige depuis findings, indicateurs, scores et preuves redigees. L'AI ne recoit ni APK brut, ni artefacts complets sensibles, ni secrets non masques.

## Mermaid sequence diagram
```mermaid
sequenceDiagram
    participant U as Auditor
    participant FE as React Frontend
    participant API as Django REST API
    participant S3 as MinIO
    participant DB as PostgreSQL
    participant Q as Redis Queue
    participant W as Worker / K8s Job
    participant R as Report Generator
    participant AI as Optional Kimi AI
    U->>FE: Create audit and upload APK
    FE->>API: Submit upload request
    API->>S3: Store APK object
    API->>DB: Save ObjectStorageReference + audit metadata
    API->>Q: Enqueue analysis job
    Q->>W: Deliver job
    W->>S3: Read APK object
    W->>W: Static analysis and normalization
    W->>S3: Store artifacts and evidence objects
    W->>DB: Save findings, indicators, evidence, scores
    API->>R: Request report generation
    R->>DB: Read normalized results
    R->>S3: Store PDF report and JSON export
    R->>DB: Save report object references
    opt AI enabled after redaction
      API->>DB: Build redacted post-analysis context
      API->>AI: Send minimized redacted context
      AI-->>API: Draft text for analyst review
      API->>DB: Store reviewed AI output state
    end
    FE->>API: Request report download
    API->>S3: Fetch or sign report object
    API-->>FE: Return download response
```
