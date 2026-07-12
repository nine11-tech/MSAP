# Pipeline d'Analyse Statique et de Triage APK - MSAP V1

## Pipeline

1. APK upload.
2. File validation.
3. Hash calculation.
4. APK metadata extraction.
5. Manifest extraction.
6. Certificate/signature metadata extraction.
7. Permission and component extraction.
8. Resource and string extraction.
9. Decompiled code extraction when possible.
10. Raw analyzer result collection.
11. Normalization into internal artifact schema.
12. MASVS rule loading.
13. ATT&CK triage rule loading.
14. AppSec rule execution.
15. Threat indicator detection.
16. Evidence collection.
17. MASVS mapping.
18. ATT&CK Mobile mapping.
19. Risk scoring.
20. Compliance scoring.
21. Result persistence.
22. Optional AI enrichment if enabled.
23. Report generation.

## Inputs

- APK autorise.
- Projet et audit.
- `rules/masvs_static_rules.yaml`.
- `rules/attck_mobile_triage_rules.yaml`.
- Configuration locale des chemins et limites.

## Outputs

- APKMetadata.
- RawAnalyzerResult.
- NormalizedArtifact.
- Findings MASVS.
- SuspiciousIndicators ATT&CK Mobile.
- Evidence.
- RiskScore et ComplianceScore.
- Rapport PDF et export JSON.

## Sequence Diagram

```mermaid
sequenceDiagram
    actor Auditor
    participant FE as React Frontend
    participant API as Django REST API
    participant ORCH as Audit Orchestrator
    participant PM as Analyzer Plugin Manager
    participant NORM as Normalization Layer
    participant MASVS as MASVS Engine
    participant ATTCK as ATT&CK Triage Engine
    participant EVID as Evidence Engine
    participant SCORE as Risk/Compliance Engine
    participant DB as PostgreSQL
    participant REP as Report Generator

    Auditor->>FE: Upload APK
    FE->>API: POST /apk
    API->>API: Validate file and calculate SHA-256
    API->>DB: Save APKFile
    Auditor->>FE: Start analysis
    FE->>API: POST /analysis/start
    API->>ORCH: Start pipeline
    ORCH->>PM: Run APKTool/JADX/Androguard/Regex adapters
    PM-->>ORCH: Raw analyzer results
    ORCH->>NORM: Normalize artifacts
    NORM-->>ORCH: Internal artifact schema
    ORCH->>MASVS: Load rules and execute AppSec detections
    ORCH->>ATTCK: Load triage rules and detect indicators
    MASVS-->>EVID: Findings with evidence candidates
    ATTCK-->>EVID: Indicators with evidence candidates
    EVID->>SCORE: Evidence-backed results
    SCORE->>DB: Persist scores and compliance
    EVID->>DB: Persist evidence
    ORCH->>REP: Generate PDF and JSON
    REP->>DB: Save report metadata
    API-->>FE: Completed status
```

## Activity Diagram

```mermaid
flowchart TD
    Start([Start]) --> Upload[APK upload]
    Upload --> Validate{Valid APK?}
    Validate -- No --> Reject[Reject and log reason]
    Reject --> Fail([Failed])
    Validate -- Yes --> Hash[Calculate SHA-256]
    Hash --> Meta[Extract APK metadata]
    Meta --> Manifest[Extract manifest]
    Manifest --> Cert[Extract certificate/signature metadata]
    Cert --> Perms[Extract permissions and components]
    Perms --> Strings[Extract resources and strings]
    Strings --> Code[Extract decompiled code when possible]
    Code --> Raw[Collect raw analyzer results]
    Raw --> Norm[Normalize artifacts]
    Norm --> LoadMASVS[Load MASVS rules]
    Norm --> LoadATTCK[Load ATT&CK triage rules]
    LoadMASVS --> AppSec[Execute AppSec rules]
    LoadATTCK --> Triage[Detect threat indicators]
    AppSec --> Evidence[Collect evidence]
    Triage --> Evidence
    Evidence --> MapMASVS[MASVS mapping]
    Evidence --> MapATTCK[ATT&CK Mobile mapping]
    MapMASVS --> Risk[Risk scoring]
    MapATTCK --> Risk
    Risk --> Compliance[Compliance scoring]
    Compliance --> Persist[Persist results]
    Persist --> AIEnabled{AI enabled?}
    AIEnabled -- No --> Report[Generate PDF and JSON]
    AIEnabled -- Yes --> AIContext[Build AI context]
    AIContext --> AIRedact[Redact AI context]
    AIRedact --> AIDraft[Generate optional AI draft]
    AIDraft --> HumanReview[Human validation]
    HumanReview --> Report
    Report --> Done([Completed])
```

## Optional Post-Scoring AI Enrichment

The AI enrichment step is optional V1.1 and occurs only after deterministic risk and compliance scoring. It may prepare redacted draft text before final report generation, but it cannot change findings, indicators, evidence or scores.

## Failure Handling

- Invalid upload: return `400`, no analysis launched.
- Tool unavailable: mark plugin result failed and continue when non-critical.
- YAML invalid: block analysis because rules are not trustworthy.
- Partial extraction: continue with missing-artifact warning.
- Rule failure: log rule ID and continue other rules.
- Reporting failure: keep analysis results and mark report failed.
- AI unavailable or disabled: continue report generation without AI content.

## Logging Requirements

- Include `audit_id`, `apk_file_id`, plugin name, step and duration.
- Never log full secrets or complete sensitive snippets.
- Distinguish analyst-facing errors from technical debug logs.
- Keep local logs only.
