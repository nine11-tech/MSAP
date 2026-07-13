# Diagramme UML de Classes - MSAP

## Objectif

Ce diagramme represente une vue simplifiee des classes et entites du domaine MSAP. Il ne decrit pas tous les attributs d'implementation Django, mais clarifie les relations metier entre projets, audits, APK, artefacts, regles, findings, indicateurs, preuves, scores et rapports.

## Diagramme

```mermaid
classDiagram
    class User {
        +id
        +username
        +email
        +role
    }

    class Project {
        +id
        +name
        +description
        +context
    }

    class Audit {
        +id
        +name
        +scope
        +status
    }

    class APKFile {
        +id
        +filename
        +sha256
        +storage_path
    }

    class APKMetadata {
        +package_name
        +version_name
        +min_sdk
        +target_sdk
        +signature_scheme
    }

    class AnalyzerPlugin {
        +name
        +plugin_type
        +enabled
    }

    class RawAnalyzerResult {
        +artifact_type
        +raw_payload
        +status
    }

    class NormalizedArtifact {
        +artifact_type
        +key
        +value
        +location
    }

    class Rule {
        +id
        +standard
        +masvs_category
        +severity
    }

    class TriageRule {
        +id
        +standard
        +tactic
        +technique_id
        +severity
    }

    class Finding {
        +title
        +severity
        +confidence
        +status
    }

    class SuspiciousIndicator {
        +title
        +severity
        +confidence
        +analyst_status
    }

    class Evidence {
        +source
        +file_path
        +snippet
        +redacted
    }

    class MASVSControl {
        +code
        +name
        +version
    }

    class ATTCKTechnique {
        +technique_id
        +technique_name
        +tactic
        +platform
    }

    class RiskScore {
        +score
        +severity
        +calculation_details
    }

    class ComplianceScore {
        +standard
        +category
        +score
    }

    class Report {
        +format
        +status
        +file_path
    }

    User "1" --> "0..*" Project : owns
    User "1" --> "0..*" Audit : creates
    Project "1" --> "0..*" Audit : contains
    Audit "1" --> "1" APKFile : analyzes
    APKFile "1" --> "0..1" APKMetadata : has
    AnalyzerPlugin "1" --> "0..*" RawAnalyzerResult : produces
    Audit "1" --> "0..*" RawAnalyzerResult : receives
    RawAnalyzerResult "1" --> "0..*" NormalizedArtifact : normalizes
    Audit "1" --> "0..*" Finding : has
    Audit "1" --> "0..*" SuspiciousIndicator : has
    Rule "1" --> "0..*" Finding : triggers
    TriageRule "1" --> "0..*" SuspiciousIndicator : triggers
    MASVSControl "1" --> "0..*" Finding : maps
    ATTCKTechnique "1" --> "0..*" SuspiciousIndicator : maps
    Finding "1" --> "1..*" Evidence : supported_by
    SuspiciousIndicator "1" --> "1..*" Evidence : supported_by
    Audit "1" --> "0..*" RiskScore : has
    Audit "1" --> "0..*" ComplianceScore : has
    Audit "1" --> "0..*" Report : generates
```
