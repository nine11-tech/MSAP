# Component Diagram - MSAP

```mermaid
flowchart TB
    subgraph Client
      U[Auditor]
    end
    subgraph Kubernetes[Namespace msap]
      ING[Ingress TLS]
      FE[React Frontend]
      API[Django REST API]
      ORCH[Audit Orchestrator]
      Q[Redis Queue]
      W[Analyzer Workers]
      KJ[Kubernetes Jobs]
      N[Normalization Layer]
      M[MASVS Engine]
      A[ATT&CK Triage Engine]
      E[Evidence Engine]
      R[Risk Engine]
      RG[Report Generator]
      DB[(PostgreSQL)]
      S3[(MinIO Object Storage)]
      SEC[Kubernetes Secrets]
    end
    U --> ING
    ING --> FE
    ING --> API
    FE --> API
    API --> ORCH
    ORCH --> Q
    Q --> W
    ORCH --> KJ
    W --> N
    KJ --> N
    N --> M
    N --> A
    M --> E
    A --> E
    E --> R
    R --> RG
    API --> DB
    E --> DB
    R --> DB
    RG --> DB
    API --> S3
    W --> S3
    KJ --> S3
    RG --> S3
    SEC --> API
    SEC --> W
```

## Notes
MinIO est un stockage objet pour APK, artefacts, preuves, rapports et exports. Kubernetes est la cible de deploiement. Docker Compose est reserve au developpement local.
