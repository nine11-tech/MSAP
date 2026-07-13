# Package / Module Diagram - MSAP Cloud

```mermaid
flowchart LR
    subgraph app[Application]
      FE[frontend/react]
      API[backend/api]
      ORCH[backend/orchestrator]
      AUTH[backend/auth_rbac]
    end
    subgraph analysis[Analysis]
      WORKERS[workers]
      PLUGINS[analyzers/plugins]
      NORM[normalization]
      MASVS[engines/masvs]
      ATTCK[engines/attck_triage]
      EVID[evidence]
      RISK[risk]
    end
    subgraph storage[Storage]
      PG[postgres models]
      OBJ[storage/minio]
      REFS[object_storage_references]
    end
    subgraph infra[Infrastructure]
      K8S[infrastructure/k8s]
      HELM[helm/msap-cloud]
      DEV[docker-compose.dev]
      CI[ci-devsecops]
    end
    FE --> API
    API --> ORCH
    ORCH --> WORKERS
    WORKERS --> PLUGINS
    PLUGINS --> NORM
    NORM --> MASVS
    NORM --> ATTCK
    MASVS --> EVID
    ATTCK --> EVID
    EVID --> RISK
    API --> PG
    API --> OBJ
    EVID --> REFS
    HELM --> K8S
```

## Modules ajoutes
`infrastructure/k8s`, `helm/msap-cloud`, `storage/minio`, `object_storage_references`, `workers` et `ci-devsecops` deviennent des modules de conception.
