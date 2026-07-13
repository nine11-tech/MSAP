# Risk Register - MSAP Cloud

| ID | Risk | Impact | Mitigation |
|---|---|---|---|
| R-001 | Kubernetes complexity | High | Helm, kind/K3s validation, minimal manifests first |
| R-002 | MinIO misconfiguration | High | Private buckets, policies, tests, no public access |
| R-003 | Object exposure | High | RBAC, short pre-signed URLs, audit logs, path isolation |
| R-004 | Secret leakage | High | Kubernetes Secrets, rotation, no committed secrets |
| R-005 | Cloud cost | Medium | Resource limits, autoscaling discipline, self-hosted option |
| R-006 | Resource limits too low | Medium | Worker profiles, requests/limits, APK size thresholds |
| R-007 | Worker failures | Medium | Retries bounded, status model, dead-letter handling future |
| R-008 | Upload of sensitive APKs | High | Authorized-use policy, retention, encryption, restricted access |
| R-009 | Network exposure | High | Ingress TLS, NetworkPolicies, auth, hardening checklist |
| R-010 | False positives in triage | Medium | Confidence scores, analyst review, cautious wording |
| R-011 | Confusion with malware verdict | High | Explicit disclaimer: no guaranteed malware classification |
| R-012 | Optional AI data leakage | High | Post-analysis only, redaction, no raw APKs, human validation |
