# Matrice de Tracabilite - MSAP V1

| Requirement ID | Requirement | Module | Standard Mapping | Rule/Indicator | Test Evidence | Report Section |
|---|---|---|---|---|---|---|
| FR-03 | Importer un APK localement | APK ingestion | N/A | N/A | Upload test | Scope and APK metadata |
| FR-05 | Calculer SHA-256 | APK ingestion | N/A | N/A | Hash unit test | APK identity |
| FR-07 | Extraire manifeste et composants | Static analysis | MASVS/ATT&CK source | MSAP-AND-001..006, MSAP-MOB-004..006 | Manifest parser test | Technical evidence |
| FR-09 | Extraire URLs, IPs, domaines | Static analysis | MASVS-NETWORK / ATT&CK C2 | MSAP-AND-009, MSAP-MOB-007 | String extraction test | Network findings |
| FR-11 | Executer regles AppSec | AppSec detection | OWASP MASVS | MSAP-AND-* | Rule execution test | MASVS findings |
| FR-12 | Executer triage menace | Threat triage | MITRE ATT&CK Mobile | MSAP-MOB-* | Triage rule test | ATT&CK indicators |
| FR-13 | Mapper MASVS | MASVS mapping | OWASP MASVS | MASVS categories | Mapping test | MASVS summary |
| FR-14 | Mapper ATT&CK | ATT&CK mapping | MITRE ATT&CK Mobile | Tactics/techniques | Mapping test | ATT&CK summary |
| FR-15 | Collecter preuves | Evidence management | Both | All rules | Evidence trace test | Evidence details |
| FR-16 | Gerer faux positifs | Analyst workflow | Both | All results | Status update test | Analyst review |
| FR-17 | Calculer risk score | Risk scoring | Both | All results | Scoring test | Risk summary |
| FR-18 | Calculer compliance score | Compliance scoring | OWASP MASVS | MSAP-AND-* | Compliance test | Compliance summary |
| FR-19 | Generer PDF | Reporting | Both | All results | Report generation test | PDF report |
| FR-20 | Exporter JSON | Reporting | Both | All results | JSON schema test | JSON export |
