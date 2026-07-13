# Mapping OWASP MASVS et MITRE ATT&CK Mobile - MSAP

Ce document definit les mappings initiaux utilises par MSAP V1. Les mappings ATT&CK Mobile sont des aides au triage: ils peuvent indiquer des capacites ou signaux suspects, mais ne constituent pas une classification definitive malveillante.

## A. OWASP MASVS Mapping

| MSAP Rule ID | Finding | MASVS Category | Severity | Evidence Source | Detection Method | Recommendation |
|---|---|---|---|---|---|---|
| MSAP-AND-001 | `android:debuggable=true` | MASVS-RESILIENCE | High | AndroidManifest.xml | Manifest attribute | Desactiver le mode debug dans les builds de production. |
| MSAP-AND-002 | `android:allowBackup=true` | MASVS-STORAGE | Medium | AndroidManifest.xml | Manifest attribute | Desactiver la sauvegarde ou justifier son usage avec protection adaptee. |
| MSAP-AND-003 | Cleartext traffic allowed | MASVS-NETWORK | High | AndroidManifest.xml, network_security_config | Configuration condition | Interdire le trafic cleartext et imposer HTTPS. |
| MSAP-AND-004 | Exported activity without protection | MASVS-PLATFORM | High | AndroidManifest.xml | Component rule | Restreindre l'export ou proteger par permission. |
| MSAP-AND-005 | Exported service without protection | MASVS-PLATFORM | High | AndroidManifest.xml | Component rule | Restreindre l'export ou proteger le service. |
| MSAP-AND-006 | Exported receiver without protection | MASVS-PLATFORM | High | AndroidManifest.xml | Component rule | Restreindre l'export ou proteger le receiver. |
| MSAP-AND-007 | Hardcoded API key | MASVS-AUTH | High | Decompiled code, resources | Regex secret detection | Retirer la cle du client mobile et utiliser une gestion cote serveur. |
| MSAP-AND-008 | Hardcoded token | MASVS-AUTH | High | Decompiled code, resources | Regex secret detection | Supprimer le token hardcode et utiliser des tokens courts et renouvelables. |
| MSAP-AND-009 | Insecure HTTP URL | MASVS-NETWORK | Medium | Decompiled code, resources | String pattern | Remplacer HTTP par HTTPS et verifier TLS. |
| MSAP-AND-010 | Weak cryptographic algorithm | MASVS-CRYPTO | High | Decompiled code | String pattern | Utiliser des primitives modernes et modes authentifies. |
| MSAP-AND-011 | Sensitive data in logs | MASVS-PRIVACY | Medium | Decompiled code | Heuristic code pattern | Supprimer les logs sensibles en production. |
| MSAP-AND-012 | WebView JavaScript enabled | MASVS-PLATFORM | Medium | Decompiled code | Code pattern | Activer JavaScript uniquement si necessaire et durcir WebView. |
| MSAP-AND-013 | Missing certificate pinning indicator | MASVS-NETWORK | Low | Decompiled code, network_security_config | Absence indicator | Evaluer le besoin de pinning selon le modele de menace. |
| MSAP-AND-014 | Weak network security configuration | MASVS-NETWORK | High | network_security_config | XML configuration rule | Retirer les exceptions faibles et durcir la configuration reseau. |

## B. MITRE ATT&CK Mobile Triage Mapping

| MSAP Indicator ID | Suspicious Indicator | ATT&CK Mobile Tactic | ATT&CK Mobile Technique | Severity | Confidence | Evidence Source | Triage Interpretation | Analyst Recommendation |
|---|---|---|---|---|---|---|---|---|
| MSAP-MOB-001 | SMS access permissions | Collection | SMS Messages | Medium | Medium | AndroidManifest.xml | May indicate capability to access SMS content; benign messaging apps may also request it. | Review app purpose and permission justification. |
| MSAP-MOB-002 | Contact access permissions | Collection | Contact List | Medium | Medium | AndroidManifest.xml | Can support triage for data collection capability. | Check business need and data handling. |
| MSAP-MOB-003 | Location access permissions | Collection | Location Tracking | Medium | Medium | AndroidManifest.xml | May indicate location collection capability. | Validate purpose, consent and frequency if runtime data exists later. |
| MSAP-MOB-004 | Accessibility service usage | Privilege Escalation | Accessibility Features | High | High | AndroidManifest.xml | Suspicious when unrelated to accessibility use cases; not definitive alone. | Review service declaration and user-facing justification. |
| MSAP-MOB-005 | Device admin receiver | Defense Evasion | Device Administrator Permissions | High | High | AndroidManifest.xml | May indicate capability for persistence or administrative control. | Review receiver, policies and legitimate MDM use cases. |
| MSAP-MOB-006 | Overlay permission | Credential Access | Screen Overlay | Medium | Medium | AndroidManifest.xml | Can support triage for overlay-based abuse patterns. | Review UI purpose and overlay flows. |
| MSAP-MOB-007 | HTTP C2-like URL pattern | Command and Control | Application Layer Protocol | High | Medium | Strings, resources, code | Suspicious network pattern; not a definitive C2 classification. | Correlate domain, path, frequency and reputation outside MSAP if authorized. |
| MSAP-MOB-008 | Dynamic code loading | Defense Evasion | Dynamic Code Loading | High | High | Decompiled code | May indicate runtime code loading capability. | Review source of loaded code and integrity controls. |
| MSAP-MOB-009 | Reflection usage | Defense Evasion | Obfuscated Files or Information | Medium | Low | Decompiled code | Common in frameworks but can support triage when combined with obfuscation. | Correlate with package context and other indicators. |
| MSAP-MOB-010 | Native library loading | Defense Evasion | Native Code | Medium | Medium | Decompiled code, lib/ | May indicate native capability or protection logic. | Review native libraries and expected SDKs. |
| MSAP-MOB-011 | Request install packages | Persistence | Install Insecure or Malicious Configuration | High | Medium | AndroidManifest.xml | May indicate capability to request package installation. | Confirm legitimate updater or enterprise use case. |
| MSAP-MOB-012 | Clipboard access indicators | Collection | Clipboard Data | Medium | Low | Decompiled code | Can support triage for sensitive data access. | Review clipboard reads and UI context. |
| MSAP-MOB-013 | Exported background service | Persistence | Background Services | Medium | Medium | AndroidManifest.xml | Suspicious if service is exported and unrelated to app function. | Review service intent filters and permissions. |
| MSAP-MOB-014 | Excessive dangerous permissions | Discovery | Software Discovery | Medium | Medium | AndroidManifest.xml | Broad permissions can support triage but may be legitimate. | Compare permissions with declared app purpose. |
| MSAP-MOB-015 | Obfuscation indicators | Defense Evasion | Obfuscated Files or Information | Low | Low | Decompiled code | Obfuscation may be commercial protection or suspicious depending on context. | Treat as supporting signal only. |
