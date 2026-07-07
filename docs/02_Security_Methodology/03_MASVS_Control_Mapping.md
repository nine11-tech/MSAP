# Mapping Initial des Controles MASVS

Ce mapping relie les premieres regles MSAP a des categories OWASP MASVS. Il s'agit d'une base initiale destinee a etre affinee pendant le developpement et la validation manuelle.

| MSAP Rule ID | Finding | MASVS Category | Severity | Evidence Source | Detection Method | Recommendation |
|---|---|---|---|---|---|---|
| MSAP-AND-001 | `android:debuggable=true` | MASVS-RESILIENCE | High | AndroidManifest.xml | Condition sur attribut manifest | Desactiver le mode debug dans les builds de production. |
| MSAP-AND-002 | `android:allowBackup=true` | MASVS-STORAGE | Medium | AndroidManifest.xml | Condition sur attribut application | Desactiver la sauvegarde ou justifier son usage avec chiffrement et politique de donnees. |
| MSAP-AND-003 | Cleartext traffic allowed | MASVS-NETWORK | High | AndroidManifest.xml, network_security_config | Analyse de configuration reseau | Interdire le trafic cleartext et utiliser HTTPS. |
| MSAP-AND-004 | Exported activity without protection | MASVS-PLATFORM | High | AndroidManifest.xml | Detection de composant exporte sans permission | Restreindre l'export ou proteger l'activite par permission appropriee. |
| MSAP-AND-005 | Exported service without protection | MASVS-PLATFORM | High | AndroidManifest.xml | Detection de service exporte sans permission | Restreindre l'export ou proteger le service par permission appropriee. |
| MSAP-AND-006 | Exported receiver without protection | MASVS-PLATFORM | High | AndroidManifest.xml | Detection de receiver exporte sans permission | Restreindre l'export ou proteger le receiver par permission appropriee. |
| MSAP-AND-007 | Hardcoded API key | MASVS-AUTH | High | Code decompile, ressources | Regex et heuristiques de secrets | Retirer la cle du client mobile et utiliser un mecanisme de gestion de secrets cote serveur. |
| MSAP-AND-008 | Hardcoded token | MASVS-AUTH | High | Code decompile, ressources | Regex et heuristiques de tokens | Supprimer le token hardcode et utiliser une emission dynamique avec expiration. |
| MSAP-AND-009 | Insecure HTTP URL | MASVS-NETWORK | Medium | Code decompile, ressources | Recherche de chaines `http://` | Remplacer par HTTPS et valider la configuration TLS. |
| MSAP-AND-010 | Weak cryptographic algorithm | MASVS-CRYPTO | High | Code decompile | Recherche d'algorithmes faibles | Utiliser des primitives modernes et des modes de chiffrement authentifies. |
| MSAP-AND-011 | Sensitive data in logs | MASVS-PRIVACY | Medium | Code decompile | Recherche d'appels de log avec motifs sensibles | Supprimer les logs sensibles et appliquer une politique de journalisation securisee. |
| MSAP-AND-012 | WebView JavaScript enabled | MASVS-PLATFORM | Medium | Code decompile | Recherche de `setJavaScriptEnabled(true)` | Activer JavaScript uniquement si necessaire et durcir la configuration WebView. |
| MSAP-AND-013 | Missing certificate pinning indicator | MASVS-NETWORK | Low | Code decompile, configuration reseau | Absence d'indicateurs connus | Evaluer le besoin de certificate pinning selon le modele de menace. |
| MSAP-AND-014 | Weak network security configuration | MASVS-NETWORK | High | network_security_config | Analyse XML de configuration | Renforcer la configuration reseau, retirer les ancres utilisateur en production et limiter les exceptions. |
