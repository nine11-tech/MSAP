# Schema Officiel des Regles Statiques V1 - MSAP

## Objectif

Le fichier `rules/masvs_static_rules.yaml` constitue le catalogue de regles statiques de la Version 1. Il doit etre lisible, validable et directement exploitable par le backend pour executer les controles d'analyse statique Android et produire des findings alignes avec OWASP MASVS.

## Structure racine

```yaml
rules:
  - id: MSAP-AND-001
    title: Android debuggable enabled
    description: The application is configured with android:debuggable set to true.
    masvs_category: MASVS-RESILIENCE
    severity: High
    source: AndroidManifest.xml
    detection_type: manifest_attribute
    pattern_or_condition: "application/@android:debuggable == true"
    impact: Debuggable production builds can expose runtime inspection.
    recommendation: Disable android:debuggable for production builds.
    evidence_example: "<application android:debuggable=\"true\" ...>"
```

La cle racine obligatoire est `rules`. Sa valeur doit etre une liste non vide de regles.

## Champs obligatoires

### id

Identifiant unique de la regle. Le format V1 attendu est `MSAP-AND-NNN`, par exemple `MSAP-AND-001`.

### title

Titre court et explicite du controle.

### description

Description du probleme recherche par la regle.

### masvs_category

Categorie MASVS associee au finding produit.

Valeurs initiales acceptees:

- `MASVS-STORAGE`
- `MASVS-CRYPTO`
- `MASVS-AUTH`
- `MASVS-NETWORK`
- `MASVS-PLATFORM`
- `MASVS-PRIVACY`
- `MASVS-RESILIENCE`

### severity

Severite par defaut de la regle.

Valeurs autorisees:

- `Informational`
- `Low`
- `Medium`
- `High`
- `Critical`

### source

Artefact ou famille d'artefacts analysee.

Valeurs autorisees pour V1:

- `AndroidManifest.xml`
- `network_security_config`
- `Decompiled code`
- `resources`
- `Decompiled code, resources`
- `AndroidManifest.xml, network_security_config`
- `Decompiled code, network_security_config`

### detection_type

Type de detection applique par le moteur.

Valeurs autorisees pour V1:

- `manifest_attribute`
- `manifest_component_rule`
- `configuration_condition`
- `xml_configuration_rule`
- `string_pattern`
- `regex_secret_detection`
- `heuristic_code_pattern`
- `code_pattern`
- `absence_indicator`

### pattern_or_condition

Motif, expression, condition ou description operationnelle permettant d'executer la detection. Le contenu depend du `detection_type`.

### impact

Impact securite attendu si le constat est confirme.

### recommendation

Recommandation de remediation exploitable par une equipe technique.

### evidence_example

Exemple de preuve attendue, utile pour le rapport et les tests de validation.

## Exemples complets

### Exemple 1: attribut manifeste

```yaml
id: MSAP-AND-001
title: Android debuggable enabled
description: The application is configured with android:debuggable set to true.
masvs_category: MASVS-RESILIENCE
severity: High
source: AndroidManifest.xml
detection_type: manifest_attribute
pattern_or_condition: "application/@android:debuggable == true"
impact: Debuggable production builds can expose runtime inspection, debugging interfaces and sensitive execution details.
recommendation: Disable android:debuggable for production builds and enforce release build configuration checks.
evidence_example: "<application android:debuggable=\"true\" ...>"
```

### Exemple 2: detection de secret

```yaml
id: MSAP-AND-007
title: Hardcoded API key
description: A value resembling an API key is present in code or resources.
masvs_category: MASVS-AUTH
severity: High
source: Decompiled code, resources
detection_type: regex_secret_detection
pattern_or_condition: "(?i)(api[_-]?key|x-api-key)[\"'\\s:=]+[A-Za-z0-9_\\-]{16,}"
impact: Exposed API keys may allow unauthorized use of backend services.
recommendation: Remove API keys from the mobile client and use server-side secret management or scoped short-lived credentials.
evidence_example: "API_KEY = \"AIza...\""
```

### Exemple 3: configuration reseau

```yaml
id: MSAP-AND-014
title: Weak network security configuration
description: The network security configuration contains permissive or weak settings.
masvs_category: MASVS-NETWORK
severity: High
source: network_security_config
detection_type: xml_configuration_rule
pattern_or_condition: "Permissive domain-config, debug-overrides, user trust anchors or cleartext exceptions in production"
impact: Weak network settings can reduce transport security and expose application traffic.
recommendation: Restrict trust anchors, remove debug overrides from release builds and avoid broad cleartext exceptions.
evidence_example: "<certificates src=\"user\" />"
```

## Regles de validation

- La cle racine `rules` est obligatoire.
- Chaque regle doit contenir tous les champs obligatoires.
- `id` doit etre unique.
- `id` doit respecter le format `MSAP-AND-NNN`.
- `severity` doit appartenir aux valeurs autorisees.
- `source` doit appartenir aux valeurs autorisees.
- `detection_type` doit appartenir aux valeurs autorisees.
- `masvs_category` doit appartenir aux categories MASVS retenues.
- Les champs textuels ne doivent pas etre vides.
- Les expressions regex doivent etre compilables pour les regles `regex_secret_detection`.
- Les snippets d'exemple ne doivent pas contenir de vrai secret.

## Chargement et validation par le backend

Au demarrage ou avant une analyse, le backend doit:

1. Lire `rules/masvs_static_rules.yaml` depuis un chemin local configure.
2. Parser le YAML avec une bibliotheque robuste.
3. Verifier la presence de la cle racine `rules`.
4. Valider chaque regle selon le schema V1.
5. Compiler les regex lorsque le type de detection le necessite.
6. Refuser le lancement de l'analyse si le catalogue est invalide.
7. Synchroniser les regles valides dans la table `Rule` ou les charger en memoire selon le MVP.
8. Journaliser uniquement les erreurs de schema et jamais de donnees sensibles issues d'un APK.

Le catalogue YAML est considere comme une configuration de securite. Une regle invalide peut fausser l'audit; elle doit donc etre detectee avant l'execution du pipeline.
