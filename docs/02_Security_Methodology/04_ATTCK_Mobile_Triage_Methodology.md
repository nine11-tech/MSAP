# Methodologie de Triage MITRE ATT&CK Mobile

## Purpose

Le triage ATT&CK Mobile dans MSAP vise a identifier des indicateurs statiques pouvant soutenir une analyse menace d'un APK. Il ne remplace pas une analyse malware complete et ne produit pas de verdict garanti.

## AppSec Weakness vs Threat Indicator

- **AppSec weakness**: faiblesse de conception ou configuration, mappee OWASP MASVS.
- **Threat indicator**: signal pouvant indiquer une capacite ou un comportement potentiel, mappe MITRE ATT&CK Mobile lorsque applicable.

Un meme artefact peut avoir deux lectures: un service exporte peut etre une faiblesse AppSec et aussi un signal de triage si son contexte suggere une exposition de service background.

## APK Artifacts Supporting Triage

- Permissions dangereuses.
- Composants exportes.
- Services d'accessibilite.
- Device admin receiver.
- URLs, IPs et domaines.
- Dynamic code loading.
- Reflection.
- Bibliotheques natives.
- Clipboard APIs.
- Obfuscation indicators.

## ATT&CK Mobile Mapping Approach

MSAP mappe un indicateur vers une tactique et une technique lorsque le signal statique est suffisamment explicite. Le mapping reste prudent: "may indicate", "can support triage", "requires analyst review".

## Indicator Confidence Model

- `Low`: signal frequent dans des applications legitimes.
- `Medium`: signal pertinent mais contexte incomplet.
- `High`: declaration ou API directement observable.

## Examples

- `BIND_ACCESSIBILITY_SERVICE` peut indiquer une capacite d'accessibilite.
- `DexClassLoader` peut indiquer du dynamic code loading.
- `REQUEST_INSTALL_PACKAGES` peut indiquer une capacite d'installation.
- Un grand nombre de permissions dangereuses peut soutenir une priorisation de revue.

## Analyst Workflow

1. Examiner les indicateurs par severite et confiance.
2. Lire les preuves associees.
3. Comparer avec la finalite declaree de l'application.
4. Rechercher les correlations entre permissions, code et endpoints.
5. Marquer les faux positifs ou les elements a investiguer.
6. Integrer les conclusions prudentes dans le rapport.

## Limitations

- Pas d'observation runtime.
- Pas de sandbox.
- Pas de reputation externe obligatoire.
- Les bibliotheques tierces peuvent generer des signaux.
- L'obfuscation n'est pas une preuve de malveillance.

## False Positives

Les faux positifs sont attendus dans un triage statique. MSAP doit permettre de conserver le signal, son contexte, sa confiance et le statut analyste.

## Report Interpretation

Les sections ATT&CK du rapport doivent indiquer que les resultats sont des indicateurs de triage, pas une classification definitive.
