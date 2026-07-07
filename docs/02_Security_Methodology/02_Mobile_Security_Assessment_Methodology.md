# Methodologie Hybride d'Evaluation Mobile - MSAP

## Objectif

La methodologie MSAP V1 combine une evaluation AppSec basee sur OWASP MASVS et un triage d'indicateurs suspects base sur MITRE ATT&CK Mobile. Elle s'applique uniquement a l'analyse statique locale d'APK Android.

## Partie 1: Evaluation AppSec OWASP MASVS

L'axe MASVS vise a identifier des faiblesses de securite applicative: stockage, reseau, cryptographie, exposition de composants, configuration WebView, logs sensibles, secrets hardcodes et resilience.

Chaque finding MASVS doit inclure:

- regle declenchee;
- categorie MASVS;
- severite;
- preuve;
- impact;
- recommandation.

## Partie 2: Triage MITRE ATT&CK Mobile

L'axe ATT&CK Mobile vise a identifier des indicateurs statiques pouvant soutenir une analyse menace. Ces indicateurs peuvent indiquer des capacites ou comportements potentiels, mais ne prouvent pas qu'une application est malveillante.

Chaque indicateur doit etre revu par un analyste et presente comme non conclusif.

## Static Analysis Workflow

1. Upload et validation APK.
2. Calcul SHA-256.
3. Extraction metadonnees.
4. Extraction manifeste, permissions, composants.
5. Extraction certificats/signatures.
6. Extraction ressources, chaines et code decompile lorsque possible.
7. Normalisation des artefacts.
8. Execution des regles MASVS.
9. Execution des regles ATT&CK triage.
10. Collecte preuves, scoring, reporting.

## APK Artifacts Analyzed

- `AndroidManifest.xml`.
- Permissions.
- Activities, services, receivers et providers.
- Certificat et signature.
- Ressources XML et textuelles.
- Strings.
- URLs, IPs, domaines.
- Code decompile lorsque possible.
- Bibliotheques natives et references de chargement.

## Manifest Checks

- `android:debuggable`.
- `android:allowBackup`.
- `usesCleartextTraffic`.
- Composants exportes.
- Permissions sensibles.
- Services d'accessibilite.
- Device admin receiver.

## Permission Checks

Les permissions dangereuses sont extraites et classees. Certaines permissions constituent des faiblesses AppSec selon le contexte; d'autres sont des indicateurs de triage lorsqu'elles sont excessives ou coherentes avec des techniques ATT&CK Mobile.

## Component Exposure Checks

Les composants exportes sans permission sont evalues comme risques AppSec. Un service background exporte ou un receiver sensible peut aussi soutenir un triage ATT&CK selon le contexte.

## Network Checks

- URLs HTTP.
- Cleartext traffic.
- Domaines et IPs.
- Patterns d'URL pouvant ressembler a des endpoints C2.
- Configuration reseau faible.

## Secrets and IOC Extraction

MSAP recherche des secrets, tokens, cles API, URLs, IPs, domaines et chaines sensibles. Ces elements doivent etre rediges dans les rapports si leur valeur complete est sensible.

## Crypto Checks

Detection d'algorithmes faibles, modes dangereux et usages cryptographiques necessitant revue humaine.

## Storage Checks

Recherche d'indicateurs de stockage non protege, backup active et references a donnees sensibles locales.

## Obfuscation Indicators

Les indicateurs d'obfuscation ou de noms de classes peu lisibles peuvent soutenir le triage, mais ne constituent pas seuls une preuve de malveillance.

## Suspicious API Indicators

Exemples: reflection, dynamic code loading, chargement de bibliotheques natives, accessibilite, installation de packages, clipboard, overlay. Ces indicateurs doivent etre interpretes avec prudence.

## Evidence Model

Une preuve contient source, artefact, chemin, ligne si disponible, extrait, regle, standard, confiance et horodatage.

## Confidence Model

- `Low`: indicateur faible ou contexte insuffisant.
- `Medium`: motif pertinent mais necessitant revue.
- `High`: preuve directe d'une configuration ou capacite.

## Risk Scoring Model

Le risque combine severite, confiance, impact, exposition et exploitabilite. Les scores servent a prioriser les revues et corrections.

## Compliance Scoring Model

Le score de conformite MASVS mesure l'absence relative de findings AppSec par categorie. Il reste indicatif et ne remplace pas une certification MASVS.

## Limitations of Static Analysis

- Pas d'observation runtime.
- Faux positifs possibles.
- Code mort ou bibliotheques inutilisees possibles.
- Impossible de confirmer un comportement C2 actif.
- Impossible de classifier definitivement malware/benin.

## Triage vs Malware Verdict

Le triage ATT&CK Mobile identifie des signaux a examiner. Il ne produit pas de verdict definitif. Une classification malveillante necessiterait d'autres sources, analyse dynamique, contexte de distribution, reputation et revue expert.

## Future Dynamic Analysis Extension

Une version future pourrait ajouter de l'analyse dynamique locale autorisee. Cette extension reste hors perimetre V1.
