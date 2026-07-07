# Methodologie d'Evaluation de Securite Mobile - MSAP

## Objectif de la methodologie d'audit

La methodologie MSAP definit une approche reproductible pour analyser statiquement des applications Android au format APK. Elle vise a produire des constats techniques exploitables, associes a des preuves, des categories OWASP MASVS, des niveaux de risque et des recommandations.

## Referentiel: OWASP MASVS

OWASP MASVS sert de referentiel principal pour structurer les constats. MSAP ne remplace pas une certification MASVS complete; la plateforme fournit un support d'audit statique permettant d'identifier des indicateurs de non-conformite ou de risque.

## Type d'audit: analyse statique Android APK

La Version 1 couvre uniquement l'analyse statique d'un fichier APK. Elle ne lance pas l'application, n'interagit pas avec un terminal mobile, n'utilise pas d'emulateur et n'execute pas d'instrumentation dynamique.

## Artefacts analyses

- `AndroidManifest.xml`
- Code source decompile ou representation intermediaire
- Ressources Android
- Fichiers de configuration
- Chaines de caracteres
- Configurations de securite reseau
- Metadonnees applicatives extraites localement

## Analyse du fichier AndroidManifest.xml

L'analyse du manifeste permet d'identifier les permissions, composants exportes, options de sauvegarde, mode debug, configurations reseau et declarations sensibles. Les constats doivent inclure l'attribut ou le composant concerne comme preuve.

## Analyse du code decompile

L'analyse du code decompile recherche des motifs a risque: secrets hardcodes, usage de fonctions cryptographiques faibles, traces de logs sensibles, configuration WebView dangereuse et appels reseau non securises.

## Analyse des ressources

Les ressources peuvent contenir des URLs, cles API, configurations, certificats, fichiers XML de securite reseau ou chaines sensibles. Elles doivent etre analysees avec prudence afin de reduire les faux positifs.

## Detection de secrets

La detection de secrets recherche des cles API, tokens, identifiants, endpoints internes et valeurs ressemblant a des credentials. Un secret detecte doit etre accompagne du fichier, du type de motif et d'un extrait limite.

## Verifications de securite reseau

- Detection d'URLs HTTP.
- Detection de trafic cleartext autorise.
- Analyse de la configuration `network_security_config`.
- Recherche d'indicateurs de certificate pinning.
- Identification des configurations faibles ou permissives.

## Verifications de stockage des donnees

- Recherche de stockage potentiel de donnees sensibles dans les preferences, fichiers locaux ou bases embarquees.
- Detection de noms de fichiers sensibles.
- Identification d'indicateurs de stockage non chiffre.

## Verifications cryptographiques

- Recherche d'algorithmes faibles comme MD5, SHA-1, DES, RC4 ou ECB.
- Identification de constantes cryptographiques hardcodees.
- Signalement des usages qui necessitent une revue humaine.

## Verifications des interactions plateforme

- Composants Android exportes.
- Activites, services et receivers sans protection apparente.
- Permissions dangereuses.
- Usage potentiellement risqué d'intents.

## Verifications de protection du code

- Presence ou absence d'indicateurs d'obfuscation.
- Usage de logs sensibles.
- Recherche d'informations de debug.
- Limites: l'absence d'obfuscation ne constitue pas toujours une vulnerabilite, mais peut augmenter l'exposition.

## Modele de preuve

Chaque preuve doit contenir:

- Source de la preuve.
- Fichier ou artefact concerne.
- Regle declenchee.
- Extrait ou attribut detecte.
- Contexte minimal.
- Niveau de confiance.

## Modele de scoring du risque

Le score initial combine:

- Severite de la regle.
- Exposition de l'artefact.
- Confiance de detection.
- Impact potentiel.
- Besoin de validation manuelle.

Les niveaux proposes sont: `Informational`, `Low`, `Medium`, `High`, `Critical`.

## Limites de l'analyse statique

- Impossible de confirmer certains comportements a l'execution.
- Risque de faux positifs sur les secrets et URLs.
- Les chemins de code morts peuvent etre detectes.
- Les protections runtime ne sont pas observees.
- Le certificate pinning peut etre difficile a confirmer uniquement par analyse statique.

## Extensions futures

- Analyse dynamique locale.
- Instrumentation Frida dans un cadre autorise.
- Analyse iOS.
- Integration optionnelle de MobSF comme outil externe dans une version ulterieure.
- Enrichissement du moteur de regles.
- Correlation entre resultats statiques et dynamiques.
