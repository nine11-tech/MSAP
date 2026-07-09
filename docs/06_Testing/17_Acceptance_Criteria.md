# Criteres d'Acceptation MVP - MSAP

## Objectif

Ces criteres definissent le niveau minimal attendu pour considerer le MVP MSAP V1 acceptable avant livraison academique.

| ID | Critere | Verification attendue |
|---|---|---|
| AC-01 | Un APK peut etre uploaded localement. | Test fonctionnel upload. |
| AC-02 | Le hash SHA-256 de l'APK est calcule. | Hash affiche et persiste. |
| AC-03 | Le manifeste Android est parse. | Package, permissions et composants extraits. |
| AC-04 | Les catalogues de regles sont valides. | YAML MASVS et ATT&CK charges sans erreur. |
| AC-05 | Des findings MASVS initiaux sont generes. | Au moins une regle MASVS declenche sur fixture. |
| AC-06 | Des indicateurs ATT&CK initiaux sont generes. | Au moins une regle triage declenche sur fixture. |
| AC-07 | Les preuves sont liees aux findings. | Chaque finding/indicateur possede une evidence. |
| AC-08 | Un risk score est calcule. | Score visible dans audit. |
| AC-09 | Une synthese de conformite est calculee. | MASVS compliance summary visible. |
| AC-10 | Un rapport PDF est genere. | Fichier PDF disponible localement. |
| AC-11 | Un export JSON est genere. | Fichier JSON disponible localement. |
| AC-12 | Le deploiement Docker Compose local fonctionne. | Services backend, frontend, PostgreSQL demarrent. |
| AC-13 | Aucune dependance a un service distant n'existe. | Analyse executable offline. |

## Conditions de rejet

- Le systeme exige MobSF, emulateur ou analyse dynamique pour fonctionner en V1.
- Le rapport presente une classification malveillante definitive.
- Les APK sont envoyes a un service distant.
- Les preuves ne sont pas tracables.
