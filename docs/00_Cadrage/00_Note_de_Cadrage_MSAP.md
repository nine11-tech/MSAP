# Note de Cadrage - MSAP

## Titre du projet

**MSAP - Mobile Security Assessment Platform**

## Nom du produit

**MSAP**, plateforme locale d'evaluation de securite des applications mobiles.

## Contexte

Les applications mobiles manipulent des donnees sensibles, interagissent avec des services distants et s'executent sur des environnements utilisateurs difficiles a maitriser. Dans un contexte academique et professionnel, l'audit de securite mobile doit s'appuyer sur une methodologie claire, des preuves techniques exploitables et des referentiels reconnus comme l'OWASP MASVS.

MSAP vise a structurer une plateforme locale d'audit pour accompagner l'analyse de securite d'applications Android, en commencant par l'analyse statique de fichiers APK.

## Problematique

Les audits mobiles sont souvent realises avec des outils disperses, des scripts non standardises ou des rapports manuels difficiles a reproduire. Cette situation complique la tracabilite, la priorisation des risques et l'alignement avec les controles OWASP MASVS.

Le probleme principal est donc de concevoir une plateforme locale capable de centraliser l'analyse statique Android, d'associer les constats a des controles MASVS et de produire des rapports exploitables, sans dependre de services distants.

## Objectif general

Concevoir et preparer une plateforme d'audit de securite mobile locale, permettant d'analyser statiquement des APK Android et de produire des constats structures selon OWASP MASVS.

## Objectifs specifiques

- Definir une architecture modulaire adaptee aux audits de securite mobile.
- Formaliser une methodologie d'analyse statique Android.
- Etablir un premier catalogue de regles de detection MASVS.
- Preparer une structure documentaire professionnelle pour un PFA de deux mois.
- Concevoir un socle extensible vers d'autres types d'analyse sans les integrer dans la premiere version.
- Preparer les livrables attendus: documentation, architecture, backlog, regles et rapports.

## Perimetre fonctionnel

- Gestion future des audits d'applications mobiles.
- Depot local d'un fichier APK pour analyse.
- Extraction d'artefacts statiques: manifeste, ressources, code decompile, configurations.
- Detection de mauvaises configurations et de motifs de code a risque.
- Association des constats aux categories OWASP MASVS.
- Calcul d'un niveau de risque initial.
- Generation de rapports d'audit locaux.

## Perimetre technique

- Analyse statique Android APK uniquement pour la Version 1.
- Execution locale sans services externes.
- Architecture prevue autour d'un frontend, d'une API backend et de moteurs d'analyse.
- Possibilite future d'utiliser des adaptateurs vers APKTool, JADX et Androguard.
- Stockage local des resultats, preuves et metadonnees d'audit.

## Hors perimetre

- Utilisation de MobSF dans la Version 1.
- Analyse dynamique.
- Execution sur Android Emulator.
- Instrumentation Frida.
- Analyse iOS.
- Tests d'intrusion sur applications sans autorisation.
- Services cloud ou API externes.
- Contournement de protections applicatives.

## Vue d'ensemble de la methodologie d'audit

La methodologie MSAP V1 repose sur l'analyse statique d'un APK Android. Les artefacts analyses incluent le fichier `AndroidManifest.xml`, le code decompile, les ressources, les configurations reseau et les chaines de caracteres. Chaque constat doit etre associe a une preuve, une categorie MASVS, une severite et une recommandation.

## Utilisateurs cibles

- Etudiants en cybersécurité.
- Encadrants academiques.
- Auditeurs juniors en securite mobile.
- Equipes techniques souhaitant preparer un audit Android local.

## Livrables attendus

- Note de cadrage.
- Specification des exigences logicielles.
- Methodologie d'audit mobile.
- Mapping initial des controles MASVS.
- Catalogue de regles statiques.
- Document d'architecture logicielle.
- Diagrammes techniques.
- Backlog initial.
- Rapport final de PFA et support de soutenance.

## Synthese de la roadmap sur 8 semaines

| Semaine | Objectif principal |
|---|---|
| 1 | Cadrage, exigences, methodologie et architecture initiale |
| 2 | Conception du modele de donnees, backlog et specification des regles |
| 3 | Mise en place du socle backend, structure API et stockage local |
| 4 | Integration initiale de l'analyse APK et extraction des artefacts |
| 5 | Implementation des regles statiques et mapping MASVS |
| 6 | Moteur de risque, preuves et generation de rapports |
| 7 | Interface utilisateur, tableau de bord et tests fonctionnels |
| 8 | Stabilisation, documentation finale, demonstration et livraison |

## Risques et contraintes principaux

- Delai limite a deux mois.
- Complexite de l'analyse Android statique.
- Risque de faux positifs et faux negatifs.
- Necessite de rester strictement dans un cadre local et autorise.
- Limitation volontaire du perimetre a l'analyse statique Android.
- Dependances futures possibles a des outils tiers locaux.

## Conclusion

MSAP est positionne comme un projet d'ingenierie cybersécurité et d'architecture d'audit mobile. La Version 1 doit rester realiste, locale et focalisee sur l'analyse statique Android, tout en posant des bases solides pour des evolutions futures.
