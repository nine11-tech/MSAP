# Software Requirements Specification - MSAP

## Introduction

Ce document decrit les exigences initiales de MSAP, plateforme locale d'evaluation de securite mobile. Il sert de reference pour cadrer le developpement, les tests, les livrables et les criteres d'acceptation de la Version 1.

## Vision du projet

MSAP doit fournir un environnement local, structure et extensible pour realiser des audits statiques d'applications Android sous forme d'APK. La plateforme doit aider l'auditeur a identifier des risques, conserver les preuves et produire un rapport aligne avec OWASP MASVS.

## Parties prenantes

- Etudiant porteur du projet.
- Encadrant academique.
- Jury de soutenance.
- Utilisateurs auditeurs.
- Equipes techniques pouvant fournir des APK de test autorises.

## Exigences fonctionnelles

| ID | Exigence | Priorite |
|---|---|---|
| FR-01 | Permettre la creation d'un audit local | Haute |
| FR-02 | Permettre l'ajout d'un fichier APK a analyser | Haute |
| FR-03 | Extraire les informations principales du manifeste Android | Haute |
| FR-04 | Identifier des configurations dangereuses dans le manifeste | Haute |
| FR-05 | Rechercher des secrets et motifs sensibles dans le code decompile | Haute |
| FR-06 | Detecter des usages reseau non securises | Haute |
| FR-07 | Associer chaque constat a une categorie MASVS | Haute |
| FR-08 | Calculer une severite et un score de risque initial | Moyenne |
| FR-09 | Centraliser les preuves techniques par constat | Haute |
| FR-10 | Generer un rapport d'audit local | Moyenne |
| FR-11 | Afficher un tableau de bord synthetique des resultats | Moyenne |

## Exigences non fonctionnelles

- L'application doit fonctionner localement.
- Les analyses doivent etre reproductibles.
- Les resultats doivent etre tracables.
- L'architecture doit etre modulaire.
- Les composants d'analyse doivent etre remplacables ou extensibles.
- L'interface doit rester simple, lisible et orientee audit.
- La documentation doit permettre la reprise du projet par un autre etudiant ou auditeur.

## Exigences de securite

- Aucun fichier APK ne doit etre transmis a un service distant.
- Les fichiers importes doivent etre stockes dans un espace local controle.
- Les chemins de fichiers et noms d'APK doivent etre traites avec prudence.
- Les rapports doivent distinguer clairement les preuves, impacts et recommandations.
- Les analyses doivent etre limitees a des applications pour lesquelles l'utilisateur dispose d'une autorisation.
- Les erreurs d'analyse ne doivent pas exposer d'informations sensibles inutiles.

## Exigences d'audit

- Chaque finding doit contenir un identifiant unique.
- Chaque finding doit inclure une preuve technique.
- Chaque finding doit etre rattache a une categorie OWASP MASVS.
- Chaque finding doit inclure une severite.
- Chaque finding doit proposer une recommandation concrete.
- Les limites de l'analyse statique doivent etre mentionnees dans les rapports.

## Exigences de reporting

- Le rapport doit contenir une synthese executive.
- Le rapport doit contenir une vue detaillee des findings.
- Le rapport doit inclure les preuves collectees.
- Le rapport doit inclure les recommandations.
- Le rapport doit preciser le perimetre et les limites de l'analyse.
- Le rapport doit etre generable localement.

## Exigences de deploiement

- Deploiement local uniquement pour la Version 1.
- Preparation d'une architecture compatible avec Docker local.
- Pas de dependance a un service cloud.
- Pas d'utilisation d'emulateur Android.
- Pas d'integration MobSF dans la Version 1.

## Contraintes

- Duree cible: 8 semaines.
- Perimetre limite a Android APK static analysis.
- Utilisation d'outils locaux uniquement.
- Niveau de maturite attendu: prototype presentable, pas produit commercial complet.
- Les detections doivent etre documentees et justifiables.

## Criteres d'acceptation

- La structure documentaire est complete et coherente.
- Le catalogue initial de regles statiques est disponible.
- L'architecture de la plateforme est documentee.
- La methodologie d'audit est alignee avec OWASP MASVS.
- La Version 1 reste strictement locale et statique.
- Les livrables permettent de demarrer le developpement sans ambiguite majeure.
