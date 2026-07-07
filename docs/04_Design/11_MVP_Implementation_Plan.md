# Plan d'Implementation MVP - MSAP V1

## Objectif

Ce plan organise le developpement MVP de MSAP sur un perimetre realiste pour un PFA de deux mois. Il couvre une plateforme locale d'analyse statique Android APK basee sur OWASP MASVS, sans MobSF, Frida, emulateur Android, analyse dynamique ou iOS.

## Milestones

### 1. Backend foundation

**Goal**: mettre en place le socle backend local.

**Tasks**:

- Initialiser le projet Django REST au moment de la phase de developpement.
- Configurer les settings locaux.
- Preparer la structure applicative: projets, audits, analyse, reporting.
- Definir les conventions d'erreur et de logs.

**Expected output**: API backend locale demarrable avec structure claire.

**Acceptance criteria**:

- Le serveur backend demarre localement.
- Les routes de base sont exposees.
- La configuration ne depend d'aucun service distant.

### 2. Database models

**Goal**: implementer le modele de donnees V1.

**Tasks**:

- Creer les modeles User, Project, Audit, APKFile, StaticAnalysisResult, Finding, Evidence, MASVSControl, Rule, RiskScore et Report.
- Ajouter les migrations.
- Definir les contraintes d'unicite et relations.
- Preparer les serializers API.

**Expected output**: schema PostgreSQL local coherent avec le modele de donnees.

**Acceptance criteria**:

- Les migrations s'executent sans erreur.
- Les relations principales sont testables.
- Les champs critiques sont valides.

### 3. APK upload service

**Goal**: permettre le depot local et controle d'un APK.

**Tasks**:

- Creer l'endpoint d'upload.
- Valider taille, extension et lisibilite.
- Normaliser le nom de stockage.
- Calculer SHA-256.
- Enregistrer les metadonnees initiales.

**Expected output**: APK stocke localement et rattache a un audit.

**Acceptance criteria**:

- Un APK valide est accepte.
- Un fichier invalide est rejete proprement.
- Le hash SHA-256 est persiste.

### 4. Static analyzer service

**Goal**: extraire les artefacts necessaires a l'analyse statique.

**Tasks**:

- Definir l'orchestrateur d'analyse.
- Integrer progressivement les adaptateurs locaux prevus pour manifeste, ressources et code decompile.
- Stocker les artefacts extraits dans un repertoire local controle.
- Gerer les erreurs partielles d'extraction.

**Expected output**: artefacts exploitables par le moteur de regles.

**Acceptance criteria**:

- Le manifeste est accessible au moteur.
- Les ressources textuelles sont parcourables.
- Le code decompile ou representation equivalente est disponible pour recherche de motifs.

### 5. YAML rule loader

**Goal**: charger et valider `rules/masvs_static_rules.yaml`.

**Tasks**:

- Lire le fichier YAML local.
- Valider le schema officiel.
- Verifier les enumerations.
- Compiler les regex necessaires.
- Synchroniser ou charger les regles en memoire.

**Expected output**: catalogue de regles valide et exploitable.

**Acceptance criteria**:

- Les 14 regles initiales sont chargees.
- Une regle invalide bloque l'analyse avec un message clair.
- Les IDs sont uniques.

### 6. Rule execution engine

**Goal**: executer les detections statiques.

**Tasks**:

- Implementer les executors par `detection_type`.
- Appliquer les conditions manifeste.
- Appliquer les recherches de chaines et regex.
- Appliquer les verifications XML de configuration reseau.
- Produire des findings normalises.

**Expected output**: findings techniques issus des regles MSAP.

**Acceptance criteria**:

- Les regles critiques du manifeste fonctionnent.
- Les detections de secrets et HTTP produisent des preuves tronquees.
- Les erreurs de regle n'arretent pas tout le pipeline sauf erreur de schema.

### 7. MASVS mapping engine

**Goal**: rattacher les findings aux categories OWASP MASVS.

**Tasks**:

- Creer les categories MASVS retenues.
- Mapper `masvs_category` vers `MASVSControl`.
- Produire une synthese par categorie.

**Expected output**: findings classes par categorie MASVS.

**Acceptance criteria**:

- Chaque finding possede une categorie MASVS.
- La synthese MASVS est exposable par API.

### 8. Risk scoring engine

**Goal**: calculer une priorisation initiale des risques.

**Tasks**:

- Definir une matrice simple par severite et confiance.
- Calculer un score par finding.
- Calculer une synthese globale d'audit.
- Documenter les limites du score.

**Expected output**: scores de risque indicatifs et persistés.

**Acceptance criteria**:

- Chaque finding possede une severite et un score.
- Le score global est reproductible.
- Le rapport indique que le scoring reste indicatif.

### 9. Report generator

**Goal**: generer un rapport local exploitable.

**Tasks**:

- Definir le template de rapport.
- Inclure perimetre, methode, limites, synthese, findings, preuves et recommandations.
- Generer un fichier local.
- Exposer l'endpoint de telechargement.

**Expected output**: rapport d'audit local.

**Acceptance criteria**:

- Un rapport est genere pour un audit termine.
- Les preuves sont lisibles et limitees.
- Le rapport ne promet pas d'analyse dynamique.

### 10. Frontend foundation

**Goal**: creer l'interface minimale de pilotage.

**Tasks**:

- Initialiser le frontend pendant la phase de developpement.
- Preparer authentification, navigation et appels API.
- Creer les pages projets, audits et upload APK.

**Expected output**: interface locale utilisable pour le flux principal.

**Acceptance criteria**:

- L'utilisateur peut creer un projet et un audit.
- L'utilisateur peut deposer un APK.
- Les erreurs API sont affichees proprement.

### 11. Dashboard

**Goal**: afficher les resultats d'audit de facon orientee securite.

**Tasks**:

- Afficher le statut d'analyse.
- Afficher le nombre de findings par severite.
- Afficher la synthese MASVS.
- Permettre la consultation du detail d'un finding.

**Expected output**: dashboard d'audit lisible.

**Acceptance criteria**:

- Les findings sont filtrables par severite et categorie.
- Les preuves et recommandations sont accessibles.
- La synthese reste claire pour une soutenance PFA.

### 12. Testing

**Goal**: valider le comportement critique du MVP.

**Tasks**:

- Tester le chargement du YAML.
- Tester la validation d'upload.
- Tester les regles principales.
- Tester le scoring.
- Tester la generation de rapport.
- Preparer des APK ou artefacts de test autorises.

**Expected output**: base de tests fonctionnels et techniques.

**Acceptance criteria**:

- Les tests critiques passent localement.
- Les erreurs attendues sont couvertes.
- Les faux positifs connus sont documentes.

### 13. Docker deployment

**Goal**: preparer un deploiement local reproductible.

**Tasks**:

- Creer une configuration Docker locale.
- Configurer backend, frontend et PostgreSQL.
- Monter les volumes locaux pour APK, artefacts et rapports.
- Documenter les commandes de lancement.

**Expected output**: environnement local reproductible pour demonstration.

**Acceptance criteria**:

- MSAP se lance localement via Docker.
- Les donnees restent sur la machine.
- La documentation de deploiement est claire.

## Priorisation recommandee

Pour un PFA de deux mois, la priorite doit rester sur:

1. Modele de donnees et API.
2. Upload APK et extraction d'artefacts.
3. Chargement YAML et execution des 14 regles initiales.
4. Preuves, MASVS mapping et rapport.
5. Interface minimale et dashboard.
6. Tests et documentation de livraison.
