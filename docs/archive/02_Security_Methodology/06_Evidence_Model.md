# Evidence Model - MSAP

## Objective
Le modele de preuve garantit qu'un finding MASVS ou un indicateur ATT&CK Mobile est relie a une source technique verifiable. MSAP conserve les binaires et artefacts volumineux dans MinIO et les references, statuts et metadonnees dans PostgreSQL.

## Evidence storage
Les preuves ne reposent plus sur un chemin disque local comme reference principale. Chaque preuve pointe vers une `ObjectStorageReference` contenant bucket, object key, hash, taille, type, politique de retention et statut de redaction.

## Evidence fields
- `audit_id`, `finding_id` ou `indicator_id`.
- `artifact_id` et `object_storage_reference_id`.
- `source_type`: manifest, resource, string, certificate, decompiled_code, report, export.
- `location`: chemin interne APK, ligne, cle manifest ou offset logique.
- `snippet`: extrait court, redige si necessaire.
- `sha256`, `confidence`, `redacted`, `created_at`.

## Traceability chain
APK object -> analyzer artifact object -> normalized artifact -> rule -> finding/indicator -> evidence -> risk/compliance score -> report object.

## Confidentiality
Les preuves contenant secrets, tokens, URLs internes ou donnees personnelles sont masquees avant affichage, export et usage AI. Kimi AI ne recoit que des preuves redigees post-analyse.
