# Strategie de Stockage MinIO - MSAP

## MinIO deployment modes
MinIO peut etre deploye dans le namespace `msap`, dans un namespace stockage partage, ou remplace par un endpoint S3-compatible institutionnel. Son role est le stockage objet des donnees MSAP, pas l'hebergement de l'application.

## Buckets
`msap-apk-uploads`, `msap-artifacts`, `msap-reports`, `msap-exports`, `msap-evidence`.

La convention de reference objet, les types d'objets, le mapping buckets et les exemples de cles sont definis dans [ObjectStorageReference Schema](../04_Design/22_ObjectStorageReference_Schema.md). Les implementations backend et worker doivent creer une ligne `ObjectStorageReference` pour chaque APK, artefact, preuve, rapport ou export stocke dans MinIO.

Convention canonique de cle:

```text
org/{organization_id}/project/{project_id}/audit/{audit_id}/{object_type}/{sha256_or_uuid}/{safe_filename}
```

## Credentials and Kubernetes secrets
Access keys, secret keys et endpoints sont fournis via Kubernetes Secrets. Les credentials sont rotatifs, limites aux operations necessaires et jamais commites.

## Access policies
Buckets prives. Le backend controle les operations utilisateur. Les workers disposent uniquement des droits necessaires pour lire les APK et ecrire artefacts/preuves. Les rapports sont telecharges via backend ou URL pre-signee courte.

## Backup considerations
PostgreSQL et MinIO doivent etre sauvegardes de facon coherente pour eviter references orphelines. Les buckets contenant APK, preuves et rapports suivent la politique institutionnelle.

## Object lifecycle and security controls
Uploads incomplets, artefacts temporaires et exports expires sont nettoyes par CronJob ou lifecycle MinIO. TLS, chiffrement au repos selon environnement, policies minimales, journalisation d'acces, desactivation d'acces public, rotation credentials et verification periodique des buckets sont requis.

MinIO reste exclusivement le stockage objet S3-compatible de MSAP. Il ne doit pas etre utilise pour heberger l'application frontend ou backend.
