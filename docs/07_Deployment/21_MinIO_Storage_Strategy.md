# Strategie de Stockage MinIO - MSAP Cloud

## MinIO deployment modes
MinIO peut etre deploye dans le namespace `msap`, dans un namespace stockage partage, ou remplace par un endpoint S3-compatible institutionnel. Son role est le stockage objet des donnees MSAP, pas l'hebergement de l'application.

## Buckets
`msap-apk-uploads`, `msap-artifacts`, `msap-reports`, `msap-exports`, `msap-evidence`.

## Credentials and Kubernetes secrets
Access keys, secret keys et endpoints sont fournis via Kubernetes Secrets. Les credentials sont rotatifs, limites aux operations necessaires et jamais commites.

## Access policies
Buckets prives. Le backend controle les operations utilisateur. Les workers disposent uniquement des droits necessaires pour lire les APK et ecrire artefacts/preuves. Les rapports sont telecharges via backend ou URL pre-signee courte.

## Backup considerations
PostgreSQL et MinIO doivent etre sauvegardes de facon coherente pour eviter references orphelines. Les buckets contenant APK, preuves et rapports suivent la politique institutionnelle.

## Object lifecycle and security controls
Uploads incomplets, artefacts temporaires et exports expires sont nettoyes par CronJob ou lifecycle MinIO. TLS, chiffrement au repos selon environnement, policies minimales, journalisation d'acces, desactivation d'acces public, rotation credentials et verification periodique des buckets sont requis.
