# Analysis Pipeline - MSAP Cloud

## Pipeline cible
1. Upload APK via API ou URL pre-signee controlee.
2. Stockage de l'APK dans MinIO bucket `msap-apk-uploads`.
3. Enregistrement PostgreSQL de l'audit et de l'ObjectStorageReference.
4. Enqueue Redis/Celery d'un job d'analyse.
5. Execution par worker scalable ou Kubernetes Job.
6. Extraction statique Android: manifest, permissions, composants, signatures, ressources, chaines, URLs, IPs, domaines, secrets potentiels, code decompile lorsque possible.
7. Stockage des artefacts dans `msap-artifacts`.
8. Normalisation des resultats.
9. Moteurs MASVS et ATT&CK Mobile.
10. Evidence Engine et Risk Engine.
11. Rapport PDF et export JSON stockes dans `msap-reports` et `msap-exports`.

## Queue and worker execution
Les analyses ne s'executent pas dans la requete HTTP. Les workers recuperent les objets depuis MinIO, ecrivent les artefacts, mettent a jour PostgreSQL et exposent un statut consultable. Les retries sont bornes et les echecs doivent laisser des messages exploitables.

## Security constraints
Pas de classification malware garantie, pas d'exploitation offensive, pas d'envoi d'APK brut a Kimi AI ou services externes. Les secrets detectes sont rediges avant affichage/export.
