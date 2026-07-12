# Modele de Preuve - MSAP

## What Is Audit Evidence

Une preuve est un element technique observable qui justifie un finding MASVS ou un indicateur ATT&CK Mobile. Elle permet la tracabilite, la validation analyste et la generation d'un rapport defensible.

## Evidence Sources

- AndroidManifest.xml.
- Permissions.
- Components.
- network_security_config.
- Ressources.
- Strings.
- Code decompile.
- Certificat et signature.
- Metadonnees APK.

## Evidence Fields

- `audit_id`
- `standard`
- `rule_id` ou `indicator_id`
- `source`
- `artifact_type`
- `file_path`
- `line_number`
- `snippet`
- `redacted`
- `confidence`
- `created_at`

## Evidence Examples

- `<application android:debuggable="true">`
- `<uses-permission android:name="android.permission.READ_SMS" />`
- `DexClassLoader(...)`
- `http://example.invalid/gate`

## Traceability

```text
APK artifact -> rule -> finding/indicator -> standard mapping -> score -> report
```

Chaque resultat doit pouvoir etre retrace jusqu'a l'artefact APK source.

## Evidence Storage Assumptions

- Les preuves sont stockees en base lorsque leur taille est limitee.
- Les artefacts volumineux restent sur disque local.
- Les chemins stockes sont relatifs a l'espace d'audit.
- Les preuves doivent survivre a la regeneration d'un rapport.

## Redaction of Sensitive Values

Les secrets, tokens, cles API et donnees personnelles doivent etre masques ou tronques. Le rapport doit montrer assez de contexte pour confirmer le finding sans exposer la valeur complete.

## Confidentiality Considerations

Les preuves peuvent contenir du code proprietaire ou des donnees sensibles. Elles restent locales, soumises au controle d'acces et exclues de tout service distant.

## AI-Safe Evidence Format

Pour l'extension optionnelle AI, les preuves transmises a l'assistant doivent etre minimales, tronquees et redigees. Le contexte AI doit utiliser des `evidence_id` stables afin que les sorties AI referencent les preuves sans recopier de donnees sensibles.

Avant tout appel AI, la couche de redaction masque secrets, tokens, cles API, emails, donnees personnelles, URLs et domaines lorsque leur valeur exacte n'est pas necessaire. Les sorties AI doivent citer les `evidence_id` fournis et ne doivent pas inventer de nouvelles preuves.
