# Analyzer Implementation Guide - MSAP V1

## Analyzer Plugin Pattern

Chaque analyzer plugin expose une interface commune:

- `name`
- `version`
- `supports(apk_file)`
- `run(apk_file, workspace)`
- `returns RawAnalyzerResult`

## Raw Result Schema

- `plugin_name`
- `artifact_type`
- `raw_payload`
- `file_path`
- `status`
- `errors`
- `created_at`

## Normalized Artifact Schema

- `artifact_type`
- `key`
- `value`
- `source`
- `location`
- `metadata`
- `confidence`

## APKTool Adapter

Responsable de l'extraction manifeste, ressources XML, configuration reseau et chaines.

## JADX Adapter

Responsable de l'extraction ou inspection de code decompile lorsque possible.

## Androguard Adapter

Responsable des metadonnees APK, permissions, certificats et signatures lorsque disponible.

## Regex/YARA Custom Adapter

Responsable des motifs secrets, URLs, IPs, domaines, IOC-like strings et heuristiques. YARA reste optionnel en V1.

## MASVS Rule Execution

Le moteur MASVS consomme les artefacts normalises et produit des findings AppSec avec preuves.

## ATT&CK Triage Execution

Le moteur ATT&CK consomme les artefacts normalises et produit des indicateurs suspects avec interpretation prudente.

## Evidence Extraction

Chaque plugin doit fournir assez de contexte pour creer une preuve: source, chemin, ligne si disponible et extrait limite.

## False Positive Management

Les findings et indicateurs doivent avoir un statut analyste: `open`, `reviewed`, `false_positive`, `accepted_risk`.
