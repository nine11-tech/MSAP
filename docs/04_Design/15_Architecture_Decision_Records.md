# Architecture Decision Records - MSAP

## ADR-001: Local-first architecture

**Context**: Les APK peuvent contenir du code proprietaire et des donnees sensibles.

**Decision**: MSAP V1 fonctionne localement, sans service distant.

**Consequences**: Meilleure confidentialite, mais l'installation locale doit gerer les dependances.

**Alternatives considered**: service cloud, API externe d'analyse. Rejetees pour confidentialite et contraintes PFA.

## ADR-002: Static analysis only for Version 1

**Context**: Le delai PFA impose un perimetre realiste.

**Decision**: V1 couvre uniquement l'analyse statique Android APK.

**Consequences**: Pipeline plus maitrisable, mais pas d'observation runtime.

**Alternatives considered**: analyse dynamique, instrumentation, sandbox. Reportees hors V1.

## ADR-003: Excluding MobSF from V1 dependencies

**Context**: Le projet doit demontrer une architecture propre et eviter une dependance centrale a un outil monolithique.

**Decision**: Toute dependance a MobSF est exclue du perimetre V1.

**Consequences**: Plus de controle sur les modules, mais plus d'effort de conception.

**Alternatives considered**: baser le MVP sur MobSF. Rejete pour V1.

## ADR-004: Plugin-based analyzer architecture

**Context**: APKTool, JADX, Androguard et regex/YARA produisent des formats differents.

**Decision**: Utiliser un gestionnaire de plugins d'analyse.

**Consequences**: Extensibilite accrue, contrat plugin a definir.

**Alternatives considered**: analyseur unique. Rejete pour manque de flexibilite.

## ADR-005: Normalization layer before rule engines

**Context**: Les moteurs MASVS et ATT&CK doivent consommer des donnees coherentes.

**Decision**: Ajouter une couche de normalisation entre resultats bruts et moteurs de regles.

**Consequences**: Meilleure maintenabilite, effort initial supplementaire.

**Alternatives considered**: regles directement sur outputs outils. Rejete pour couplage fort.

## ADR-006: Hybrid MASVS + MITRE ATT&CK Mobile model

**Context**: MSAP doit couvrir audit AppSec et triage menace sans confusion.

**Decision**: Utiliser OWASP MASVS pour findings AppSec et MITRE ATT&CK Mobile pour indicateurs de triage.

**Consequences**: Positionnement cybersécurité plus fort, mais wording prudent obligatoire.

**Alternatives considered**: MASVS seul ou triage menace seul. Juges moins complets.

## ADR-007: Evidence-first finding model

**Context**: Un audit professionnel doit etre defensible.

**Decision**: Chaque finding ou indicateur doit etre lie a une preuve.

**Consequences**: Meilleure tracabilite et reporting, mais exigences plus strictes sur l'extraction.

**Alternatives considered**: resultats sans preuves detaillees. Rejete.

## ADR-008: Docker Compose local deployment

**Context**: Le MVP doit etre deployable sur poste institutionnel.

**Decision**: Cible de deploiement Docker Compose local.

**Consequences**: Reproductibilite accrue, vigilance ARM64 necessaire.

**Alternatives considered**: installation manuelle uniquement. Rejetee pour demonstration et livraison.

## ADR-009: Optional AI-assisted triage and reporting layer

**Context**: MSAP produces deterministic findings, indicators, evidence and scores that can be dense for final reporting. AI may help draft clearer summaries and explanations, but external AI introduces confidentiality, non-determinism and availability concerns.

**Decision**: Add Kimi AI as an optional post-analysis assistant for V1.1. It is disabled by default, receives only redacted normalized context, and cannot replace deterministic rules, evidence, scores or analyst judgment.

**Consequences**: Reports may become easier to read when AI is enabled and approved. The platform must add context construction, redaction, prompt templates, audit logging and human validation. Core V1 remains fully functional without AI.

**Alternatives considered**:

- No AI: safest and simplest, but does not help draft readable analyst text.
- External AI assistant: useful for report wording, but requires redaction and institutional approval.
- Local LLM: better data locality, but heavier operational requirements and still non-deterministic.
- Direct raw APK AI analysis: rejected because it violates confidentiality, local-first positioning and evidence-based deterministic design.

**Final decision**: Optional post-analysis AI assistant, disabled by default.
