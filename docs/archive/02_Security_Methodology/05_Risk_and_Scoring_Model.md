# Modele de Risque et de Scoring - MSAP

## Risk Scoring Formula

Score indicatif:

```text
risk_score = severity_weight * confidence_weight * exposure_weight * exploitability_weight * impact_weight
```

Le score est normalise sur 100 pour l'audit global.

## Severity

| Severity | Weight |
|---|---|
| Informational | 0.1 |
| Low | 0.3 |
| Medium | 0.6 |
| High | 0.85 |
| Critical | 1.0 |

## Confidence

| Confidence | Weight |
|---|---|
| Low | 0.4 |
| Medium | 0.7 |
| High | 1.0 |

## Impact

L'impact represente l'effet potentiel sur confidentialite, integrite, disponibilite, vie privee ou controle applicatif.

## Exposure

L'exposition augmente lorsqu'un artefact est accessible a d'autres applications, au reseau ou a des composants non proteges.

## Exploitability

L'exploitabilite estime la facilite d'abus, sans effectuer de test intrusif.

## MASVS Compliance Score

Le score MASVS mesure la proportion de regles AppSec non declenchees, ponderee par severite:

```text
compliance_score = 100 - weighted_masvs_findings_penalty
```

Ce score est indicatif et ne constitue pas une certification OWASP MASVS.

## ATT&CK Triage Score

Le score triage synthetise la densite, severite et confiance des indicateurs ATT&CK Mobile:

```text
triage_score = weighted_indicator_sum / max_expected_indicator_weight
```

Il sert a prioriser la revue analyste.

## Overall Risk Score

Le score global combine:

- findings MASVS;
- indicateurs ATT&CK;
- confiance;
- exposition;
- concentration de signaux.

## Prioritization Logic

1. High/Critical avec confiance High.
2. Indicateurs ATT&CK multiples et coherents.
3. Findings MASVS reseau, auth, stockage.
4. Elements Medium avec preuves fortes.
5. Low/Informational pour suivi.

## Examples

- `android:debuggable=true`: High, confidence High, priorite forte.
- `DexClassLoader`: High, confidence High, a revoir selon contexte.
- Obfuscation seule: Low, confidence Low, signal de support uniquement.

## Optional AI and Scoring Boundaries

L'AI ne peut pas changer le score de risque deterministe, le score de conformite MASVS ou le score de triage ATT&CK Mobile. Elle peut seulement expliquer la priorisation a partir des scores existants.

Si une sortie AI suggere une priorite differente, cette suggestion reste un commentaire de revue et ne doit pas ecraser le moteur de scoring.
