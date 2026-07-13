# AI-Assisted Triage Methodology - MSAP

## Purpose

AI-assisted triage helps auditors interpret deterministic MSAP results and draft clearer report text. It is an optional methodology layer after static analysis, evidence collection and scoring.

## Deterministic Findings vs AI Explanations

Deterministic findings are produced by MSAP rules and engines from normalized evidence. AI-generated explanations are draft text based only on those findings, indicators, evidence IDs and scores. AI text cannot create, delete or modify findings.

## Threat Triage vs Malware Verdict

MITRE ATT&CK Mobile indicators support cautious triage. They do not prove that an APK is malicious. AI may explain why an indicator is relevant, but it must not classify the APK as malicious or benign.

## AI Role in MASVS Finding Explanation

AI may summarize the security meaning of a MASVS finding, reference the provided evidence IDs, describe potential impact and draft remediation language. It must not invent additional code locations, evidence or affected assets.

## AI Role in ATT&CK Mobile Contextualization

AI may explain how an indicator relates to a MITRE ATT&CK Mobile tactic or technique. It must use conditional language and emphasize that static indicators require analyst interpretation.

## AI Role in Report Generation

AI may draft executive summaries, section introductions, finding explanations, remediation text, prioritization summaries and conclusions. The report generator must include only AI text that has been validated by an analyst.

## Human-in-the-Loop Validation

Every AI output starts as a draft. The analyst checks consistency with deterministic results, evidence references, wording, uncertainty and confidentiality before accepting it.

## Allowed AI Actions

- Summarize existing deterministic results.
- Explain existing findings and indicators.
- Draft remediation recommendations.
- Improve readability of report text.
- Suggest prioritization narratives based on existing scores.
- Mention uncertainty where evidence is limited.

## Forbidden AI Actions

- Analyze raw APK files.
- Receive raw APKs or full decompiled source code.
- Create findings or indicators.
- Modify deterministic scores.
- Override MASVS or ATT&CK rule results.
- Produce guaranteed malware or benign verdicts.
- Publish final report text without analyst validation.

## Limitations

AI output is probabilistic, may be incomplete and may overstate certainty. It depends on the quality of the provided context and cannot inspect omitted data.

## False Authority Risk

AI-generated text can appear authoritative even when it is only a draft. MSAP must label AI outputs clearly and require analyst validation before report inclusion.

## Analyst Responsibility

The analyst remains accountable for final conclusions, remediation wording, risk interpretation and report publication.

## Recommended Workflow

1. Run deterministic static analysis.
2. Review findings, indicators, evidence and scores.
3. Build minimized AI context from selected results.
4. Redact sensitive values.
5. Generate AI draft text only if AI is enabled.
6. Review and edit the draft.
7. Accept or reject AI output.
8. Include accepted text in the report with traceability.
