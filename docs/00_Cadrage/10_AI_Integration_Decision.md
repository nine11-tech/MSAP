# AI Integration Decision - MSAP

## Purpose

This document records the decision to introduce Kimi AI as an optional AI-assisted triage and audit reporting layer for MSAP. It clarifies the scope, boundaries, risks and roadmap impact of AI support.

## Why AI Is Being Considered

MSAP produces deterministic findings, indicators, evidence and scores. These results can be technically dense for executive readers and junior analysts. AI can help transform existing results into clearer analyst-facing draft text without changing the underlying assessment.

## Problem AI Helps Solve

- Produce readable executive summaries from deterministic results.
- Explain MASVS findings using existing evidence.
- Contextualize MITRE ATT&CK Mobile indicators with cautious threat language.
- Draft remediation wording.
- Help prioritize review work based on existing scores and evidence.
- Improve report readability while preserving traceability.

## Why AI Is Optional

AI introduces external-service, confidentiality, availability and non-determinism risks. MSAP V1 must remain usable without network access or external dependencies. Therefore, AI is disabled by default and enabled only by explicit configuration.

## Why AI Is Not Core V1

The deterministic V1 core is the evidence-based static APK assessment pipeline: ingestion, local analysis, normalization, MASVS rules, ATT&CK Mobile triage, evidence, scoring and reporting. Kimi AI does not execute rules, inspect raw APKs or determine security truth. It is not required for the platform to function.

## V1.1 Optional Extension

Kimi AI is positioned as a V1.1 optional extension because it depends on configuration, redaction, prompt governance, audit logging and human validation workflows. These design elements should be prepared now but implemented after core V1 delivery.

## Scope of AI Assistance

- Executive summary drafts.
- MASVS finding explanations.
- ATT&CK Mobile indicator contextualization.
- Remediation recommendation wording.
- Risk prioritization narratives.
- Report conclusion drafts.

## Out of Scope

- Raw APK analysis by AI.
- Uploading APK files to Kimi AI.
- Sending full decompiled source code to Kimi AI.
- Replacing deterministic rules or scores.
- Creating new findings not produced by MSAP.
- Guaranteed malware or benign verdicts.
- Autonomous report publication without analyst review.

## Security and Confidentiality Constraints

- AI receives only normalized, redacted, minimized context.
- Raw APKs, full decompiled source, secrets, tokens and credentials are forbidden.
- APK-derived strings are treated as untrusted input.
- AI requests and responses require audit logging without secrets.
- Institution approval is required before enabling an external AI provider.

## Human Validation Requirement

All AI-generated content is a draft. An analyst must review, accept, edit or reject it before it can enter a final report. AI output must remain traceable to finding IDs, indicator IDs and evidence IDs.

## Final Decision

MSAP will document Kimi AI as an optional post-analysis AI assistant for V1.1. It is disabled by default, does not process raw APKs and does not replace deterministic MASVS, ATT&CK Mobile, evidence or scoring engines.

## Impact on Roadmap

Core V1 remains unchanged and local-first. AI preparation is documentation and design only during V1. Kimi connector implementation, prompt governance and validation workflows are planned as optional post-V1.0 work.

## Impact on Architecture

The architecture adds an optional layer after evidence and risk scoring:

```text
Normalized results + findings + indicators + evidence + risk scores
-> AI Context Builder
-> AI Redaction Layer
-> Kimi AI Connector
-> AI Triage & Audit Assistant
-> Report Generator / Dashboard
```

## Impact on Deliverables

V1 deliverables remain deterministic and local-first. AI deliverables are design documents, optional configuration documentation, prompt templates, validation workflow and future test strategy.

## Risks and Mitigations

| Risk | Mitigation |
|---|---|
| Confidential data sent to AI | Redaction layer, minimized context, no raw APK, no full source |
| AI hallucination | Controlled prompts, evidence IDs only, analyst validation |
| False authority | Cautious wording, explicit uncertainty, draft lifecycle |
| External service outage | Disabled-by-default and no-AI fallback |
| API key exposure | Environment variables, no Git secrets, no key logging |
| Scope creep | V1.1 optional extension, not blocking V1 |
