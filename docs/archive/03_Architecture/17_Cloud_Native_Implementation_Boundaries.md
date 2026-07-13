# Cloud-Native Implementation Boundaries - MSAP

## Purpose
This document defines the implementation boundaries that must remain stable when coding starts. Each component has explicit responsibilities, inputs, outputs, prohibited behavior and failure behavior.

## Django API
Responsibility: expose authenticated API workflows for projects, audits, APK upload metadata, status, findings, evidence and exports.
Inputs: HTTP requests, authenticated user context, metadata payloads, uploaded APK streams.
Outputs: API responses, PostgreSQL metadata, MinIO object references, Celery task submissions.
Must not do: run heavy APK analysis inline, store raw APK bytes in PostgreSQL, bypass project authorization, send raw APKs to AI providers.
Failure behavior: return controlled HTTP errors, preserve audit status, log correlation IDs and avoid leaking secrets or APK contents.

## Celery Workers
Responsibility: execute asynchronous APK analysis tasks and produce raw and normalized analysis outputs.
Inputs: task IDs, audit IDs, `ObjectStorageReference` records, YAML rules, analyzer configuration.
Outputs: raw analyzer results, normalized artifacts, findings, evidence records, task status updates.
Must not do: expose public endpoints, make authorization decisions for users, write objects outside scoped MinIO prefixes, call optional AI with raw data.
Failure behavior: mark task failed or retryable, capture error summaries, keep partial artifacts traceable and avoid infinite retries.

## MinIO Storage Service
Responsibility: store APKs, artifacts, evidence objects, reports and exports as private S3-compatible objects.
Inputs: object writes from backend, workers and report generator.
Outputs: object reads, metadata checks, lifecycle cleanup targets.
Must not do: host the MSAP application, enforce business authorization alone, store relational metadata as the source of truth.
Failure behavior: fail closed on unavailable buckets or denied access; callers must preserve pending or failed states in PostgreSQL.

## PostgreSQL Metadata Layer
Responsibility: persist relational business state, object references, audit status, findings, evidence summaries, scores and report metadata.
Inputs: validated writes from API, workers and generators.
Outputs: queryable audit state, relationships and object references.
Must not do: store raw APK payloads or large binary reports, replace MinIO lifecycle management, hold unredacted external AI context unless explicitly approved.
Failure behavior: transactions roll back on inconsistent writes; object writes without database references require cleanup reconciliation.

## Analyzer Adapters
Responsibility: wrap external or internal analysis tools behind stable interfaces.
Inputs: APK object reference, worker scratch path, adapter configuration.
Outputs: raw analyzer result objects and structured summaries.
Must not do: define MASVS or ATT&CK business logic, decide final risk alone, assume APK input is trusted.
Failure behavior: return bounded error objects with tool name, exit status, timeout state and safe logs.

## Normalization Layer
Responsibility: convert raw analyzer outputs into stable internal artifacts.
Inputs: raw analyzer results, extraction outputs and parser results.
Outputs: normalized artifacts such as permissions, components, manifest attributes, URLs, domains, certificates and code patterns.
Must not do: create findings without rule evaluation, produce malware verdicts, mutate raw analyzer objects.
Failure behavior: record normalization errors per artifact type and continue where partial normalization is safe.

## MASVS Engine
Responsibility: evaluate normalized artifacts against OWASP MASVS-oriented rules.
Inputs: normalized artifacts, YAML MASVS rules, audit context.
Outputs: AppSec findings, MASVS mappings, confidence and evidence links.
Must not do: perform ATT&CK triage, classify malware, fetch APK bytes directly unless mediated by artifacts.
Failure behavior: mark failed rules as evaluation errors and continue evaluating independent rules.

## ATT&CK Triage Engine
Responsibility: map suspicious indicators to MITRE ATT&CK Mobile techniques cautiously.
Inputs: normalized artifacts, YAML ATT&CK indicator rules, evidence candidates.
Outputs: suspicious indicators, ATT&CK mappings, confidence and evidence links.
Must not do: guarantee malware classification, produce legal or incident-response conclusions, override analyst review.
Failure behavior: emit cautious incomplete triage status when rules cannot be evaluated.

## Evidence Engine
Responsibility: create traceable evidence records that support findings and suspicious indicators.
Inputs: findings, indicators, normalized artifacts, source locations and redaction settings.
Outputs: evidence records, snippets, object references and redaction status.
Must not do: expose secrets unnecessarily, store large evidence blobs in PostgreSQL, invent evidence without source traceability.
Failure behavior: block report generation for critical missing evidence only when required; otherwise mark evidence incomplete.

## Report Generator
Responsibility: generate JSON exports and later PDF reports from approved audit state.
Inputs: audit metadata, findings, indicators, evidence, risk summaries and object references.
Outputs: JSON export objects, report objects and report metadata.
Must not do: re-run analysis, bypass redaction policy, expose raw APK contents.
Failure behavior: mark report generation failed with a safe error summary and preserve previous successful report objects.

## Optional AI Assistant
Responsibility: provide optional post-analysis explanation or prioritization using redacted context only.
Inputs: redacted findings, indicators, evidence summaries and user prompt templates.
Outputs: AI-generated assistant text tagged as advisory.
Must not do: receive raw APKs, receive unredacted secrets, create authoritative findings, replace analyst validation, run in V1.0 implementation.
Failure behavior: degrade gracefully with no impact on core audit status or report generation.

## Kubernetes Infrastructure
Responsibility: run and isolate frontend, backend, workers, Redis, PostgreSQL and MinIO through Kubernetes and future Helm packaging.
Inputs: images, Helm values, ConfigMaps, Secrets, PVCs and ingress configuration.
Outputs: running workloads, service discovery, network policy, persistent storage and operational status.
Must not do: encode application business rules, store secrets in plain values, expose Redis/PostgreSQL/MinIO publicly by default.
Failure behavior: workloads restart according to policy, readiness probes prevent bad routing, failed jobs and pods remain inspectable.
