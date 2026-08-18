# Static-Finding Driven Dynamic Validation

MSAP dynamic validation starts with a deterministic static finding. The AI may
classify that finding and propose a bounded scenario, but it never creates
findings, assigns severity, confirms vulnerabilities, or receives direct tool
access.

The workflow is now finding-centered:

`Audit → Static Findings → Validate Dynamically → Dynamic Validation Mission → Approve Mission → Finding Validation Agent → Evidence → Oracle → Dynamic Validation Result`

The auditor is not expected to manually invent a PoC. The AI proposes a bounded
mission; MSAP validates and executes it through the existing controlled dynamic
analysis architecture.

## Trust boundary

`static finding → bounded scenario → schema/policy validation → target and capability authorization → auditor approval → Tool Gateway → emulator → evidence → deterministic oracle → linked result/report`

The existing adaptive agent remains available for approved assessment plans.
Finding-driven validation reuses the same planner, `AssessmentPlan`,
capability envelope, adaptive agent, Tool Gateway, emulator, evidence store,
findings, scoring, and reports.

## Mission model

`FindingValidationMission` represents one dynamic validation attempt for one
static `Finding`. It links audit, authorized APK/package metadata, original
finding, generated scenario contract, reused `AssessmentPlan`, reused
`AgentRun`, evidence records, deterministic `DynamicValidationResult`,
provider/model metadata, approval actor/timestamp, hashes, final status, and
limitations.

Mission statuses:

- `DRAFT`
- `GENERATED`
- `VALIDATED`
- `APPROVED`
- `RUNNING`
- `CONFIRMED`
- `NOT_REPRODUCED`
- `INCONCLUSIVE`
- `BLOCKED`
- `NOT_DYNAMICALLY_TESTABLE`
- `FAILED`

The original static finding is not overwritten. The latest mission/result is
displayed as dynamic metadata on the finding, and multiple mission attempts may
exist for the same static finding.

## Scenario contract

The versioned contract is `msap.dynamic-validation-scenario/v1`. It contains
the audit and target, source finding, one approved scenario family, allowed
capabilities, expected evidence, bounded steps and troubleshooting branches,
stop conditions, approval requirement, and decision/tool/time budgets.

Unknown tools, model-supplied executable source, prohibited access instructions,
unbounded branches, target mismatches, scope expansion, and missing evidence
requirements are rejected before approval. A scenario is never executable raw
model text.

## Supported and unsupported findings

The first implementation maps only findings that can use current Tool Gateway
capabilities:

- runtime tampering / Frida resilience / runtime instrumentation;
- debuggable or instrumentable application findings;
- selected exported activity/provider findings when the backend has a safe
  manifest-owned playbook;
- selected UI/logging families as current tool support allows.

Hardcoded secrets and static-only properties normally become
`NOT_DYNAMICALLY_TESTABLE` unless a separate supported runtime exposure can be
observed. MSAP does not fake dynamic confirmation for static-only evidence.

## Result and oracle logic

Results use `msap.dynamic-validation-result/v1` and link the source finding,
scenario/mission, agent run, evidence IDs, artifact IDs, oracle results,
confidence, summary, limitations, and next manual step.

Mission final status is backend-owned:

- `CONFIRMED` requires deterministic oracle support and linked evidence.
- `NOT_REPRODUCED` means the PoC ran with meaningful coverage but supporting
  evidence was not observed.
- `INCONCLUSIVE` means coverage or evidence was insufficient.
- `BLOCKED` means lab/tool/runtime failure prevented completion.
- `NOT_DYNAMICALLY_TESTABLE` means no current safe Tool Gateway playbook can
  validate the selected finding.

AI text alone cannot mark a finding confirmed.

## Troubleshooting

Runtime problems use only backend-owned bounded branches: one launch retry with
device status/screenshot, one UI dump retry with screenshot fallback, one
bounded log recapture after a safe interaction, and foreground-target checks.
Frida unavailability is reported as blocked/not assessable/inconclusive; setup
is never invented or performed without approval. Budgets remain authoritative
across retries.

## API workflow

- `GET /api/findings/?audit={id}` lists static findings with dynamic mission
  metadata and supported playbooks.
- `POST /api/findings/{id}/dynamic-validation/generate/` creates a mission for
  one finding. The request body is closed and does not accept model IDs,
  capability envelopes, tool arguments, or target scope.
- `GET /api/dynamic/finding-validations/{id}/` returns mission state.
- `POST /api/dynamic/finding-validations/{id}/approve/` records explicit
  Analyst/Admin approval and approves the linked `AssessmentPlan`.
- `POST /api/dynamic/finding-validations/{id}/start/` starts the existing
  adaptive agent against the approved mission.
- `GET /api/dynamic/finding-validations/{id}/timeline/` returns scenario step
  to action/observation traceability.
- `GET /api/dynamic/finding-validations/{id}/evidence/` returns linked
  evidence.

Viewer users may read missions but cannot generate, approve, or start them.

## UI workflow

Dynamic Lab places Finding-Driven Dynamic Validation above the generic
assessment controls:

1. static findings panel with supported/unsupported state;
2. mission review with hypothesis, PoC steps, tools, evidence, limitations,
   and security checks;
3. explicit approval boundary;
4. start action after approval;
5. live PoC timeline with decision summary, action, observation,
   troubleshooting, evidence goal, and oracle/result;
6. evidence grouped by screenshots, logs, UI, runtime/Frida, and tool output.

Advanced operator controls remain available but collapsed by default.

## Report integration

The existing JSON report includes `finding_validation_missions` under
`dynamic_assessments`. Each mission record reports the static finding, mission
ID, run ID, hypothesis, PoC scenario summary, executed actions,
troubleshooting, evidence IDs, oracle result, final conclusion, limitations,
and hashes. No separate report framework is introduced.

## Security boundaries

The browser cannot supply arbitrary model IDs, provider endpoints, capability
envelopes, Frida source, shell commands, ADB shell commands, filesystem paths,
Docker access, credentials, or cross-audit finding IDs.

Credentials, arbitrary shell/ADB, host/database/filesystem access, arbitrary
Frida source, destructive actions, and unsupported workflows are outside this
capability envelope. The enforcement boundary remains backend validation,
policy authorization, explicit approval, Tool Gateway execution, evidence
persistence, and deterministic oracles.
