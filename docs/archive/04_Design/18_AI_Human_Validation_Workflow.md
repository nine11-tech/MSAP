# AI Human Validation Workflow - MSAP

## Purpose

Human validation ensures AI-generated text remains an analyst-reviewed draft and cannot silently become authoritative report content.

## AI Output Lifecycle

| State | Meaning |
|---|---|
| Draft | AI output generated and not reviewed. |
| Reviewed | Analyst has inspected the output and may request edits. |
| Accepted | Analyst approves the output for report/dashboard use. |
| Rejected | Analyst rejects the output; it is excluded from final reports. |
| Archived | Output is retained for audit trail but no longer active. |

## Analyst Review Steps

1. Confirm the output references only provided finding, indicator and evidence IDs.
2. Check that no new finding or unsupported claim was introduced.
3. Confirm no malware or benign verdict is stated.
4. Verify cautious wording and uncertainty.
5. Edit wording where needed.
6. Accept or reject the output.

## Entry into Final Report

Only accepted AI outputs can be included in final reports. The report generator must exclude draft, reviewed, rejected and archived outputs unless an analyst explicitly accepts them first.

## Rejected AI Output

Rejected output is stored with reviewer, timestamp and rejection reason. It is not reused for final report text.

## Accountability Model

The analyst is accountable for accepted content. The AI provider is treated as a drafting assistant, not an authoritative assessment engine.

## Audit Trail Requirements

- AI request purpose.
- Provider and model.
- Context hash and redaction summary.
- User who requested generation.
- Output lifecycle state.
- Reviewer identity.
- Review timestamp.
- Acceptance, edit or rejection reason.

## UI Implications

- AI actions appear only when enabled.
- Draft AI text is visibly labeled.
- Review controls support accept, edit, reject and archive.
- Final report preview indicates which AI sections are accepted.

## Acceptance Criteria for AI-Assisted Text

- References valid IDs only.
- Contains no invented evidence.
- Does not change deterministic risk or compliance scores.
- Does not classify the APK as malicious or benign.
- Uses cautious wording.
- Includes analyst validation notice.
- Contains no unredacted sensitive values.
