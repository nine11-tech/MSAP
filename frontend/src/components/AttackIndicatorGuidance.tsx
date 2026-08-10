import type { Indicator } from "../api/types";


type GuidanceIndicator = Pick<
  Indicator,
  | "triage_interpretation"
  | "auditor_explanation"
  | "dynamic_verification_scenario"
  | "source_evidence"
  | "mapping_rationale"
  | "false_positive_considerations"
>;


export function AttackIndicatorGuidance({
  indicator,
}: {
  indicator: GuidanceIndicator;
}) {
  const references = indicator.source_evidence || [];
  return (
    <div className="attack-indicator-guidance">
      <p>
        <strong>What this means:</strong>{" "}
        {indicator.auditor_explanation || indicator.triage_interpretation}
      </p>
      <p>
        <strong>Why ATT&amp;CK maps it:</strong>{" "}
        {indicator.mapping_rationale || "The static capability is associated with this technique but does not prove execution."}
      </p>
      <section className="attack-source-support">
        <strong>Supporting source evidence:</strong>
        {references.length ? references.slice(0, 3).map((reference, index) => (
          <div className="attack-source-reference" key={`${reference.path}-${reference.start_line}-${index}`}>
            {reference.source_lines_available ? (
              <>
                <small className="mono">
                  {reference.representation_label} · {reference.path} · line {reference.start_line}
                  {reference.method_name ? ` · ${reference.method_name}` : ""}
                </small>
                <code><span>{reference.start_line}</span>{reference.excerpt || " "}</code>
                <small>{reference.provenance}</small>
                {reference.manual_validation_required ? (
                  <small>Multiple candidate locations were found; validate the shown call path.</small>
                ) : null}
              </>
            ) : (
              <p className="muted">
                Source lines not applicable or unavailable. {reference.reason}
              </p>
            )}
          </div>
        )) : (
          <p className="muted">
            No source line was recorded. Re-run static analysis to resolve newly indexed source evidence.
          </p>
        )}
      </section>
      <p className="attack-verification-scenario">
        <strong>Suggested dynamic verification:</strong>{" "}
        {indicator.dynamic_verification_scenario || "Exercise the related feature in an authorized test environment and correlate runtime behavior with this static signal."}
      </p>
      <p>
        <strong>False-positive considerations:</strong>{" "}
        {indicator.false_positive_considerations || "Legitimate applications may expose the same capability. Validate business purpose and surrounding code."}
      </p>
    </div>
  );
}
