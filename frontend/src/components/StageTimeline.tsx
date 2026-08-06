import type { DynamicSessionStage } from "../api/types";
import { formatDuration, formatEnum, StatusBadge } from "./Common";

const EXPECTED_STAGE_ORDER = [
  "preflight",
  "restore_instrumented_snapshot",
  "refresh_frida_bridge",
  "frida_smoke",
  "mitmproxy_smoke",
  "platform_tls_probe",
  "cleanup_runtime_state",
];

const STAGE_LABELS = new Map<string, string>([
  ["preflight", "Preflight"],
  ["restore_instrumented_snapshot", "Restore Instrumented Snapshot"],
  ["refresh_frida_bridge", "Refresh Frida Bridge"],
  ["frida_smoke", "Frida Smoke"],
  ["mitmproxy_smoke", "mitmproxy Smoke"],
  ["platform_tls_probe", "Platform TLS Probe"],
  ["cleanup_runtime_state", "Cleanup Runtime State"],
]);

export function StageTimeline({ stages }: { stages: DynamicSessionStage[] }) {
  const orderedStages = [...stages].sort((left, right) => {
    const leftOrder = EXPECTED_STAGE_ORDER.indexOf(left.name);
    const rightOrder = EXPECTED_STAGE_ORDER.indexOf(right.name);
    if (leftOrder === -1 && rightOrder === -1) {
      return left.created_at.localeCompare(right.created_at);
    }
    if (leftOrder === -1) return 1;
    if (rightOrder === -1) return -1;
    return leftOrder - rightOrder || left.attempt - right.attempt;
  });

  if (!orderedStages.length) {
    return (
      <div className="stage-timeline-empty">
        No stage evidence recorded for this session yet.
      </div>
    );
  }

  return (
    <ol className="stage-timeline">
      {orderedStages.map((stage) => {
        const passMarkers = stringList(stage.metadata.pass_markers);
        const failMarkers = stringList(stage.metadata.fail_markers);
        const scriptName = stringValue(stage.metadata.script_name);
        const timeoutSeconds = numberValue(stage.metadata.timeout_seconds);
        return (
          <li
            className={`stage-item stage-${stage.status.toLowerCase()}`}
            key={stage.id}
          >
            <span className="stage-marker" aria-hidden="true" />
            <div className="stage-body">
              <header>
                <div>
                  <strong>{STAGE_LABELS.get(stage.name) || formatEnum(stage.name)}</strong>
                  <small>
                    {scriptName || formatEnum(stage.state)}
                    {stage.attempt > 1 ? ` - attempt ${stage.attempt}` : ""}
                  </small>
                </div>
                <StatusBadge value={stage.status} />
              </header>
              <p>{stage.message || "Waiting for runner evidence."}</p>
              <div className="stage-meta">
                <span>{formatDuration(stage.duration_seconds)}</span>
                {timeoutSeconds !== null ? <span>Timeout {timeoutSeconds}s</span> : null}
                {passMarkers.length ? (
                  <span className="marker-pass">PASS {passMarkers.join(", ")}</span>
                ) : null}
                {failMarkers.length ? (
                  <span className="marker-fail">FAIL {failMarkers.join(", ")}</span>
                ) : null}
              </div>
            </div>
          </li>
        );
      })}
    </ol>
  );
}

function stringList(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value
    .filter((item): item is string => typeof item === "string")
    .slice(0, 5);
}

function stringValue(value: unknown): string | null {
  return typeof value === "string" && value ? value : null;
}

function numberValue(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}
