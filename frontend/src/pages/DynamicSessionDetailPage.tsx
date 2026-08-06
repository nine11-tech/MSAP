import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  getDynamicSession,
  listDynamicSessionArtifacts,
  listDynamicSessionEvents,
  listDynamicSessionStages,
} from "../api/msap";
import type {
  DynamicSession,
  DynamicSessionArtifact,
  DynamicSessionEvent,
  DynamicSessionStage,
} from "../api/types";
import {
  Card,
  EmptyState,
  ErrorMessage,
  LoadingState,
  MetricCard,
  PageHeader,
  SectionHeader,
  StatusBadge,
  errorMessage,
  formatDate,
  formatDuration,
  formatEnum,
} from "../components/Common";
import { StageTimeline } from "../components/StageTimeline";

export function DynamicSessionDetailPage() {
  const { sessionId } = useParams();
  const id = Number(sessionId);
  const [session, setSession] = useState<DynamicSession | null>(null);
  const [stages, setStages] = useState<DynamicSessionStage[]>([]);
  const [events, setEvents] = useState<DynamicSessionEvent[]>([]);
  const [artifacts, setArtifacts] = useState<DynamicSessionArtifact[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");

  const loadSession = useCallback(async (showLoading = true) => {
    if (!Number.isFinite(id)) {
      setError("Invalid dynamic session id.");
      setLoading(false);
      return;
    }
    if (showLoading) setLoading(true);
    setRefreshing(!showLoading);
    setError("");
    try {
      const [sessionData, stageData, eventData, artifactData] = await Promise.all([
        getDynamicSession(id),
        listDynamicSessionStages(id),
        listDynamicSessionEvents(id),
        listDynamicSessionArtifacts(id),
      ]);
      setSession(sessionData);
      setStages(stageData);
      setEvents(eventData);
      setArtifacts(artifactData);
    } catch (requestError) {
      setError(errorMessage(requestError));
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [id]);

  useEffect(() => {
    void loadSession();
  }, [loadSession]);

  const sortedEvents = useMemo(
    () => [...events].sort((left, right) => left.sequence_number - right.sequence_number),
    [events],
  );
  const sortedArtifacts = useMemo(
    () =>
      [...artifacts].sort(
        (left, right) => left.sequence_number - right.sequence_number,
      ),
    [artifacts],
  );
  const latestStage = useMemo(
    () =>
      [...stages].sort(
        (left, right) =>
          new Date(right.updated_at).getTime() - new Date(left.updated_at).getTime(),
      )[0],
    [stages],
  );

  if (loading) return <LoadingState label="Loading dynamic session..." />;
  if (!session) return <ErrorMessage message={error || "Dynamic session not found."} />;

  return (
    <>
      <PageHeader
        eyebrow={`Session #${session.id}`}
        title="Dynamic MVP Evidence"
        description={`Job #${session.job} on ${session.device_serial || `device #${session.device}`}`}
        actions={
          <>
            <Link className="button button-secondary" to="/dynamic">
              Back to Dynamic Lab
            </Link>
            <button
              className="button button-primary"
              onClick={() => void loadSession(false)}
              disabled={refreshing}
            >
              {refreshing ? "Refreshing..." : "Refresh evidence"}
            </button>
          </>
        }
      />
      {error ? <ErrorMessage message={error} /> : null}

      <div className="metric-grid dynamic-metrics">
        <MetricCard label="Session state" value={formatEnum(session.state)} accent />
        <MetricCard label="Cleanup" value={formatEnum(session.cleanup_status)} />
        <MetricCard
          label="Duration"
          value={formatDuration(session.duration_seconds)}
          detail={session.started_at ? `Started ${formatDate(session.started_at)}` : ""}
        />
        <MetricCard
          label="Latest stage"
          value={latestStage ? formatEnum(latestStage.status) : "None"}
          detail={latestStage ? formatEnum(latestStage.name) : "No stage records"}
        />
      </div>

      <div className="content-grid dynamic-session-grid">
        <Card title="Session summary">
          <dl className="details-list">
            <div>
              <dt>Job</dt>
              <dd>#{session.job}</dd>
            </div>
            <div>
              <dt>Audit</dt>
              <dd>#{session.audit}</dd>
            </div>
            <div>
              <dt>Device</dt>
              <dd>{session.device_serial || `#${session.device}`}</dd>
            </div>
            <div>
              <dt>Started</dt>
              <dd>{formatDate(session.started_at)}</dd>
            </div>
            <div>
              <dt>Finished</dt>
              <dd>{formatDate(session.finished_at)}</dd>
            </div>
          </dl>
          <div className="runtime-flag-grid">
            <BooleanChip label="Network capture" value={session.network_capture_enabled} />
            <BooleanChip label="Frida" value={session.frida_enabled} />
            <BooleanChip label="Runtime CA" value={session.runtime_ca_enabled} />
            <BooleanChip label="UI automation" value={session.ui_automation_enabled} />
          </div>
          {Object.keys(session.tool_versions).length ? (
            <details className="status-details">
              <summary>Tool versions</summary>
              <dl className="details-list">
                {Object.entries(session.tool_versions).map(([key, value]) => (
                  <div key={key}>
                    <dt>{formatEnum(key)}</dt>
                    <dd>{String(value)}</dd>
                  </div>
                ))}
              </dl>
            </details>
          ) : null}
        </Card>

        <Card className="limitations-card" title="Limitations">
          <ul className="limitations-list">
            <li>
              This MVP records lab orchestration evidence. It does not yet
              install or exercise the uploaded target APK.
            </li>
            <li>No malware verdict is produced.</li>
            <li>
              Platform TLS proof is limited to configured lab probes and does
              not guarantee interception for pinned apps.
            </li>
          </ul>
        </Card>
      </div>

      <Card>
        <SectionHeader
          title="Stage timeline"
          description="Runner sequence: preflight, snapshot restore, Frida bridge, Frida smoke, mitmproxy smoke, optional platform TLS probe, cleanup."
        />
        <StageTimeline stages={stages} />
      </Card>

      <div className="content-grid dynamic-session-grid">
        <Card title={`Events (${sortedEvents.length})`}>
          {sortedEvents.length ? (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>#</th>
                    <th>Severity</th>
                    <th>Type</th>
                    <th>Message</th>
                    <th>Created</th>
                  </tr>
                </thead>
                <tbody>
                  {sortedEvents.map((event) => (
                    <tr key={event.id}>
                      <td>{event.sequence_number}</td>
                      <td>
                        <StatusBadge value={event.severity} />
                      </td>
                      <td>{formatEnum(event.event_type)}</td>
                      <td>{event.message || "-"}</td>
                      <td>{formatDate(event.created_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState message="No session events recorded yet." />
          )}
        </Card>

        <Card title={`Artifacts (${sortedArtifacts.length})`}>
          {sortedArtifacts.length ? (
            <div className="artifact-stack">
              {sortedArtifacts.map((artifact) => (
                <ArtifactCard artifact={artifact} key={artifact.id} />
              ))}
            </div>
          ) : (
            <EmptyState message="No session artifacts recorded yet." />
          )}
        </Card>
      </div>
    </>
  );
}

function BooleanChip({ label, value }: { label: string; value: boolean }) {
  return (
    <span className={`boolean-chip ${value ? "enabled" : ""}`}>
      <strong>{label}</strong>
      <small>{value ? "Enabled" : "Disabled"}</small>
    </span>
  );
}

function ArtifactCard({ artifact }: { artifact: DynamicSessionArtifact }) {
  const normalized = artifact.normalized;
  const markers = normalized.markers;
  const passMarkers = markerList(markers, "pass");
  const failMarkers = markerList(markers, "fail");
  return (
    <article className="artifact-card">
      <header>
        <div>
          <strong>{artifact.name || formatEnum(artifact.artifact_type)}</strong>
          <small>
            {formatEnum(artifact.artifact_type)} / {formatEnum(artifact.category)}
          </small>
        </div>
        <div className="artifact-badges">
          <StatusBadge value={artifact.confidence} />
          <StatusBadge value={artifact.redaction_state} />
        </div>
      </header>
      <p>{artifact.summary || "No artifact summary provided."}</p>
      <div className="artifact-facts">
        <span>Status {formatEnum(stringValue(normalized.status))}</span>
        <span>Return {numberValue(normalized.return_code) ?? "-"}</span>
        <span>
          Manual validation {artifact.manual_validation_required ? "required" : "not required"}
        </span>
        {passMarkers.length ? <span className="marker-pass">PASS {passMarkers.join(", ")}</span> : null}
        {failMarkers.length ? <span className="marker-fail">FAIL {failMarkers.join(", ")}</span> : null}
      </div>
      <details>
        <summary>Normalized preview</summary>
        <pre className="json-output">{JSON.stringify(normalized, null, 2)}</pre>
      </details>
    </article>
  );
}

function markerList(value: unknown, key: "pass" | "fail"): string[] {
  if (!isRecord(value) || !Array.isArray(value[key])) return [];
  return value[key].filter((item): item is string => typeof item === "string");
}

function stringValue(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

function numberValue(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}
