import { useAuth } from "../auth/AuthContext";
import { useSystemStatus } from "../status/SystemStatusContext";
import {
  Card,
  LoadingState,
  PageHeader,
  formatDate,
} from "../components/Common";

export function SystemStatusPage() {
  const { user } = useAuth();
  const { status, loading, refreshing, refresh } = useSystemStatus();

  return (
    <>
      <PageHeader
        eyebrow="Operational awareness"
        title="System status"
        description="Bounded health checks for the services and deterministic security-engine catalogs used by MSAP."
        actions={
          <button
            className="button button-secondary"
            onClick={() => void refresh()}
            disabled={refreshing}
          >
            {refreshing ? "Refreshing…" : "Refresh checks"}
          </button>
        }
      />
      {loading && !status ? <LoadingState label="Checking components…" /> : null}
      {status ? (
        <>
          <div className={`overall-status overall-${status.overall_status.toLowerCase()}`}>
            <div>
              <span className={`status-dot status-${status.overall_status.toLowerCase()}`} />
              <strong>Platform {status.overall_status.toLowerCase()}</strong>
            </div>
            <span>Checked {formatDate(status.checked_at)}</span>
          </div>
          <div className="status-card-grid">
            {status.components.map((component) => (
              <Card className="status-card" key={component.id}>
                <header>
                  <div>
                    <span className={`status-dot status-${component.status.toLowerCase()}`} />
                    <h2>{component.label}</h2>
                  </div>
                  <span className={`badge component-${component.status.toLowerCase()}`}>
                    {component.status}
                  </span>
                </header>
                <p>{component.message}</p>
                <dl className="details-list">
                  <div><dt>Latency</dt><dd>{component.latency_ms === null ? "—" : `${component.latency_ms} ms`}</dd></div>
                  <div><dt>Last successful</dt><dd>{formatDate(component.last_successful_check)}</dd></div>
                </dl>
                {user?.role === "ADMIN" && component.details && Object.keys(component.details).length ? (
                  <details className="status-details">
                    <summary>Capability details</summary>
                    <dl className="details-list">
                      {Object.entries(component.details)
                        .filter(([key]) => key !== "capabilities")
                        .map(([key, value]) => (
                          <div key={key}><dt>{key.replaceAll("_", " ")}</dt><dd>{typeof value === "object" ? JSON.stringify(value) : String(value)}</dd></div>
                        ))}
                    </dl>
                  </details>
                ) : null}
              </Card>
            ))}
          </div>
          {user?.role === "ADMIN" ? (
            <Card title="Deployment metadata">
              <dl className="details-list compact-details">
                <div><dt>Mode</dt><dd>{status.deployment_mode || "—"}</dd></div>
                <div><dt>Application version</dt><dd>{status.application_version || "—"}</dd></div>
              </dl>
            </Card>
          ) : null}
        </>
      ) : null}
    </>
  );
}
