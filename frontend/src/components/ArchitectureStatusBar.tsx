import type {
  ComponentStatus,
  SystemComponent,
} from "../api/types";
import { useSystemStatus } from "../status/SystemStatusContext";
import { formatDate } from "./Common";

const VISIBLE_COMPONENTS = [
  ["api", "API"],
  ["postgresql", "Database"],
  ["redis", "Redis"],
  ["celery", "Worker"],
  ["minio", "MinIO"],
] as const;

const STATUS_RANK: Record<ComponentStatus, number> = {
  OPERATIONAL: 0,
  DISABLED: 1,
  DEGRADED: 2,
  UNAVAILABLE: 3,
};

function securityEngine(components: SystemComponent[]): SystemComponent {
  const parts = components.filter((component) =>
    ["analyzers", "masvs_catalog", "attack_catalog"].includes(component.id),
  );
  const status = parts.reduce<ComponentStatus>(
    (worst, component) =>
      STATUS_RANK[component.status] > STATUS_RANK[worst]
        ? component.status
        : worst,
    "OPERATIONAL",
  );
  return {
    id: "security_engine",
    label: "Security Engine",
    status,
    latency_ms: parts.length
      ? Math.max(...parts.map((part) => part.latency_ms || 0))
      : null,
    message:
      status === "OPERATIONAL" ? "Operational" : "Attention required",
    last_successful_check: null,
  };
}

export function ArchitectureStatusBar() {
  const { status, loading, refreshing, refresh } = useSystemStatus();
  const components = status?.components || [];
  const displayed = VISIBLE_COMPONENTS.map(([id, label]) => {
    const component = components.find((item) => item.id === id);
    return (
      component || {
        id,
        label,
        status: "UNAVAILABLE" as const,
        latency_ms: null,
        message: loading ? "Checking" : "Status unavailable",
        last_successful_check: null,
      }
    );
  });
  displayed.push(securityEngine(components));

  return (
    <section className="architecture-bar" aria-label="Architecture status">
      <div className="architecture-overall">
        <span
          className={`status-dot status-${(
            status?.overall_status || "unknown"
          ).toLowerCase()}`}
          aria-hidden="true"
        />
        <span>
          Platform {status?.overall_status?.toLowerCase() || "checking"}
        </span>
      </div>
      <div className="architecture-components">
        {displayed.map((component) => (
          <div
            className="component-state"
            key={component.id}
            title={`${component.label}: ${component.message}${
              component.latency_ms !== null
                ? ` (${component.latency_ms} ms)`
                : ""
            }`}
          >
            <span
              className={`status-dot status-${component.status.toLowerCase()}`}
              aria-hidden="true"
            />
            <span className="component-label">{component.label}</span>
            <span className="component-value">
              {component.status.toLowerCase()}
            </span>
            <span className="sr-only">
              {component.label} is {component.status.toLowerCase()}
            </span>
          </div>
        ))}
      </div>
      <div className="status-actions">
        <span title={status?.checked_at || undefined}>
          {status ? formatDate(status.checked_at) : "Checking…"}
        </span>
        <button
          className="status-refresh"
          onClick={() => void refresh()}
          disabled={refreshing}
          aria-label="Refresh component status"
        >
          {refreshing ? "Refreshing…" : "Refresh"}
        </button>
      </div>
    </section>
  );
}
