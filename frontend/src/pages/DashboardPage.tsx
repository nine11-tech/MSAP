import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  listAudits,
  listComplianceScores,
  listFindings,
  listIndicators,
  listProjects,
} from "../api/msap";
import type {
  Audit,
  ComplianceScore,
  Finding,
  Indicator,
  Project,
} from "../api/types";
import {
  Card,
  ErrorMessage,
  LoadingState,
  PageHeader,
  StatusBadge,
  errorMessage,
} from "../components/Common";
import { useSystemStatus } from "../status/SystemStatusContext";

export function DashboardPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [audits, setAudits] = useState<Audit[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [indicators, setIndicators] = useState<Indicator[]>([]);
  const [compliance, setCompliance] = useState<ComplianceScore[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const { status: systemStatus } = useSystemStatus();

  useEffect(() => {
    Promise.all([
      listProjects(),
      listAudits(),
      listFindings(),
      listIndicators(),
      listComplianceScores(),
    ])
      .then(([projectData, auditData, findingData, indicatorData, scores]) => {
        setProjects(projectData);
        setAudits(auditData);
        setFindings(findingData);
        setIndicators(indicatorData);
        setCompliance(scores);
      })
      .catch((requestError: unknown) => setError(errorMessage(requestError)))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <LoadingState label="Loading dashboard…" />;

  const severityCounts = ["Critical", "High", "Medium", "Low"].map(
    (severity) => ({
      severity,
      count: findings.filter((finding) => finding.severity === severity).length,
    }),
  );
  const maxSeverity = Math.max(1, ...severityCounts.map((item) => item.count));
  const activeAudits = audits.filter((audit) =>
    ["queued", "running", "analyzing"].some((state) =>
      audit.status.toLowerCase().includes(state),
    ),
  ).length;
  const averageCompliance = compliance.length
    ? Math.round(
        compliance.reduce((sum, score) => sum + Number(score.score), 0) /
          compliance.length,
      )
    : null;
  const completed = audits.filter((audit) =>
    audit.status.toLowerCase().includes("completed"),
  ).length;

  return (
    <>
      <PageHeader
        eyebrow="Overview"
        title="Security assessment overview"
        description="Portfolio risk, deterministic Android findings, framework coverage, and platform readiness in one operational view."
        actions={
          <Link className="button button-primary" to="/projects">
            Open projects
          </Link>
        }
      />
      {error ? <ErrorMessage message={error} /> : null}

      <div className="metric-grid dashboard-metrics">
        <Card className="metric-card">
          <span className="metric-label">Projects</span>
          <strong className="metric-value">{projects.length}</strong>
          <span className="metric-trend">Active assessment portfolio</span>
        </Card>
        <Card className="metric-card">
          <span className="metric-label">Audits</span>
          <strong className="metric-value">{audits.length}</strong>
          <span className="metric-trend">{activeAudits} queued or running</span>
        </Card>
        <Card className="metric-card">
          <span className="metric-label">Critical / High</span>
          <strong className="metric-value severity-value">
            {severityCounts[0].count} / {severityCounts[1].count}
          </strong>
          <Link to="/findings">Review security findings</Link>
        </Card>
        <Card className="metric-card">
          <span className="metric-label">MASVS average</span>
          <strong className="metric-value">{averageCompliance === null ? "—" : `${averageCompliance}%`}</strong>
          <span className="metric-trend">Across evaluated audits</span>
        </Card>
        <Card className="metric-card">
          <span className="metric-label">ATT&amp;CK signals</span>
          <strong className="metric-value">{indicators.length}</strong>
          <Link to="/attack-triage">Triage capability signals</Link>
        </Card>
        <Card className="metric-card">
          <span className="metric-label">Architecture</span>
          <strong className={`architecture-value overall-${systemStatus?.overall_status.toLowerCase() || "unknown"}`}>
            {systemStatus?.overall_status || "CHECKING"}
          </strong>
          <Link to="/system-status">Inspect components</Link>
        </Card>
      </div>

      <div className="content-grid dashboard-grid">
        <Card title="Recent audits">
          {audits.length ? (
            <div className="list-stack">
              {audits.slice(0, 6).map((audit) => (
                <Link className="list-row" to={`/audits/${audit.id}`} key={audit.id}>
                  <span>
                    <strong>{audit.name}</strong>
                    <small>Audit #{audit.id}</small>
                  </span>
                  <StatusBadge value={audit.status} />
                </Link>
              ))}
            </div>
          ) : (
            <p className="empty-state">No audits yet.</p>
          )}
        </Card>
        <Card title="Finding severity distribution">
          <div className="bar-chart" aria-label="Finding severity distribution">
            {severityCounts.map((item) => (
              <div className="bar-row" key={item.severity}>
                <span>{item.severity}</span>
                <div className="bar-track">
                  <span
                    className={`bar-fill severity-bg-${item.severity.toLowerCase()}`}
                    style={{ width: `${(item.count / maxSeverity) * 100}%` }}
                  />
                </div>
                <strong>{item.count}</strong>
              </div>
            ))}
          </div>
        </Card>
        <Card title="Audit status distribution">
          <div className="donut-summary">
            <div
              className="donut"
              style={{
                background: `conic-gradient(#2dd4bf 0 ${
                  audits.length ? (completed / audits.length) * 100 : 0
                }%, #f59e0b 0 ${
                  audits.length
                    ? ((completed + activeAudits) / audits.length) * 100
                    : 0
                }%, #334155 0)`,
              }}
              aria-label={`${completed} of ${audits.length} audits completed`}
            >
              <span>{audits.length}</span>
            </div>
            <dl className="chart-legend">
              <div><dt><span className="legend-dot legend-complete" />Completed</dt><dd>{completed}</dd></div>
              <div><dt><span className="legend-dot legend-active" />Active</dt><dd>{activeAudits}</dd></div>
              <div><dt><span className="legend-dot legend-other" />Other</dt><dd>{Math.max(0, audits.length - completed - activeAudits)}</dd></div>
            </dl>
          </div>
        </Card>
        <Card title="Assessment principles">
          <ul className="principles-list">
            <li><strong>Deterministic evidence</strong><span>Findings originate from repeatable static checks.</span></li>
            <li><strong>Explicit confidence</strong><span>Review-required signals remain distinct from confirmed configuration failures.</span></li>
            <li><strong>No malware verdict</strong><span>ATT&amp;CK mappings support triage and do not classify applications.</span></li>
          </ul>
        </Card>
        <Card title="Dynamic Lab MVP">
          <div className="dynamic-dashboard-card">
            <p>
              Validate Android lab orchestration with snapshots, Frida,
              mitmproxy, optional platform TLS proof, and cleanup evidence.
            </p>
            <Link className="button button-secondary" to="/dynamic">
              Open Dynamic Lab
            </Link>
          </div>
        </Card>
      </div>
    </>
  );
}
