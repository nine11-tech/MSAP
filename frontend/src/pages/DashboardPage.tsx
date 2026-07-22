import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { listAudits, listProjects } from "../api/msap";
import type { Audit, Project } from "../api/types";
import {
  Card,
  ErrorMessage,
  LoadingState,
  PageHeader,
  StatusBadge,
  errorMessage,
} from "../components/Common";

export function DashboardPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [audits, setAudits] = useState<Audit[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    Promise.all([listProjects(), listAudits()])
      .then(([projectData, auditData]) => {
        setProjects(projectData);
        setAudits(auditData);
      })
      .catch((requestError: unknown) => setError(errorMessage(requestError)))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <LoadingState label="Loading dashboard…" />;

  return (
    <>
      <PageHeader
        eyebrow="Overview"
        title="Mobile security workspace"
        description="Create an audit, register an APK upload, run static analysis, and review deterministic results."
        actions={
          <Link className="button button-primary" to="/projects">
            Open projects
          </Link>
        }
      />
      {error ? <ErrorMessage message={error} /> : null}

      <div className="metric-grid">
        <Card className="metric-card">
          <span className="metric-label">Projects</span>
          <strong className="metric-value">{projects.length}</strong>
          <Link to="/projects">View all projects</Link>
        </Card>
        <Card className="metric-card">
          <span className="metric-label">Audits</span>
          <strong className="metric-value">{audits.length}</strong>
          <span className="muted">Across all projects</span>
        </Card>
        <Card className="metric-card">
          <span className="metric-label">Completed</span>
          <strong className="metric-value">
            {
              audits.filter((audit) =>
                audit.status.toLowerCase().includes("completed"),
              ).length
            }
          </strong>
          <span className="muted">Analysis workflow status</span>
        </Card>
      </div>

      <div className="content-grid two-column">
        <Card title="Recent audits">
          {audits.length ? (
            <div className="list-stack">
              {audits.slice(0, 5).map((audit) => (
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
        <Card title="MVP workflow">
          <ol className="workflow-list">
            <li>Create a project and audit.</li>
            <li>Initiate the APK upload contract.</li>
            <li>Confirm the upload metadata and start analysis.</li>
            <li>Review findings, triage signals, scores, and JSON report.</li>
          </ol>
          <p className="notice">
            ATT&amp;CK Mobile indicators support triage. They are not malware
            verdicts.
          </p>
        </Card>
      </div>
    </>
  );
}
