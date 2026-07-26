import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { listAudits, listProjects } from "../api/msap";
import type { Audit, Project } from "../api/types";
import {
  Card,
  EmptyState,
  ErrorMessage,
  LoadingState,
  PageHeader,
  StatusBadge,
  errorMessage,
  formatDate,
} from "../components/Common";

export function ReportsPage() {
  const [audits, setAudits] = useState<Audit[]>([]);
  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    Promise.all([listAudits(), listProjects()])
      .then(([auditData, projectData]) => {
        setAudits(auditData);
        setProjects(projectData);
      })
      .catch((requestError) => setError(errorMessage(requestError)))
      .finally(() => setLoading(false));
  }, []);
  const projectMap = useMemo(
    () => new Map(projects.map((project) => [project.id, project.name])),
    [projects],
  );
  const ready = audits.filter((audit) =>
    audit.status.toLowerCase().includes("completed"),
  );

  return (
    <>
      <PageHeader
        eyebrow="Assessment output"
        title="Reports"
        description="Open on-demand JSON assessment data or generate a professional PDF for completed audits."
      />
      {error ? <ErrorMessage message={error} /> : null}
      <Card>
        {loading ? (
          <LoadingState label="Loading report inventory…" />
        ) : ready.length ? (
          <div className="report-grid">
            {ready.map((audit) => (
              <article className="report-card" key={audit.id}>
                <div className="report-icon">PDF</div>
                <div>
                  <p className="eyebrow">{projectMap.get(audit.project)}</p>
                  <h2>{audit.name}</h2>
                  <p className="muted">Assessment audit #{audit.id}</p>
                  <div className="inline-actions">
                    <StatusBadge value={audit.status} />
                    <span className="muted">{formatDate(audit.updated_at)}</span>
                  </div>
                </div>
                <div className="report-actions">
                  <Link className="button button-primary" to={`/audits/${audit.id}/report`}>
                    Open report
                  </Link>
                  <Link className="button button-secondary" to={`/audits/${audit.id}`}>
                    Audit workspace
                  </Link>
                </div>
              </article>
            ))}
          </div>
        ) : (
          <EmptyState message="Reports become available after an audit completes analysis." />
        )}
      </Card>
    </>
  );
}
