import { type FormEvent, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { createAudit, getProject, listAudits } from "../api/msap";
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
import { useAuth } from "../auth/AuthContext";

export function ProjectDetailPage() {
  const { projectId } = useParams();
  const id = Number(projectId);
  const [project, setProject] = useState<Project | null>(null);
  const [audits, setAudits] = useState<Audit[]>([]);
  const [auditName, setAuditName] = useState("");
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const { hasRole } = useAuth();
  const canEdit = hasRole("ADMIN", "ANALYST");

  useEffect(() => {
    Promise.all([getProject(id), listAudits()])
      .then(([projectData, auditData]) => {
        setProject(projectData);
        setAudits(auditData.filter((audit) => audit.project === id));
      })
      .catch((requestError: unknown) => setError(errorMessage(requestError)))
      .finally(() => setLoading(false));
  }, [id]);

  async function handleCreateAudit(event: FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    setError("");
    try {
      const audit = await createAudit({ project: id, name: auditName });
      setAudits((current) => [audit, ...current]);
      setAuditName("");
    } catch (requestError) {
      setError(errorMessage(requestError));
    } finally {
      setSubmitting(false);
    }
  }

  if (loading) return <LoadingState label="Loading project…" />;
  if (!project) return <ErrorMessage message={error || "Project not found."} />;

  return (
    <>
      <PageHeader
        eyebrow={`Project #${project.id}`}
        title={project.name}
        description={project.description || "No project description provided."}
        actions={
          <Link className="button button-secondary" to="/projects">
            Back to projects
          </Link>
        }
      />
      {error ? <ErrorMessage message={error} /> : null}

      <div className="content-grid sidebar-layout">
        {canEdit ? <Card title="Create audit">
          <form className="form-stack" onSubmit={handleCreateAudit}>
            <label>
              Audit name
              <input
                value={auditName}
                onChange={(event) => setAuditName(event.target.value)}
                placeholder="Release 1.0 assessment"
                required
              />
            </label>
            <button className="button button-primary" disabled={submitting}>
              {submitting ? "Creating…" : "Create audit"}
            </button>
          </form>
        </Card> : (
          <Card title="Read-only access">
            <p className="muted">Your viewer role can review existing audits but cannot create one.</p>
          </Card>
        )}

        <Card title={`Audits (${audits.length})`}>
          {audits.length ? (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Audit</th>
                    <th>Status</th>
                    <th>Created</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {audits.map((audit) => (
                    <tr key={audit.id}>
                      <td>
                        <strong>{audit.name}</strong>
                        <small>#{audit.id}</small>
                      </td>
                      <td>
                        <StatusBadge value={audit.status} />
                      </td>
                      <td>{formatDate(audit.created_at)}</td>
                      <td className="align-right">
                        <Link to={`/audits/${audit.id}`}>Open →</Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState message="No audits exist for this project." />
          )}
        </Card>
      </div>
    </>
  );
}
