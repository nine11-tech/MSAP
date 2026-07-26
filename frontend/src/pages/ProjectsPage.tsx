import { type FormEvent, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { createProject, listProjects } from "../api/msap";
import type { Project } from "../api/types";
import {
  Card,
  EmptyState,
  ErrorMessage,
  LoadingState,
  PageHeader,
  errorMessage,
  formatDate,
} from "../components/Common";
import { useAuth } from "../auth/AuthContext";

export function ProjectsPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const { hasRole } = useAuth();
  const canEdit = hasRole("ADMIN", "ANALYST");

  useEffect(() => {
    listProjects()
      .then(setProjects)
      .catch((requestError: unknown) => setError(errorMessage(requestError)))
      .finally(() => setLoading(false));
  }, []);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    setError("");
    try {
      const project = await createProject({ name, description });
      setProjects((current) => [...current, project]);
      setName("");
      setDescription("");
    } catch (requestError) {
      setError(errorMessage(requestError));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <>
      <PageHeader
        eyebrow="Portfolio"
        title="Projects"
        description="Group related application audits under a single project."
      />
      {error ? <ErrorMessage message={error} /> : null}

      <div className="content-grid sidebar-layout">
        {canEdit ? <Card title="Create project">
          <form className="form-stack" onSubmit={handleSubmit}>
            <label>
              Name
              <input
                value={name}
                onChange={(event) => setName(event.target.value)}
                placeholder="Android client"
                required
              />
            </label>
            <label>
              Description
              <textarea
                value={description}
                onChange={(event) => setDescription(event.target.value)}
                placeholder="Release or application scope"
                rows={4}
              />
            </label>
            <button className="button button-primary" disabled={submitting}>
              {submitting ? "Creating…" : "Create project"}
            </button>
          </form>
        </Card> : (
          <Card title="Read-only access">
            <p className="muted">Your viewer role can inspect projects and assessments but cannot create or modify them.</p>
          </Card>
        )}

        <Card title={`All projects (${projects.length})`}>
          {loading ? (
            <LoadingState label="Loading projects…" />
          ) : projects.length ? (
            <div className="project-grid">
              {projects.map((project) => (
                <Link
                  className="project-card"
                  to={`/projects/${project.id}`}
                  key={project.id}
                >
                  <div>
                    <strong>{project.name}</strong>
                    <p>{project.description || "No description provided."}</p>
                  </div>
                  <small>Created {formatDate(project.created_at)}</small>
                </Link>
              ))}
            </div>
          ) : (
            <EmptyState message="Create the first project to begin an audit." />
          )}
        </Card>
      </div>
    </>
  );
}
