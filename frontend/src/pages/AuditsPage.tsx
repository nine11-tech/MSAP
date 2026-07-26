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

export function AuditsPage() {
  const [audits, setAudits] = useState<Audit[]>([]);
  const [projects, setProjects] = useState<Project[]>([]);
  const [query, setQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState("ALL");
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

  const projectNames = useMemo(
    () => new Map(projects.map((project) => [project.id, project.name])),
    [projects],
  );
  const filtered = audits.filter((audit) => {
    const matchesQuery = `${audit.name} ${projectNames.get(audit.project) || ""}`
      .toLowerCase()
      .includes(query.toLowerCase());
    return (
      matchesQuery &&
      (statusFilter === "ALL" || audit.status === statusFilter)
    );
  });
  const statuses = [...new Set(audits.map((audit) => audit.status))];

  return (
    <>
      <PageHeader
        eyebrow="Assessment portfolio"
        title="Audits"
        description="Track Android assessment lifecycle, execution state, and results across the project portfolio."
      />
      {error ? <ErrorMessage message={error} /> : null}
      <Card>
        <div className="filter-bar">
          <label>
            <span>Search audits</span>
            <input
              type="search"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Audit or project"
            />
          </label>
          <label>
            <span>Status</span>
            <select
              value={statusFilter}
              onChange={(event) => setStatusFilter(event.target.value)}
            >
              <option value="ALL">All states</option>
              {statuses.map((status) => (
                <option value={status} key={status}>{status}</option>
              ))}
            </select>
          </label>
        </div>
        {loading ? (
          <LoadingState label="Loading audits…" />
        ) : filtered.length ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Audit</th>
                  <th>Project</th>
                  <th>Status</th>
                  <th>Created</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {filtered.map((audit) => (
                  <tr key={audit.id}>
                    <td><strong>{audit.name}</strong><small>Audit #{audit.id}</small></td>
                    <td>{projectNames.get(audit.project) || `#${audit.project}`}</td>
                    <td><StatusBadge value={audit.status} /></td>
                    <td>{formatDate(audit.created_at)}</td>
                    <td className="align-right">
                      <Link to={`/audits/${audit.id}`}>Open workspace →</Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState message="No audits match the current filters." />
        )}
      </Card>
    </>
  );
}
