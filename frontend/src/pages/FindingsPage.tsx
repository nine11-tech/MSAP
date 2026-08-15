import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import {
  listAudits,
  listEvidence,
  listFindings,
  listProjects,
} from "../api/msap";
import type { Audit, Evidence, Finding, Project } from "../api/types";
import {
  Card,
  EmptyState,
  ErrorMessage,
  LoadingState,
  PageHeader,
  SeverityBadge,
  errorMessage,
  formatDate,
} from "../components/Common";
import { FindingSourceEvidence } from "../components/CodeEvidenceViewer";

const PAGE_SIZE = 15;

export function FindingsPage() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [audits, setAudits] = useState<Audit[]>([]);
  const [projects, setProjects] = useState<Project[]>([]);
  const [evidence, setEvidence] = useState<Evidence[]>([]);
  const [selected, setSelected] = useState<Finding | null>(null);
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("ALL");
  const [category, setCategory] = useState("ALL");
  const [sort, setSort] = useState("newest");
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    Promise.all([
      listFindings(),
      listAudits(),
      listProjects(),
      listEvidence(),
    ])
      .then(([findingData, auditData, projectData, evidenceData]) => {
        setFindings(findingData);
        setAudits(auditData);
        setProjects(projectData);
        setEvidence(evidenceData);
      })
      .catch((requestError) => setError(errorMessage(requestError)))
      .finally(() => setLoading(false));
  }, []);

  const auditMap = useMemo(
    () => new Map(audits.map((audit) => [audit.id, audit])),
    [audits],
  );
  const projectMap = useMemo(
    () => new Map(projects.map((project) => [project.id, project])),
    [projects],
  );
  const categories = [...new Set(findings.map((item) => item.category).filter(Boolean))];
  const severityWeight: Record<string, number> = {
    Critical: 4,
    High: 3,
    Medium: 2,
    Low: 1,
  };
  const filtered = findings
    .filter((finding) => {
      const haystack = `${finding.rule_id} ${finding.title} ${finding.category}`.toLowerCase();
      return (
        haystack.includes(query.toLowerCase()) &&
        (severity === "ALL" || finding.severity === severity) &&
        (category === "ALL" || finding.category === category)
      );
    })
    .sort((a, b) =>
      sort === "severity"
        ? (severityWeight[b.severity] || 0) - (severityWeight[a.severity] || 0)
        : new Date(b.created_at).getTime() - new Date(a.created_at).getTime(),
    );
  const pages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const visible = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);
  const linkedEvidence = selected
    ? evidence.filter((item) => item.finding === selected.id)
    : [];

  return (
    <>
      <PageHeader
        eyebrow="Deterministic results"
        title="Security findings"
        description="Deterministic static rules and bounded runtime-evidence rules. AI recommendations never create findings or assign risk."
      />
      {error ? <ErrorMessage message={error} /> : null}
      <Card>
        <div className="filter-bar filter-bar-wide">
          <label><span>Search</span><input type="search" value={query} onChange={(event) => { setQuery(event.target.value); setPage(1); }} placeholder="Rule ID, title, category" /></label>
          <label><span>Severity</span><select value={severity} onChange={(event) => { setSeverity(event.target.value); setPage(1); }}><option value="ALL">All severities</option>{["Critical", "High", "Medium", "Low"].map((item) => <option key={item}>{item}</option>)}</select></label>
          <label><span>Framework/category</span><select value={category} onChange={(event) => { setCategory(event.target.value); setPage(1); }}><option value="ALL">All categories</option>{categories.map((item) => <option key={item}>{item}</option>)}</select></label>
          <label><span>Sort</span><select value={sort} onChange={(event) => setSort(event.target.value)}><option value="newest">Newest</option><option value="severity">Severity</option></select></label>
        </div>
        {loading ? <LoadingState label="Loading findings…" /> : visible.length ? (
          <>
            <div className="table-wrap">
              <table>
                <thead><tr><th>Rule</th><th>Finding</th><th>Severity</th><th>Confidence</th><th>MASVS control</th><th>Provenance</th><th>Audit / Project</th><th>Created</th></tr></thead>
                <tbody>{visible.map((finding) => {
                  const audit = auditMap.get(finding.audit);
                  const project = audit ? projectMap.get(audit.project) : undefined;
                  return (
                    <tr key={finding.id} className="clickable-row" onClick={() => setSelected(finding)}>
                      <td className="mono">{finding.rule_id}</td>
                      <td><strong>{finding.title}</strong><small>{finding.status || "Open"}</small></td>
                      <td><SeverityBadge value={finding.severity} /></td>
                      <td>{finding.confidence}</td>
                      <td>{finding.masvs_controls?.join(", ") || finding.category || "—"}</td>
                      <td><small>{finding.provenance === "DETERMINISTIC_DYNAMIC_EVIDENCE" ? `Runtime evidence · ${finding.evidence_count || 0} records` : "Deterministic static rule"}</small></td>
                      <td>{audit ? <Link to={`/audits/${audit.id}`} onClick={(event) => event.stopPropagation()}>{audit.name}</Link> : `#${finding.audit}`}<small>{project?.name || "Unknown project"}</small></td>
                      <td>{formatDate(finding.created_at)}</td>
                    </tr>
                  );
                })}</tbody>
              </table>
            </div>
            <div className="pagination"><span>{filtered.length} results</span><button disabled={page === 1} onClick={() => setPage((value) => value - 1)}>Previous</button><span>Page {page} of {pages}</span><button disabled={page === pages} onClick={() => setPage((value) => value + 1)}>Next</button></div>
          </>
        ) : <EmptyState message="No findings match the current filters." />}
      </Card>
      {selected ? (
        <div className="detail-overlay" role="presentation" onClick={() => setSelected(null)}>
          <aside className="detail-drawer" role="dialog" aria-modal="true" aria-labelledby="finding-detail-title" onClick={(event) => event.stopPropagation()}>
            <button className="drawer-close" onClick={() => setSelected(null)} aria-label="Close finding detail">×</button>
            <p className="eyebrow mono">{selected.rule_id}</p>
            <h2 id="finding-detail-title">{selected.title}</h2>
            <div className="inline-actions"><SeverityBadge value={selected.severity} /><span className="badge badge-neutral">{selected.confidence} confidence</span></div>
            <section><h3>Description</h3><p>{selected.description || "This deterministic check matched the normalized artifact evidence shown below."}</p></section>
            <section><h3>Evidence</h3>{linkedEvidence.length ? linkedEvidence.map((item) => <div className="evidence-block" key={item.id}><strong>{item.source}</strong><code>{item.snippet || "Evidence metadata recorded"}</code></div>) : <p className="muted">No linked evidence returned.</p>}</section>
            <FindingSourceEvidence findingId={selected.id} />
            <section><h3>Mappings</h3><p>{selected.masvs_controls?.join(", ") || selected.category || "Mapping details pending catalog enrichment."}</p>{selected.maswe_ids?.length ? <p>MASWE: {selected.maswe_ids.join(", ")}</p> : null}</section>
            <section><h3>Remediation</h3><p>{selected.recommendation || "Review the affected configuration and apply platform security guidance."}</p></section>
            <section><h3>False-positive considerations</h3><p>{selected.false_positive_guidance || "Validate application context and the affected release configuration."}</p></section>
            <p className="notice">{selected.requires_manual_validation ? "Manual validation is required." : "Deterministic static finding; contextual validation remains recommended."}</p>
          </aside>
        </div>
      ) : null}
    </>
  );
}
