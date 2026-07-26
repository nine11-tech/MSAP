import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import {
  listAudits,
  listEvidence,
  listIndicators,
  listProjects,
} from "../api/msap";
import type { Audit, Evidence, Indicator, Project } from "../api/types";
import {
  Card,
  EmptyState,
  ErrorMessage,
  LoadingState,
  PageHeader,
  errorMessage,
} from "../components/Common";

export function AttackTriagePage() {
  const [indicators, setIndicators] = useState<Indicator[]>([]);
  const [audits, setAudits] = useState<Audit[]>([]);
  const [projects, setProjects] = useState<Project[]>([]);
  const [evidence, setEvidence] = useState<Evidence[]>([]);
  const [query, setQuery] = useState("");
  const [tactic, setTactic] = useState("ALL");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    Promise.all([listIndicators(), listAudits(), listProjects(), listEvidence()])
      .then(([indicatorData, auditData, projectData, evidenceData]) => {
        setIndicators(indicatorData);
        setAudits(auditData);
        setProjects(projectData);
        setEvidence(evidenceData);
      })
      .catch((requestError) => setError(errorMessage(requestError)))
      .finally(() => setLoading(false));
  }, []);

  const auditMap = useMemo(() => new Map(audits.map((item) => [item.id, item])), [audits]);
  const projectMap = useMemo(() => new Map(projects.map((item) => [item.id, item])), [projects]);
  const tactics = [...new Set(indicators.map((item) => item.tactic).filter(Boolean))];
  const filtered = indicators.filter((indicator) =>
    `${indicator.technique_id} ${indicator.technique_name} ${indicator.title}`.toLowerCase().includes(query.toLowerCase()) &&
    (tactic === "ALL" || indicator.tactic === tactic),
  );
  const techniques = Object.entries(
    filtered.reduce<Record<string, Indicator[]>>((groups, indicator) => {
      const key = `${indicator.technique_id}|${indicator.technique_name}`;
      (groups[key] ||= []).push(indicator);
      return groups;
    }, {}),
  );

  return (
    <>
      <PageHeader eyebrow="Threat-informed review" title="ATT&CK Mobile triage" description="Static capability signals mapped for analyst triage. A declaration or API reference does not prove a technique was executed." />
      <div className="triage-banner" role="note"><strong>Triage signal — not a malware verdict</strong><span>Correlate every indicator with application purpose and individual evidence.</span></div>
      {error ? <ErrorMessage message={error} /> : null}
      <Card>
        <div className="filter-bar">
          <label><span>Search techniques</span><input type="search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Technique ID, name, indicator" /></label>
          <label><span>Tactic</span><select value={tactic} onChange={(event) => setTactic(event.target.value)}><option value="ALL">All tactics</option>{tactics.map((item) => <option key={item}>{item}</option>)}</select></label>
        </div>
        {loading ? <LoadingState label="Loading ATT&CK triage…" /> : techniques.length ? (
          <div className="technique-list">
            {techniques.map(([key, matches]) => {
              const [techniqueId, techniqueName] = key.split("|");
              return (
                <article className="technique-card" key={key}>
                  <header><div><span className="mono technique-id">{techniqueId || "Unmapped"}</span><h2>{techniqueName || "Technique review"}</h2></div><span className="badge badge-neutral">{matches[0].tactic || "Triage"} · {matches.length} signal{matches.length === 1 ? "" : "s"}</span></header>
                  <div className="indicator-stack">
                    {matches.map((indicator) => {
                      const audit = auditMap.get(indicator.audit);
                      const project = audit ? projectMap.get(audit.project) : undefined;
                      const linked = evidence.filter((item) => item.indicator === indicator.id);
                      return (
                        <details key={indicator.id}>
                          <summary><span><strong>{indicator.title}</strong><small>{indicator.confidence} confidence · {audit?.name || `Audit #${indicator.audit}`} · {project?.name || "Unknown project"}</small></span><span>Review evidence</span></summary>
                          <div className="indicator-detail">
                            <p><strong>Mapping rationale:</strong> {indicator.mapping_rationale || indicator.triage_interpretation}</p>
                            <p><strong>Evidence:</strong></p>
                            {linked.length ? linked.map((item) => <code key={item.id}>{item.source}: {item.snippet}</code>) : <span className="muted">No linked evidence returned.</span>}
                            <p><strong>False-positive considerations:</strong> {indicator.false_positive_considerations || "Legitimate applications may expose the same capability. Validate business purpose and surrounding code."}</p>
                            {audit ? <Link to={`/audits/${audit.id}`}>Open audit workspace →</Link> : null}
                          </div>
                        </details>
                      );
                    })}
                  </div>
                </article>
              );
            })}
          </div>
        ) : <EmptyState message="No ATT&CK triage signals match the current filters." />}
      </Card>
    </>
  );
}
