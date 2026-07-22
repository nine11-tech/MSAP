import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { getJsonReport } from "../api/msap";
import type { JsonReport } from "../api/types";
import {
  Card,
  EmptyState,
  ErrorMessage,
  LoadingState,
  PageHeader,
  SeverityBadge,
  StatusBadge,
  errorMessage,
} from "../components/Common";

export function ReportPage() {
  const { auditId } = useParams();
  const id = Number(auditId);
  const [report, setReport] = useState<JsonReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    getJsonReport(id)
      .then(setReport)
      .catch((requestError: unknown) => setError(errorMessage(requestError)))
      .finally(() => setLoading(false));
  }, [id]);

  if (loading) return <LoadingState label="Generating JSON report…" />;
  if (!report) return <ErrorMessage message={error || "Report unavailable."} />;

  return (
    <>
      <PageHeader
        eyebrow={`JSON report #${report.report.id}`}
        title={report.audit.name}
        description={`${report.project.name} • On-demand static assessment report`}
        actions={
          <Link className="button button-secondary" to={`/audits/${id}`}>
            Back to audit
          </Link>
        }
      />
      {error ? <ErrorMessage message={error} /> : null}

      <div className="metric-grid">
        <Card className="metric-card">
          <span className="metric-label">Audit status</span>
          <StatusBadge value={report.audit.status} />
          <span className="muted">Static analysis</span>
        </Card>
        <Card className="metric-card">
          <span className="metric-label">Risk score</span>
          <strong className="metric-value">{report.summary.risk.score}</strong>
          <SeverityBadge value={report.summary.risk.severity} />
        </Card>
        <Card className="metric-card">
          <span className="metric-label">MASVS compliance</span>
          <strong className="metric-value">
            {report.summary.masvs_compliance.score}%
          </strong>
          <span className="muted">
            {report.summary.masvs_compliance.failed_rules} of{" "}
            {report.summary.masvs_compliance.evaluated_rules} failed
          </span>
        </Card>
        <Card className="metric-card">
          <span className="metric-label">ATT&amp;CK triage</span>
          <strong className="metric-value">
            {report.summary.attack_mobile_triage.triage_level}
          </strong>
          <span className="muted">
            {report.summary.attack_mobile_triage.triage_indicators} signals
          </span>
        </Card>
      </div>

      <Card title={`Findings (${report.findings.length})`}>
        {report.findings.length ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Rule</th>
                  <th>Title</th>
                  <th>Severity</th>
                  <th>Standard</th>
                </tr>
              </thead>
              <tbody>
                {report.findings.map((finding, index) => (
                  <tr key={index}>
                    <td className="mono">{String(finding.rule_id || "—")}</td>
                    <td>{String(finding.title || "—")}</td>
                    <td>
                      <SeverityBadge value={String(finding.severity || "Low")} />
                    </td>
                    <td>{String(finding.standard || "—")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState message="No findings in this report." />
        )}
      </Card>

      <Card title={`ATT&CK indicators (${report.indicators.length})`}>
        {report.indicators.length ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Indicator</th>
                  <th>Title</th>
                  <th>Technique</th>
                  <th>Severity</th>
                </tr>
              </thead>
              <tbody>
                {report.indicators.map((indicator, index) => (
                  <tr key={index}>
                    <td className="mono">
                      {String(indicator.indicator_id || "—")}
                    </td>
                    <td>{String(indicator.title || "—")}</td>
                    <td>
                      {String(indicator.technique_id || "")} {" "}
                      {String(indicator.technique_name || "")}
                    </td>
                    <td>
                      <SeverityBadge value={String(indicator.severity || "Low")} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState message="No triage indicators in this report." />
        )}
        <p className="notice">{report.summary.attack_mobile_triage.note}</p>
      </Card>

      <Card title={`Evidence (${report.evidence.length})`}>
        {report.evidence.length ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Source</th>
                  <th>Snippet</th>
                  <th>Redacted</th>
                </tr>
              </thead>
              <tbody>
                {report.evidence.map((item, index) => (
                  <tr key={index}>
                    <td>{String(item.evidence_type || "—")}</td>
                    <td>{String(item.source || "—")}</td>
                    <td className="mono">{String(item.snippet || "—")}</td>
                    <td>{item.redacted ? "Yes" : "No"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState message="No evidence in this report." />
        )}
      </Card>

      <div className="content-grid two-column">
        <Card title="Limitations">
          <ul className="limitations-list">
            {report.limitations.map((limitation) => (
              <li key={limitation}>{limitation}</li>
            ))}
          </ul>
        </Card>
        <Card title="Artifact summary">
          <p>
            <strong>{report.normalized_artifacts.count}</strong> normalized
            artifacts are represented by metadata only.
          </p>
          <dl className="details-list">
            {Object.entries(report.normalized_artifacts.by_type).map(
              ([type, count]) => (
                <div key={type}>
                  <dt>{type}</dt>
                  <dd>{count}</dd>
                </div>
              ),
            )}
          </dl>
        </Card>
      </div>

      <Card title="Raw JSON response">
        <details>
          <summary>Show formatted report JSON</summary>
          <pre className="json-output">{JSON.stringify(report, null, 2)}</pre>
        </details>
      </Card>
    </>
  );
}
