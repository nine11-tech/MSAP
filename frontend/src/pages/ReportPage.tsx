import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { downloadPdfReport, getJsonReport } from "../api/msap";
import type { JsonReport } from "../api/types";
import { AttackIndicatorGuidance } from "../components/AttackIndicatorGuidance";
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
  const [downloadingPdf, setDownloadingPdf] = useState(false);
  const [error, setError] = useState("");

  async function handlePdfDownload() {
    setDownloadingPdf(true);
    setError("");
    try {
      const { blob, filename } = await downloadPdfReport(id);
      const objectUrl = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = objectUrl;
      link.download = filename || `MSAP_Audit_${id}_Security_Report.pdf`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.setTimeout(() => window.URL.revokeObjectURL(objectUrl), 0);
    } catch (requestError) {
      setError(errorMessage(requestError));
    } finally {
      setDownloadingPdf(false);
    }
  }

  useEffect(() => {
    getJsonReport(id)
      .then(setReport)
      .catch((requestError: unknown) => setError(errorMessage(requestError)))
      .finally(() => setLoading(false));
  }, [id]);

  if (loading) return <LoadingState label="Generating JSON report…" />;
  if (!report) return <ErrorMessage message={error || "Report unavailable."} />;
  const dynamicRuns = report.dynamic_assessments?.items || [];

  return (
    <>
      <PageHeader
        eyebrow={`JSON report #${report.report.id}`}
        title={report.audit.name}
        description={`${report.project.name} • Auditable static and approved dynamic assessment report`}
        actions={
          <>
            <Link className="button button-secondary" to={`/audits/${id}`}>
              Back to audit
            </Link>
            <button
              className="button button-primary"
              onClick={() => void handlePdfDownload()}
              disabled={downloadingPdf}
            >
              {downloadingPdf ? "Generating PDF…" : "Download PDF Report"}
            </button>
          </>
        }
      />
      {error ? <ErrorMessage message={error} /> : null}

      <div className="metric-grid">
        <Card className="metric-card">
          <span className="metric-label">Audit status</span>
          <StatusBadge value={report.audit.status} />
          <span className="muted">Static + approved runtime evidence</span>
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

      <Card title={`Approved dynamic assessments (${dynamicRuns.length})`}>
        {dynamicRuns.length ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Run</th>
                  <th>Target</th>
                  <th>Status</th>
                  <th>Plan / hash</th>
                  <th>Capabilities</th>
                  <th>Evidence</th>
                  <th>Findings</th>
                </tr>
              </thead>
              <tbody>
                {dynamicRuns.map((item, index) => {
                  const plan = asRecord(item.plan);
                  const capabilities = Array.isArray(item.capabilities_used)
                    ? item.capabilities_used
                    : [];
                  const evidence = Array.isArray(item.evidence) ? item.evidence : [];
                  const findingIds = Array.isArray(item.finding_ids) ? item.finding_ids : [];
                  return (
                    <tr key={String(item.run_id ?? index)}>
                      <td className="mono">#{String(item.run_id ?? "—")}</td>
                      <td className="mono">{String(item.target_package ?? "—")}</td>
                      <td><StatusBadge value={String(item.status ?? "Unknown")} /></td>
                      <td className="mono">
                        #{String(plan.id ?? "—")} · {String(plan.hash ?? "Unavailable").slice(0, 16)}…
                      </td>
                      <td>{capabilities.map(String).join(", ") || "None"}</td>
                      <td>{evidence.length}</td>
                      <td>{findingIds.length}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState message="No approved AgentRun evidence is recorded for this audit." />
        )}
        <p className="notice">
          AI planning, auditor approval, gateway execution, untrusted observations,
          and deterministic findings are separate provenance layers.
        </p>
      </Card>

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
                  <th>Auditor guidance</th>
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
                    <td>
                      <details>
                        <summary>Explain and verify</summary>
                        <div className="indicator-detail">
                          <AttackIndicatorGuidance indicator={indicator} />
                        </div>
                      </details>
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

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}
