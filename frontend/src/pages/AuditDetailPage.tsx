import { type FormEvent, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  confirmApkUpload,
  getAnalysisStatus,
  getAudit,
  initiateApkUpload,
  listApkFiles,
  listComplianceScores,
  listEvidence,
  listFindings,
  listIndicators,
  listRiskScores,
  startAnalysis,
} from "../api/msap";
import type {
  AnalysisStatusResponse,
  ApkFile,
  Audit,
  ComplianceScore,
  Evidence,
  Finding,
  Indicator,
  RiskScore,
  UploadContract,
} from "../api/types";
import {
  Card,
  EmptyState,
  ErrorMessage,
  LoadingState,
  PageHeader,
  SeverityBadge,
  StatusBadge,
  errorMessage,
  formatBytes,
  formatDate,
} from "../components/Common";

const APK_CONTENT_TYPE = "application/vnd.android.package-archive";

export function AuditDetailPage() {
  const { auditId } = useParams();
  const id = Number(auditId);
  const [audit, setAudit] = useState<Audit | null>(null);
  const [apkFiles, setApkFiles] = useState<ApkFile[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [indicators, setIndicators] = useState<Indicator[]>([]);
  const [evidence, setEvidence] = useState<Evidence[]>([]);
  const [riskScores, setRiskScores] = useState<RiskScore[]>([]);
  const [complianceScores, setComplianceScores] = useState<ComplianceScore[]>([]);
  const [analysisStatus, setAnalysisStatus] =
    useState<AnalysisStatusResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [working, setWorking] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const [filename, setFilename] = useState("");
  const [contentType, setContentType] = useState(APK_CONTENT_TYPE);
  const [sizeBytes, setSizeBytes] = useState("");
  const [sha256, setSha256] = useState("");
  const [uploadContract, setUploadContract] = useState<UploadContract | null>(null);

  async function loadAuditData(showLoading = true) {
    if (showLoading) setLoading(true);
    setError("");
    try {
      const [
        auditData,
        allApkFiles,
        allFindings,
        allIndicators,
        allEvidence,
        allRiskScores,
        allComplianceScores,
        statusData,
      ] = await Promise.all([
        getAudit(id),
        listApkFiles(),
        listFindings(),
        listIndicators(),
        listEvidence(),
        listRiskScores(),
        listComplianceScores(),
        getAnalysisStatus(id),
      ]);
      setAudit(auditData);
      setApkFiles(allApkFiles.filter((item) => item.audit === id));
      setFindings(allFindings.filter((item) => item.audit === id));
      setIndicators(allIndicators.filter((item) => item.audit === id));
      setEvidence(allEvidence.filter((item) => item.audit === id));
      setRiskScores(allRiskScores.filter((item) => item.audit === id));
      setComplianceScores(
        allComplianceScores.filter((item) => item.audit === id),
      );
      setAnalysisStatus(statusData);
    } catch (requestError) {
      setError(errorMessage(requestError));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void loadAuditData();
  }, [id]);

  async function handleInitiateUpload(event: FormEvent) {
    event.preventDefault();
    setWorking(true);
    setError("");
    setNotice("");
    try {
      const contract = await initiateApkUpload(id, {
        filename,
        content_type: contentType,
        size_bytes: Number(sizeBytes),
        ...(sha256 ? { sha256 } : {}),
      });
      setUploadContract(contract);
      setNotice("Upload contract created. The browser PUT step is deferred.");
      await loadAuditData(false);
    } catch (requestError) {
      setError(errorMessage(requestError));
    } finally {
      setWorking(false);
    }
  }

  async function handleConfirmUpload() {
    if (!uploadContract) return;
    setWorking(true);
    setError("");
    setNotice("");
    try {
      await confirmApkUpload(uploadContract.apk_file_id, {
        size_bytes: Number(sizeBytes),
        ...(sha256 ? { sha256 } : {}),
      });
      setNotice(
        "Upload metadata confirmed. Ensure the APK object exists in MinIO before analysis.",
      );
      await loadAuditData(false);
    } catch (requestError) {
      setError(errorMessage(requestError));
    } finally {
      setWorking(false);
    }
  }

  async function handleStartAnalysis() {
    setWorking(true);
    setError("");
    setNotice("");
    try {
      const response = await startAnalysis(id);
      setNotice(`Analysis job #${response.analysis_job_id} was submitted.`);
      await loadAuditData(false);
    } catch (requestError) {
      setError(errorMessage(requestError));
    } finally {
      setWorking(false);
    }
  }

  if (loading) return <LoadingState label="Loading audit workspace…" />;
  if (!audit) return <ErrorMessage message={error || "Audit not found."} />;

  const riskScore = riskScores[0];
  const masvsScore = complianceScores.find((score) => score.standard === "MASVS");
  const analysisIsActive = ["QUEUED", "RUNNING"].includes(
    analysisStatus?.latest_job?.status || "",
  );

  return (
    <>
      <PageHeader
        eyebrow={`Audit #${audit.id}`}
        title={audit.name}
        description={`Created ${formatDate(audit.created_at)}`}
        actions={
          <>
            <button
              className="button button-secondary"
              onClick={() => void loadAuditData()}
              disabled={working}
            >
              Refresh
            </button>
            <Link className="button button-primary" to={`/audits/${id}/report`}>
              View JSON report
            </Link>
          </>
        }
      />
      {error ? <ErrorMessage message={error} /> : null}
      {notice ? <div className="alert alert-success">{notice}</div> : null}

      <div className="metric-grid audit-metrics">
        <Card className="metric-card">
          <span className="metric-label">Audit status</span>
          <StatusBadge value={analysisStatus?.audit_status || audit.status} />
          <span className="muted">
            Job: {analysisStatus?.latest_job?.status || "not started"}
          </span>
        </Card>
        <Card className="metric-card">
          <span className="metric-label">Risk score</span>
          <strong className="metric-value">{riskScore?.score ?? "—"}</strong>
          {riskScore ? <SeverityBadge value={riskScore.severity} /> : null}
        </Card>
        <Card className="metric-card">
          <span className="metric-label">MASVS compliance</span>
          <strong className="metric-value">
            {masvsScore ? `${masvsScore.score}%` : "—"}
          </strong>
          <span className="muted">Two implemented rules</span>
        </Card>
        <Card className="metric-card">
          <span className="metric-label">Triage signals</span>
          <strong className="metric-value">{indicators.length}</strong>
          <span className="muted">Not a malware verdict</span>
        </Card>
      </div>

      <Card title="APK upload contract">
        <div className="upload-layout">
          <form className="form-grid" onSubmit={handleInitiateUpload}>
            <label>
              Filename
              <input
                value={filename}
                onChange={(event) => setFilename(event.target.value)}
                placeholder="application.apk"
                required
              />
            </label>
            <label>
              Content type
              <input
                value={contentType}
                onChange={(event) => setContentType(event.target.value)}
                required
              />
            </label>
            <label>
              Size in bytes
              <input
                type="number"
                min="1"
                value={sizeBytes}
                onChange={(event) => setSizeBytes(event.target.value)}
                required
              />
            </label>
            <label>
              SHA-256 (optional)
              <input
                value={sha256}
                onChange={(event) => setSha256(event.target.value)}
                placeholder="64 hexadecimal characters"
                maxLength={64}
              />
            </label>
            <button className="button button-primary" disabled={working}>
              Initiate upload
            </button>
          </form>

          <div className="contract-panel">
            {uploadContract ? (
              <>
                <dl className="details-list">
                  <div>
                    <dt>Bucket</dt>
                    <dd>{uploadContract.bucket}</dd>
                  </div>
                  <div>
                    <dt>Object key</dt>
                    <dd className="break-text">{uploadContract.object_key}</dd>
                  </div>
                  <div>
                    <dt>Expires</dt>
                    <dd>{uploadContract.expires_in} seconds</dd>
                  </div>
                </dl>
                <a
                  className="break-text contract-url"
                  href={uploadContract.upload_url}
                  target="_blank"
                  rel="noreferrer"
                >
                  View presigned upload URL ↗
                </a>
                <button
                  type="button"
                  className="button button-secondary"
                  onClick={() => void handleConfirmUpload()}
                  disabled={working}
                >
                  Confirm upload metadata
                </button>
              </>
            ) : (
              <p className="empty-state">
                Initiate the contract to display its MinIO destination and URL.
              </p>
            )}
          </div>
        </div>
        <p className="notice">
          The dashboard does not PUT APK bytes to MinIO yet. Confirmation only
          updates backend metadata; use the presigned URL externally when needed.
        </p>
      </Card>

      <Card title="Analysis">
        <div className="inline-actions">
          <button
            className="button button-primary"
            onClick={() => void handleStartAnalysis()}
            disabled={working || analysisIsActive || apkFiles.length === 0}
          >
            {analysisIsActive ? "Analysis active" : "Start analysis"}
          </button>
          <button
            className="button button-secondary"
            onClick={() => void loadAuditData()}
            disabled={working}
          >
            Refresh status and results
          </button>
          {apkFiles.length === 0 ? (
            <span className="muted">Initiate an APK upload first.</span>
          ) : null}
        </div>
        {analysisStatus?.latest_job?.error_message ? (
          <ErrorMessage message={analysisStatus.latest_job.error_message} />
        ) : null}
      </Card>

      <Card title={`APK metadata (${apkFiles.length})`}>
        {apkFiles.length ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Package</th>
                  <th>Version</th>
                  <th>Size</th>
                  <th>SHA-256</th>
                </tr>
              </thead>
              <tbody>
                {apkFiles.map((apk) => (
                  <tr key={apk.id}>
                    <td>#{apk.id}</td>
                    <td>{apk.package_name || "Pending analysis"}</td>
                    <td>{apk.version_name || "—"}</td>
                    <td>{formatBytes(apk.size_bytes)}</td>
                    <td className="mono compact-hash">{apk.sha256 || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState message="No APK metadata exists for this audit." />
        )}
      </Card>

      <Card title={`Findings (${findings.length})`}>
        {findings.length ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Rule</th>
                  <th>Title</th>
                  <th>Category</th>
                  <th>Severity</th>
                  <th>Confidence</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((finding) => (
                  <tr key={finding.id}>
                    <td className="mono">{finding.rule_id}</td>
                    <td>{finding.title}</td>
                    <td>{finding.category || "—"}</td>
                    <td>
                      <SeverityBadge value={finding.severity} />
                    </td>
                    <td>{finding.confidence}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState message="No MASVS findings recorded." />
        )}
      </Card>

      <Card title={`ATT&CK indicators (${indicators.length})`}>
        {indicators.length ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Indicator</th>
                  <th>Title</th>
                  <th>Technique</th>
                  <th>Tactic</th>
                  <th>Severity</th>
                </tr>
              </thead>
              <tbody>
                {indicators.map((indicator) => (
                  <tr key={indicator.id}>
                    <td className="mono">{indicator.indicator_id}</td>
                    <td>{indicator.title}</td>
                    <td>
                      {indicator.technique_id} {indicator.technique_name}
                    </td>
                    <td>{indicator.tactic || "—"}</td>
                    <td>
                      <SeverityBadge value={indicator.severity} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState message="No ATT&CK Mobile triage indicators recorded." />
        )}
        <p className="notice">
          ATT&amp;CK Mobile indicators are triage signals, not malware verdicts.
        </p>
      </Card>

      <Card title={`Evidence (${evidence.length})`}>
        {evidence.length ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Linked result</th>
                  <th>Type</th>
                  <th>Source</th>
                  <th>Snippet</th>
                </tr>
              </thead>
              <tbody>
                {evidence.map((item) => (
                  <tr key={item.id}>
                    <td>
                      {item.finding
                        ? `Finding #${item.finding}`
                        : `Indicator #${item.indicator}`}
                    </td>
                    <td>{item.evidence_type}</td>
                    <td>{item.source}</td>
                    <td className="mono">{item.snippet || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState message="No evidence recorded." />
        )}
      </Card>
    </>
  );
}
