import { type FormEvent, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  confirmApkUpload,
  downloadPdfReport,
  getAnalysisStatus,
  getAuditCoverage,
  getAudit,
  initiateApkUpload,
  listApkFiles,
  listComplianceScores,
  listEvidence,
  listFindings,
  listIndicators,
  listRiskScores,
  listSourceDocuments,
  sha256File,
  startAnalysis,
  uploadApkFile,
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
  RuleCoverage,
  SourceDocument,
  UploadContract,
} from "../api/types";
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
  formatBytes,
  formatDate,
} from "../components/Common";
import { AuditSourceBrowser } from "../components/CodeEvidenceViewer";
import { useAuth } from "../auth/AuthContext";

const APK_CONTENT_TYPE = "application/vnd.android.package-archive";
type UploadState =
  | "idle"
  | "hashing"
  | "initiating"
  | "uploading"
  | "confirming"
  | "uploaded"
  | "failed";

const UPLOAD_STATE_LABELS: Record<UploadState, string> = {
  idle: "Select an APK to begin",
  hashing: "Calculating APK SHA-256…",
  initiating: "Requesting upload contract…",
  uploading: "Uploading APK to MinIO…",
  confirming: "Confirming upload metadata…",
  uploaded: "APK uploaded and confirmed",
  failed: "Upload failed",
};

const ACTIVE_JOB_STATUSES = ["QUEUED", "RUNNING"];
const TERMINAL_JOB_STATUSES = ["COMPLETED", "FAILED"];

export function AuditDetailPage() {
  const { auditId } = useParams();
  const id = Number(auditId);
  const [audit, setAudit] = useState<Audit | null>(null);
  const [apkFiles, setApkFiles] = useState<ApkFile[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [indicators, setIndicators] = useState<Indicator[]>([]);
  const [evidence, setEvidence] = useState<Evidence[]>([]);
  const [sourceDocuments, setSourceDocuments] = useState<SourceDocument[]>([]);
  const [riskScores, setRiskScores] = useState<RiskScore[]>([]);
  const [complianceScores, setComplianceScores] = useState<ComplianceScore[]>([]);
  const [analysisStatus, setAnalysisStatus] =
    useState<AnalysisStatusResponse | null>(null);
  const [coverage, setCoverage] = useState<RuleCoverage | null>(null);
  const [loading, setLoading] = useState(true);
  const [working, setWorking] = useState(false);
  const [downloadingPdf, setDownloadingPdf] = useState(false);
  const [isPolling, setIsPolling] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [activeTab, setActiveTab] = useState<
    "overview" | "findings" | "source" | "attack" | "evidence" | "coverage"
  >("overview");
  const { hasRole } = useAuth();
  const canOperate = hasRole("ADMIN", "ANALYST");

  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploadState, setUploadState] = useState<UploadState>("idle");
  const [uploadContract, setUploadContract] = useState<UploadContract | null>(null);

  async function loadAuditData(showLoading = true) {
    if (showLoading) setLoading(true);
    setError("");
    try {
      const [
        auditData,
        allApkFiles,
        auditFindings,
        auditIndicators,
        auditEvidence,
        auditSourceDocuments,
        auditRiskScores,
        auditComplianceScores,
        statusData,
        coverageData,
      ] = await Promise.all([
        getAudit(id),
        listApkFiles(),
        listFindings(id),
        listIndicators(id),
        listEvidence(id),
        listSourceDocuments(id),
        listRiskScores(id),
        listComplianceScores(id),
        getAnalysisStatus(id),
        getAuditCoverage(id),
      ]);
      setAudit(auditData);
      setApkFiles(allApkFiles.filter((item) => item.audit === id));
      setFindings(auditFindings);
      setIndicators(auditIndicators);
      setEvidence(auditEvidence);
      setSourceDocuments(auditSourceDocuments);
      setRiskScores(auditRiskScores);
      setComplianceScores(auditComplianceScores);
      setAnalysisStatus(statusData);
      setCoverage(coverageData);
      if (ACTIVE_JOB_STATUSES.includes(statusData.latest_job?.status || "")) {
        setIsPolling(true);
      }
    } catch (requestError) {
      setError(errorMessage(requestError));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void loadAuditData();
  }, [id]);

  useEffect(() => {
    if (!isPolling) return;

    let cancelled = false;
    const timer = window.setInterval(() => {
      void getAnalysisStatus(id)
        .then(async (statusData) => {
          if (cancelled) return;
          setAnalysisStatus(statusData);
          setAudit((current) =>
            current ? { ...current, status: statusData.audit_status } : current,
          );

          const jobStatus = statusData.latest_job?.status || "";
          if (TERMINAL_JOB_STATUSES.includes(jobStatus)) {
            setIsPolling(false);
            await loadAuditData(false);
            if (!cancelled) {
              setNotice(
                jobStatus === "COMPLETED"
                  ? "Analysis completed. Results and scores were refreshed."
                  : "Analysis failed. Review the latest job error below.",
              );
            }
          }
        })
        .catch((requestError: unknown) => {
          if (!cancelled) {
            setIsPolling(false);
            setError(errorMessage(requestError));
          }
        });
    }, 2000);

    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [id, isPolling]);

  function handleFileSelection(file: File | null) {
    setSelectedFile(file);
    setUploadContract(null);
    setUploadState("idle");
    setError("");
    setNotice("");
  }

  async function handleUpload(event: FormEvent) {
    event.preventDefault();
    if (!selectedFile) return;

    setWorking(true);
    setUploadState("initiating");
    setError("");
    setNotice("");
    try {
      const contentType = selectedFile.type || APK_CONTENT_TYPE;
      setUploadState("hashing");
      const sha256 = await sha256File(selectedFile);
      setUploadState("initiating");
      const contract = await initiateApkUpload(id, {
        filename: selectedFile.name,
        content_type: contentType,
        size_bytes: selectedFile.size,
        sha256,
      });
      setUploadContract(contract);
      setUploadState("uploading");
      await uploadApkFile(contract, selectedFile);
      setUploadState("confirming");
      const confirmedApk = await confirmApkUpload(contract.apk_file_id, {
        size_bytes: selectedFile.size,
        sha256,
      });
      setUploadState("uploaded");
      setNotice(
        `APK #${confirmedApk.id} uploaded and confirmed. Analysis can now start.`,
      );
      await loadAuditData(false);
    } catch (requestError) {
      setUploadState("failed");
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
      const statusData = await getAnalysisStatus(id);
      setAnalysisStatus(statusData);
      const jobStatus = statusData.latest_job?.status || "";
      if (TERMINAL_JOB_STATUSES.includes(jobStatus)) {
        await loadAuditData(false);
        setNotice(
          jobStatus === "COMPLETED"
            ? `Analysis job #${response.analysis_job_id} completed. Results were refreshed.`
            : `Analysis job #${response.analysis_job_id} failed.`,
        );
      } else {
        setIsPolling(true);
        setNotice(
          `Analysis job #${response.analysis_job_id} was submitted. Polling every 2 seconds.`,
        );
      }
    } catch (requestError) {
      setError(errorMessage(requestError));
    } finally {
      setWorking(false);
    }
  }

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

  if (loading) return <LoadingState label="Loading audit workspace…" />;
  if (!audit) return <ErrorMessage message={error || "Audit not found."} />;

  const riskScore = riskScores[0];
  const masvsScore = complianceScores.find((score) => score.standard === "MASVS");
  const analysisIsActive = ACTIVE_JOB_STATUSES.includes(
    analysisStatus?.latest_job?.status || "",
  );
  const hasConfirmedApk = apkFiles.some((apk) =>
    ["UPLOADED", "VERIFIED"].includes(apk.storage_status || ""),
  );
  const lifecycleStep = analysisStatus?.latest_job?.status === "COMPLETED"
    ? 4
    : analysisIsActive
      ? 3
      : hasConfirmedApk
        ? 2
        : apkFiles.length
          ? 1
          : 0;

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
      {notice ? <div className="alert alert-success">{notice}</div> : null}

      <ol className="lifecycle-stepper" aria-label="Audit lifecycle">
        {["Audit created", "Upload initiated", "APK confirmed", "Analysis running", "Results ready"].map((label, index) => (
          <li className={index < lifecycleStep ? "complete" : index === lifecycleStep ? "current" : ""} key={label}>
            <span>{index < lifecycleStep ? "✓" : index + 1}</span>
            {label}
          </li>
        ))}
      </ol>

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

      <nav className="workspace-tabs" aria-label="Audit result views">
        {[
          ["overview", "Overview"],
          ["findings", `Findings (${findings.length})`],
          ["source", `Source (${sourceDocuments.length})`],
          ["attack", `ATT&CK (${indicators.length})`],
          ["evidence", `Evidence (${evidence.length})`],
          ["coverage", "Analyzer coverage"],
        ].map(([value, label]) => (
          <button
            key={value}
            className={activeTab === value ? "active" : ""}
            onClick={() => setActiveTab(value as typeof activeTab)}
          >
            {label}
          </button>
        ))}
      </nav>

      {activeTab === "overview" ? <>
      <Card title="APK upload">
        <div className="upload-layout">
          <form className="form-stack" onSubmit={handleUpload}>
            <label>
              APK file
              <input
                type="file"
                accept=".apk,application/vnd.android.package-archive,application/octet-stream"
                onChange={(event) =>
                  handleFileSelection(event.target.files?.[0] || null)
                }
                disabled={working || !canOperate}
                required
              />
            </label>
            {selectedFile ? (
              <dl className="details-list file-details">
                <div>
                  <dt>Name</dt>
                  <dd>{selectedFile.name}</dd>
                </div>
                <div>
                  <dt>Size</dt>
                  <dd>{formatBytes(selectedFile.size)}</dd>
                </div>
                <div>
                  <dt>Content type</dt>
                  <dd>{selectedFile.type || APK_CONTENT_TYPE}</dd>
                </div>
              </dl>
            ) : null}
            <button
              className="button button-primary"
              disabled={working || !selectedFile || !canOperate}
            >
              Upload and confirm APK
            </button>
          </form>

          <div className="contract-panel">
            <span className={`upload-state upload-${uploadState}`}>
              {UPLOAD_STATE_LABELS[uploadState]}
            </span>
            {uploadContract ? (
              <dl className="details-list upload-contract-details">
                <div>
                  <dt>APK record</dt>
                  <dd>#{uploadContract.apk_file_id}</dd>
                </div>
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
                {Object.entries(uploadContract.required_headers).map(
                  ([header, value]) => (
                    <div key={header}>
                      <dt>{header}</dt>
                      <dd>{value}</dd>
                    </div>
                  ),
                )}
              </dl>
            ) : (
              <p className="empty-state">
                The MinIO destination will appear after upload initiation.
              </p>
            )}
          </div>
        </div>
        <p className="notice">
          {canOperate
            ? "Upload uses a short-lived backend-signed contract and confirms metadata after the MinIO transfer."
            : "Viewer access is read-only. An analyst or administrator can upload an APK."}
        </p>
      </Card>

      <Card title="Analysis">
        <div className="inline-actions">
          <button
            className="button button-primary"
            onClick={() => void handleStartAnalysis()}
            disabled={working || analysisIsActive || !hasConfirmedApk || !canOperate}
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
          {isPolling ? (
            <span className="polling-indicator">Polling every 2 seconds…</span>
          ) : null}
          {!hasConfirmedApk ? (
            <span className="muted">Upload and confirm an APK first.</span>
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
                  <th>Storage</th>
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
                    <td>
                      <StatusBadge value={apk.storage_status || "unknown"} />
                    </td>
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
      </> : null}

      {activeTab === "findings" ? (
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
                  <th>Source evidence</th>
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
                    <td>{finding.source_reference_count || 0} reference(s)</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState message="No MASVS findings recorded." />
        )}
      </Card>
      ) : null}

      {activeTab === "source" ? (
        <Card title={`Indexed source documents (${sourceDocuments.length})`}>
          <p className="notice">
            Line numbers identify MSAP-decoded or JADX-decompiled representations,
            not the developer&apos;s original source tree.
          </p>
          <AuditSourceBrowser documents={sourceDocuments} />
        </Card>
      ) : null}

      {activeTab === "attack" ? (
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
                  <th>Auditor guidance</th>
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
          <EmptyState message="No ATT&CK Mobile triage indicators recorded." />
        )}
        <p className="notice">
          ATT&amp;CK Mobile indicators are triage signals, not malware verdicts.
        </p>
      </Card>
      ) : null}

      {activeTab === "evidence" ? (
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
      ) : null}

      {activeTab === "coverage" ? (
        <Card title="Analyzer coverage">
          {coverage?.total_catalog_rules ? (
            <>
              <div className="metric-grid compact-metrics">
                {[
                  ["Catalog", coverage.total_catalog_rules],
                  ["Evaluated", coverage.evaluated],
                  ["Passed", coverage.passed],
                  ["Failed", coverage.failed],
                  ["Review", coverage.review_required],
                  ["Not evaluated", coverage.not_evaluated],
                ].map(([label, value]) => (
                  <div className="metric-card" key={String(label)}>
                    <span>{label}</span><strong>{value}</strong>
                  </div>
                ))}
              </div>
              {coverage.partial_coverage ? (
                <p className="inline-notice warning">
                  Partial coverage: unevaluated rules are not counted as passing.
                </p>
              ) : null}
              <dl className="details-list compact-details">
                <div><dt>Completed analyzers</dt><dd>{coverage.analyzers.completed.join(", ") || "None"}</dd></div>
                <div><dt>Skipped analyzers</dt><dd>{coverage.analyzers.skipped.map((item) => item.name).join(", ") || "None"}</dd></div>
                <div><dt>Failed analyzers</dt><dd>{coverage.analyzers.failed.map((item) => item.name).join(", ") || "None"}</dd></div>
                <div><dt>ATT&CK techniques matched</dt><dd>{coverage.attack_mobile.matched_techniques.join(", ") || "None"}</dd></div>
              </dl>
              <p className="muted">{coverage.attack_mobile.note}</p>
            </>
          ) : (
            <EmptyState message="Start analysis to populate analyzer coverage." />
          )}
        </Card>
      ) : null}
    </>
  );
}
