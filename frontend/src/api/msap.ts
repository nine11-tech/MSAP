import { apiDownload, apiGet, apiPost, apiPostBlob } from "./client";
import type {
  AnalysisStartResponse,
  AnalysisStatusResponse,
  ApkFile,
  Audit,
  ComplianceScore,
  DynamicAnalysisJob,
  DynamicDevice,
  DynamicDeviceCapability,
  DynamicDevicePool,
  DynamicEmulatorSnapshot,
  DynamicJobCreateRequest,
  DynamicRunMvpResponse,
  DynamicRunnerReadiness,
  DynamicHostAgentActionResult,
  DynamicHostAgentInstallResult,
  DynamicHostAgentPackages,
  DynamicHostAgentStatus,
  DynamicSession,
  DynamicSessionArtifact,
  DynamicSessionEvent,
  DynamicSessionStage,
  Evidence,
  Finding,
  Indicator,
  JsonReport,
  Project,
  RiskScore,
  RuleCoverage,
  SystemStatus,
  UploadContract,
  UploadInitiateRequest,
} from "./types";

export const listProjects = () => apiGet<Project[]>("projects/");
export const getProject = (projectId: number) =>
  apiGet<Project>(`projects/${projectId}/`);
export const createProject = (data: Pick<Project, "name" | "description">) =>
  apiPost<Project, Pick<Project, "name" | "description">>("projects/", data);

export const listAudits = () => apiGet<Audit[]>("audits/");
export const getAudit = (auditId: number) =>
  apiGet<Audit>(`audits/${auditId}/`);
export const createAudit = (data: { project: number; name: string }) =>
  apiPost<Audit, { project: number; name: string }>("audits/", data);

export const listApkFiles = () => apiGet<ApkFile[]>("apk-files/");
export const initiateApkUpload = (
  auditId: number,
  data: UploadInitiateRequest,
) =>
  apiPost<UploadContract, UploadInitiateRequest>(
    `audits/${auditId}/apk-upload/initiate/`,
    data,
  );
export async function uploadApkFile(
  contract: UploadContract,
  file: File,
): Promise<void> {
  const response = await fetch(contract.upload_url, {
    method: "PUT",
    headers: contract.required_headers,
    body: file,
  });
  if (!response.ok) {
    throw new Error(
      `MinIO upload failed with HTTP ${response.status}. ` +
        "Check the presigned URL and MinIO CORS policy.",
    );
  }
}

export async function sha256File(file: File): Promise<string> {
  if (!globalThis.crypto?.subtle) {
    throw new Error("This browser cannot calculate the required APK SHA-256.");
  }
  const digest = await globalThis.crypto.subtle.digest(
    "SHA-256",
    await file.arrayBuffer(),
  );
  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}
export const confirmApkUpload = (
  apkFileId: number,
  data: { size_bytes?: number; sha256?: string },
) =>
  apiPost<ApkFile, { size_bytes?: number; sha256?: string }>(
    `apk-files/${apkFileId}/confirm-upload/`,
    data,
  );

export const startAnalysis = (auditId: number) =>
  apiPost<AnalysisStartResponse>(`audits/${auditId}/analysis/start/`);
export const getAnalysisStatus = (auditId: number) =>
  apiGet<AnalysisStatusResponse>(`audits/${auditId}/analysis/status/`);
export const getAuditCoverage = (auditId: number) =>
  apiGet<RuleCoverage>(`audits/${auditId}/coverage/`);

const auditQuery = (auditId?: number) =>
  auditId === undefined ? "" : `?audit=${encodeURIComponent(auditId)}`;

export const listFindings = (auditId?: number) =>
  apiGet<Finding[]>(`findings/${auditQuery(auditId)}`);
export const listIndicators = (auditId?: number) =>
  apiGet<Indicator[]>(`indicators/${auditQuery(auditId)}`);
export const listEvidence = (auditId?: number) =>
  apiGet<Evidence[]>(`evidence/${auditQuery(auditId)}`);
export const listRiskScores = (auditId?: number) =>
  apiGet<RiskScore[]>(`risk-scores/${auditQuery(auditId)}`);
export const listComplianceScores = (auditId?: number) =>
  apiGet<ComplianceScore[]>(`compliance-scores/${auditQuery(auditId)}`);

export const getJsonReport = (auditId: number) =>
  apiGet<JsonReport>(`audits/${auditId}/report/json/`);
export const downloadPdfReport = (auditId: number) =>
  apiDownload(`audits/${auditId}/report/pdf/`);

export const getSystemStatus = (force = false) =>
  apiGet<SystemStatus>(`system/status/${force ? "?refresh=true" : ""}`);

export const listDynamicDevicePools = () =>
  apiGet<DynamicDevicePool[]>("dynamic/device-pools/");
export const listDynamicDevices = () =>
  apiGet<DynamicDevice[]>("dynamic/devices/");
export const listDynamicDeviceCapabilities = (deviceId?: number) =>
  apiGet<DynamicDeviceCapability[]>(
    `dynamic/device-capabilities/${deviceId === undefined ? "" : `?device=${encodeURIComponent(deviceId)}`}`,
  );
export const listDynamicEmulatorSnapshots = (deviceId?: number) =>
  apiGet<DynamicEmulatorSnapshot[]>(
    `dynamic/emulator-snapshots/${deviceId === undefined ? "" : `?device=${encodeURIComponent(deviceId)}`}`,
  );
export const listDynamicJobs = (auditId?: number) =>
  apiGet<DynamicAnalysisJob[]>(
    `dynamic/jobs/${auditId === undefined ? "" : `?audit=${encodeURIComponent(auditId)}`}`,
  );
export const createDynamicJob = (data: DynamicJobCreateRequest) =>
  apiPost<DynamicAnalysisJob, DynamicJobCreateRequest>("dynamic/jobs/", data);
export const getDynamicRunnerReadiness = () =>
  apiGet<DynamicRunnerReadiness>("dynamic/jobs/readiness/");
export const cancelDynamicJob = (jobId: number) =>
  apiPost<DynamicAnalysisJob>(`dynamic/jobs/${jobId}/cancel/`);
export const recoverStaleDynamicJobs = (olderThanMinutes = 5) =>
  apiPost<{
    recovered_count: number;
    recovered_job_ids: number[];
  }, { older_than_minutes: number }>("dynamic/jobs/recover-stale/", {
    older_than_minutes: olderThanMinutes,
  });
export const runDynamicMvpJob = (
  jobId: number,
  data: { include_platform_tls_probe?: boolean } = {},
) =>
  apiPost<DynamicRunMvpResponse, { include_platform_tls_probe?: boolean }>(
    `dynamic/jobs/${jobId}/run-mvp/`,
    data,
  );
export const listDynamicSessions = (jobId?: number) =>
  apiGet<DynamicSession[]>(
    `dynamic/sessions/${jobId === undefined ? "" : `?job=${encodeURIComponent(jobId)}`}`,
  );
export const getDynamicSession = (sessionId: number) =>
  apiGet<DynamicSession>(`dynamic/sessions/${sessionId}/`);
export const listDynamicSessionStages = (sessionId: number) =>
  apiGet<DynamicSessionStage[]>(
    `dynamic/session-stages/?session=${encodeURIComponent(sessionId)}`,
  );
export const listDynamicSessionEvents = (sessionId: number) =>
  apiGet<DynamicSessionEvent[]>(
    `dynamic/session-events/?session=${encodeURIComponent(sessionId)}`,
  );
export const listDynamicSessionArtifacts = (sessionId: number) =>
  apiGet<DynamicSessionArtifact[]>(
    `dynamic/session-artifacts/?session=${encodeURIComponent(sessionId)}`,
  );

export const getDynamicHostAgentStatus = () =>
  apiGet<DynamicHostAgentStatus>("dynamic/host-agent/status/");
export const syncDynamicHostAgent = () =>
  apiPost<DynamicHostAgentStatus>("dynamic/host-agent/sync/", {});
export const runDynamicHostAgentAction = (
  action:
    | "preflight"
    | "restore-instrumented-snapshot"
    | "frida-smoke"
    | "mitmproxy-smoke"
    | "platform-tls-probe"
    | "verify-trust-state"
    | "apply-lab-proxy"
    | "clear-lab-proxy"
    | "cleanup",
) =>
  apiPost<DynamicHostAgentActionResult>(
    `dynamic/host-agent/${action}/`,
    {},
  );
export const captureDynamicHostAgentScreenshot = () =>
  apiPostBlob("dynamic/host-agent/screenshot/");
export const listDynamicHostAgentPackages = () =>
  apiGet<DynamicHostAgentPackages>("dynamic/host-agent/packages/");
export const runDynamicHostAgentPackageAction = (
  action: "launch-package" | "force-stop" | "clear-data" | "uninstall",
  packageName: string,
) =>
  apiPost<
    DynamicHostAgentActionResult,
    { package_name: string }
  >(`dynamic/host-agent/${action}/`, { package_name: packageName });
export const installDynamicAuditApk = (
  audit: number,
  apkFile?: number,
) =>
  apiPost<
    DynamicHostAgentInstallResult,
    { audit: number; apk_file?: number }
  >("dynamic/host-agent/install-audit-apk/", {
    audit,
    ...(apkFile === undefined ? {} : { apk_file: apkFile }),
  });
