import { apiGet, apiPost } from "./client";
import type {
  AnalysisStartResponse,
  AnalysisStatusResponse,
  ApkFile,
  Audit,
  ComplianceScore,
  Evidence,
  Finding,
  Indicator,
  JsonReport,
  Project,
  RiskScore,
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
