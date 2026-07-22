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

export const listFindings = () => apiGet<Finding[]>("findings/");
export const listIndicators = () => apiGet<Indicator[]>("indicators/");
export const listEvidence = () => apiGet<Evidence[]>("evidence/");
export const listRiskScores = () => apiGet<RiskScore[]>("risk-scores/");
export const listComplianceScores = () =>
  apiGet<ComplianceScore[]>("compliance-scores/");

export const getJsonReport = (auditId: number) =>
  apiGet<JsonReport>(`audits/${auditId}/report/json/`);
