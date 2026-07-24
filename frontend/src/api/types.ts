export interface Project {
  id: number;
  name: string;
  description: string;
  created_at: string;
  updated_at: string;
}

export interface Audit {
  id: number;
  project: number;
  name: string;
  status: string;
  created_at: string;
  updated_at: string;
}

export interface ApkFile {
  id: number;
  audit: number;
  package_name: string;
  version_name: string;
  sha256: string;
  size_bytes: number | null;
  storage_reference: number | null;
  storage_status: string | null;
  created_at: string;
}

export interface Finding {
  id: number;
  audit: number;
  rule_id: string;
  title: string;
  severity: string;
  confidence: string;
  standard: string;
  category: string;
  recommendation: string;
  created_at: string;
}

export interface Indicator {
  id: number;
  audit: number;
  indicator_id: string;
  title: string;
  tactic: string;
  technique_id: string;
  technique_name: string;
  severity: string;
  confidence: string;
  triage_interpretation: string;
  created_at: string;
}

export interface Evidence {
  id: number;
  audit: number;
  finding: number | null;
  indicator: number | null;
  storage_reference: number | null;
  evidence_type: string;
  source: string;
  snippet: string;
  redacted: boolean;
  created_at: string;
}

export interface RiskScore {
  id: number;
  audit: number;
  score: string;
  severity: string;
  created_at: string;
}

export interface ComplianceScore {
  id: number;
  audit: number;
  standard: string;
  score: string;
  created_at: string;
}

export interface UploadInitiateRequest {
  filename: string;
  content_type: string;
  size_bytes: number;
  sha256?: string;
}

export interface UploadContract {
  apk_file_id: number;
  storage_reference_id: number;
  bucket: string;
  object_key: string;
  upload_url: string;
  expires_in: number;
  required_headers: Record<string, string>;
}

export interface AnalysisStartResponse {
  audit_id: number;
  analysis_job_id: number;
  task_id: string;
  status: string;
}

export interface AnalysisJob {
  id: number;
  task_id: string;
  status: string;
  started_at: string | null;
  finished_at: string | null;
  error_message: string;
  result_summary: Record<string, unknown>;
}

export interface AnalysisStatusResponse {
  audit_id: number;
  audit_status: string;
  latest_job: AnalysisJob | null;
}

export interface ReportRiskSummary {
  score: number;
  severity: string;
  finding_count: number;
  indicator_count: number;
  raw_weight: number;
}

export interface ReportComplianceSummary {
  standard: string;
  score: number;
  evaluated_rules: number;
  failed_rules: number;
  passed_rules: number;
}

export interface ReportTriageSummary {
  triage_indicators: number;
  triage_level: string;
  note: string;
}

export interface JsonReport {
  report: {
    id: number;
    report_type: string;
    recorded_at: string;
  };
  audit: {
    id: number;
    name: string;
    status: string;
    created_at: string;
    updated_at: string;
  };
  project: {
    id: number;
    name: string;
    description: string;
  };
  apk: {
    id: number;
    package_name: string;
    version_name: string;
    sha256: string;
    size_bytes: number | null;
    created_at: string;
  } | null;
  summary: {
    risk: ReportRiskSummary;
    masvs_compliance: ReportComplianceSummary;
    attack_mobile_triage: ReportTriageSummary;
  };
  findings: Array<Record<string, unknown>>;
  indicators: Array<Record<string, unknown>>;
  evidence: Array<Record<string, unknown>>;
  normalized_artifacts: {
    count: number;
    by_type: Record<string, number>;
    items: Array<Record<string, unknown>>;
  };
  analysis_job: Record<string, unknown> | null;
  limitations: string[];
}
