export interface Project {
  id: number;
  name: string;
  description: string;
  created_at: string;
  updated_at: string;
}

export type UserRole = "ADMIN" | "ANALYST" | "VIEWER";

export interface AuthUser {
  id: number;
  username: string;
  email: string;
  first_name: string;
  last_name: string;
  role: UserRole;
  is_staff: boolean;
  permissions: string[];
}

export type ComponentStatus =
  | "OPERATIONAL"
  | "DEGRADED"
  | "UNAVAILABLE"
  | "DISABLED";

export interface SystemComponent {
  id: string;
  label: string;
  status: ComponentStatus;
  latency_ms: number | null;
  message: string;
  last_successful_check: string | null;
  details?: Record<string, unknown>;
}

export interface SystemStatus {
  overall_status: "OPERATIONAL" | "DEGRADED" | "OUTAGE";
  checked_at: string;
  components: SystemComponent[];
  deployment_mode?: string;
  application_version?: string;
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
  description?: string;
  masvs_controls?: string[];
  maswe_ids?: string[];
  mastg_references?: string[];
  false_positive_guidance?: string;
  requires_manual_validation?: boolean;
  status?: string;
  created_at: string;
  source_reference_count?: number;
}

export type SourceRepresentation =
  | "JADX_SOURCE"
  | "JADX_JAVA"
  | "JADX_KOTLIN"
  | "SMALI"
  | "DEX_DISASSEMBLY"
  | "DEX_METADATA"
  | "MANIFEST_XML"
  | "RESOURCE_XML"
  | "NETWORK_SECURITY_XML"
  | "NATIVE_SYMBOL"
  | "APK_SIGNING_METADATA"
  | "CERTIFICATE_METADATA"
  | "OTHER_TEXT";

export interface SourceDocument {
  id: number;
  audit: number;
  apk_file: number;
  representation_type: SourceRepresentation;
  representation_label: string;
  logical_path: string;
  display_path: string;
  language: string;
  class_name: string;
  package_name: string;
  sha256: string;
  line_count: number;
  generated_by: string;
  tool_version: string;
  storage_available: boolean;
  metadata: Record<string, unknown>;
  created_at: string;
}

export interface FindingSourceReference {
  id: number;
  finding: number;
  source_document: number | null;
  representation_type: SourceRepresentation;
  representation_label: string;
  logical_path: string;
  source_document_display_path: string | null;
  source_document_sha256: string | null;
  source_document_line_count: number | null;
  class_name: string;
  method_name: string;
  method_descriptor: string;
  symbol_name: string;
  start_line: number | null;
  end_line: number | null;
  start_offset: number | null;
  end_offset: number | null;
  excerpt: string;
  excerpt_sha256: string;
  locator: Record<string, unknown>;
  confidence: string;
  is_primary: boolean;
  provenance: string;
  source_lines_available: boolean;
  unavailable_reason: string;
  created_at: string;
}

export interface SourceLineRange {
  document: SourceDocument;
  start_line: number;
  end_line: number;
  lines: Array<{ number: number; text: string }>;
  redaction_applied: boolean;
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
  auditor_explanation?: string;
  dynamic_verification_scenario?: string;
  source_evidence?: IndicatorSourceEvidence[];
  mapping_rationale?: string;
  false_positive_considerations?: string;
  requires_manual_validation?: boolean;
  non_malware_verdict_note?: string;
  created_at: string;
}

export interface IndicatorSourceEvidence {
  source_document: number | null;
  representation: string;
  representation_label: string;
  path: string;
  class_name: string;
  method_name: string;
  start_line: number | null;
  end_line: number | null;
  excerpt: string;
  confidence: string;
  is_primary: boolean;
  source_lines_available: boolean;
  provenance: string;
  reason?: string;
  candidate_count?: number;
  manual_validation_required?: boolean;
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

export interface RuleCoverage {
  total_catalog_rules: number;
  applicable: number;
  evaluated: number;
  passed: number;
  failed: number;
  review_required: number;
  not_applicable: number;
  not_evaluated: number;
  partial_coverage: boolean;
  analyzers: {
    completed: string[];
    skipped: Array<{ name: string; reason: string }>;
    failed: Array<{ name: string; reason: string }>;
  };
  masvs: {
    total: number;
    by_category: Record<string, Record<string, number>>;
  };
  attack_mobile: {
    total: number;
    by_tactic: Record<string, Record<string, number>>;
    matched_techniques: string[];
    note: string;
  };
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
  applicable_rules: number;
  review_required: number;
  not_evaluated: number;
  partial_coverage: boolean;
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
    filename: string;
    package_name: string;
    version_name: string;
    sha256: string;
    size_bytes: number | null;
    storage_status: string;
    created_at: string;
  } | null;
  summary: {
    risk: ReportRiskSummary;
    masvs_compliance: ReportComplianceSummary;
    attack_mobile_triage: ReportTriageSummary;
    coverage: RuleCoverage;
  };
  findings: Array<Record<string, unknown>>;
  indicators: Array<Omit<Indicator, "audit" | "created_at">>;
  evidence: Array<Record<string, unknown>>;
  rule_evaluations: Array<Record<string, unknown>>;
  analyzer_results: Array<Record<string, unknown>>;
  normalized_artifacts: {
    count: number;
    by_type: Record<string, number>;
    items: Array<Record<string, unknown>>;
  };
  source_documents: {
    count: number;
    items: Array<Record<string, unknown>>;
  };
  analysis_job: Record<string, unknown> | null;
  limitations: string[];
}

export interface DynamicDevicePool {
  id: number;
  name: string;
  slug: string;
  description: string;
  is_active: boolean;
  max_concurrent_leases: number;
  created_at: string;
  updated_at: string;
}

export interface DynamicDevice {
  id: number;
  pool: number | null;
  pool_name: string | null;
  name: string;
  serial: string;
  kind: string;
  host_type: string;
  host_identifier: string;
  status: string;
  api_level: number;
  android_version: string;
  abi: string;
  avd_name: string;
  is_rooted: boolean;
  selinux_mode: string;
  has_frida: boolean;
  has_mitm_ready: boolean;
  current_snapshot: string;
  last_seen_at: string | null;
  last_health_check_at: string | null;
  quarantine_reason: string;
  notes: string;
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface DynamicDeviceCapability {
  id: number;
  device: number;
  device_serial: string;
  capability_type: string;
  name: string;
  version: string;
  is_available: boolean;
  details: Record<string, unknown>;
  checked_at: string;
  created_at: string;
  updated_at: string;
}

export interface DynamicEmulatorSnapshot {
  id: number;
  device: number;
  device_serial: string;
  name: string;
  snapshot_type: string;
  description: string;
  api_level: number;
  abi: string;
  contains_frida_binary: boolean;
  contains_public_ca: boolean;
  contains_target_apk: boolean;
  validation_status: string;
  validated_at: string | null;
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface DynamicAnalysisJob {
  id: number;
  audit: number;
  apk: number | null;
  requested_by: number | null;
  requested_by_username: string | null;
  mode: string;
  status: string;
  priority: number;
  requested_tool_profile: string;
  requested_interaction_mode: string;
  requested_device_pool: number | null;
  timeout_seconds: number;
  max_retries: number;
  retry_count: number;
  queued_at: string;
  started_at: string | null;
  finished_at: string | null;
  summary: Record<string, unknown>;
  failure_category: string;
  failure_message: string;
  created_at: string;
  updated_at: string;
}

export interface DynamicSession {
  id: number;
  job: number;
  audit: number;
  apk: number | null;
  device: number;
  device_serial: string;
  lease: number;
  snapshot: number | null;
  state: string;
  state_reason: string;
  started_at: string | null;
  finished_at: string | null;
  duration_seconds: number | null;
  tool_versions: Record<string, unknown>;
  network_capture_enabled: boolean;
  frida_enabled: boolean;
  runtime_ca_enabled: boolean;
  ui_automation_enabled: boolean;
  cleanup_status: string;
  quarantine_required: boolean;
  summary: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface DynamicSessionStage {
  id: number;
  session: number;
  name: string;
  state: string;
  status: string;
  started_at: string | null;
  finished_at: string | null;
  duration_seconds: number | null;
  attempt: number;
  message: string;
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface DynamicSessionEvent {
  id: number;
  session: number;
  event_type: string;
  severity: string;
  message: string;
  sequence_number: number;
  metadata: Record<string, unknown>;
  created_at: string;
}

export interface DynamicSessionArtifact {
  id: number;
  session: number;
  artifact_type: string;
  category: string;
  name: string;
  summary: string;
  raw_reference: number | null;
  normalized: Record<string, unknown>;
  redaction_state: string;
  confidence: string;
  manual_validation_required: boolean;
  correlation_keys: string[];
  sequence_number: number;
  created_at: string;
}

export interface DynamicJobCreateRequest {
  audit: number;
  mode: "COMBINED" | "DYNAMIC_ONLY";
  requested_tool_profile:
    | "ADB_ONLY"
    | "NETWORK_CAPTURE"
    | "FRIDA_BASIC"
    | "FRIDA_EXTENDED"
    | "FULL";
  requested_interaction_mode:
    | "PASSIVE"
    | "BASIC_AUTOMATION"
    | "SCRIPTED_SCENARIO"
    | "AUTHORIZED_LOGIN_SCENARIO";
  requested_device_pool?: number | null;
  timeout_seconds?: number;
}

export interface DynamicRunMvpResponse {
  job: DynamicAnalysisJob;
  task_id: string | null;
  execution_mode: "celery" | "synchronous";
  include_platform_tls_probe: boolean;
  result?: Record<string, unknown>;
}

export interface DynamicRunnerReadiness {
  runner_enabled: boolean;
  sync_demo_enabled: boolean;
  execution_mode: "celery" | "synchronous";
  worker_status: "ONLINE" | "OFFLINE" | "UNKNOWN";
  workers_responding: number;
  ready: boolean;
  code: string;
  detail: string;
}

export interface DynamicHostAgentDevice {
  serial: string;
  state: string;
  adb_path_present: boolean;
  root_uid: number | null;
  api_level: number | null;
  android_version: string;
  abi: string;
  selinux: string;
  proxy: string;
  focused_app: string;
  frida_server_running: boolean;
  frida_smoke: boolean | null;
  mitmproxy_smoke: boolean | null;
}

export interface DynamicHostAgentStatus {
  connected: boolean;
  enabled: boolean;
  code: string;
  detail: string;
  agent?: {
    status: string;
    version: string;
    dynamic_env_detected: boolean;
    adb_path_present: boolean;
    serial: string;
  };
  device?: DynamicHostAgentDevice | null;
  synced_device_id?: number;
  last_sync_at?: string | null;
}

export interface DynamicHostAgentActionResult {
  action: string;
  success: boolean;
  status: "PASS" | "FAIL" | string;
  duration_seconds?: number;
  return_code?: number;
  package_name?: string;
  focused_app?: string;
  focused_activity?: string;
  launchable_activity?: string;
  evidence?: Record<string, unknown>;
  detail?: string;
  results?: Array<{
    stage_name: string;
    script_name: string;
    return_code: number;
    stdout_preview: string;
    stderr_preview: string;
    duration_seconds: number;
    pass_markers: string[];
    fail_markers: string[];
    redaction_applied: boolean;
    timed_out: boolean;
    timeout_seconds: number | null;
  }>;
}

export interface DynamicHostAgentPackages {
  success: boolean;
  serial: string;
  count: number;
  packages: string[];
  truncated: boolean;
  return_code: number;
  duration_seconds: number;
}

export interface DynamicHostAgentInstallResult
  extends DynamicHostAgentActionResult {
  install_status: "PASS" | "FAIL" | string;
  sha256: string;
  size_bytes: number;
  audit: number;
  apk_file: number;
  package_name: string;
  package_metadata: {
    package_name: string;
    version_name: string;
    version_code: string;
    installed_apk_path: string;
    launchable_activity: string;
    requested_permission_count: number;
    granted_permission_count: number;
  };
}
