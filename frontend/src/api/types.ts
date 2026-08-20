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
  evidence_count?: number;
  related_agent_runs?: number[];
  related_agent_run_steps?: number[];
  provenance?: "DETERMINISTIC_DYNAMIC_EVIDENCE" | "DETERMINISTIC_STATIC_RULE";
  dynamic_validation_status?: string;
  dynamic_validation_result_id?: number | null;
  dynamic_validation_mission_id?: number | null;
  dynamic_validation_summary?: {
    mission_id?: number;
    run_id?: number | null;
    status?: string;
    hypothesis?: string;
    scenario_summary?: string;
    evidence_count?: number;
    oracle_result?: Record<string, unknown>;
    final_conclusion?: string;
    limitations?: string;
    created_at?: string;
    completed_at?: string | null;
  };
  dynamic_validation_playbooks?: string[];
}

export interface DynamicPlaybook {
  playbook_id: string;
  title: string;
  description: string;
  applicable_static_rule_ids: string[];
  masvs_mapping: string[];
  required_evidence_inputs: string[];
  supported_tools: string[];
  required_capabilities: string[];
  safe_argument_policy: string;
  oracle_id: string;
  result_states: string[];
  limitations: string;
  destructive: boolean;
  requires_additional_approval: boolean;
  default_priority: number;
  current_capability_status: string;
}

export interface DynamicValidationResult {
  id: number;
  audit: number;
  finding: number | null;
  rule_id: string;
  scenario_id: string;
  playbook_id: string;
  agent_run: number | null;
  oracle_id: string;
  oracle_result: Record<string, unknown>;
  validation_status: string;
  result: string;
  evidence_ids: number[];
  confidence: number;
  safe_summary: string;
  limitations: string;
  created_at: string;
}

export interface FindingValidationMission {
  id: number;
  audit: number;
  apk: number | null;
  finding: number;
  finding_title: string;
  finding_rule_id: string;
  finding_severity: string;
  assessment_plan: number | null;
  assessment_plan_status?: string;
  agent_run: number | null;
  agent_run_status?: string;
  dynamic_validation_result: number | null;
  dynamic_validation_result_status?: string;
  target_package: string;
  status: string;
  scenario_contract: Record<string, unknown>;
  scenario_hash: string;
  mission_hash: string;
  validation_family: string;
  playbook_id: string;
  hypothesis: string;
  final_conclusion: string;
  limitations: string;
  oracle_result: Record<string, unknown>;
  provider: string;
  model: string;
  provider_metadata: Record<string, unknown>;
  allowed_capabilities: string[];
  budgets: Record<string, unknown>;
  evidence_ids: number[];
  evidence_count: number;
  result_label?: string;
  result_explanation?: string;
  scenario_summary?: string;
  created_by: number | null;
  approved_by: number | null;
  approved_by_username?: string;
  approved_at: string | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  updated_at: string;
}

export type CorrelationClassification =
  | "RECOMMENDED_DYNAMIC_VALIDATION"
  | "OPTIONAL_DYNAMIC_VALIDATION"
  | "STATIC_EVIDENCE_SUFFICIENT"
  | "NOT_TESTABLE_WITH_CURRENT_CAPABILITIES"
  | "ALREADY_VALIDATED"
  | "BLOCKED_BY_LAB_CAPABILITY";

export interface CorrelationCandidate {
  finding_id: number;
  finding_title: string;
  severity: string;
  confidence: string;
  rule_id: string;
  category: string;
  classification: CorrelationClassification;
  priority: number;
  security_hypothesis: string;
  dynamic_validation_value: string;
  recommended_poc_summary: string;
  likely_capabilities: string[];
  expected_evidence: string[];
  prerequisites: string;
  limitations: string;
  estimated_complexity: string;
  current_validation_status: string;
  missing_capabilities: string[];
  start_poc_available: boolean;
}

export interface CapabilityGapEntry {
  missing_capability: string;
  affected_finding_count: number;
  affected_finding_ids: number[];
}

export interface CapabilityGapReport {
  audit_id: number;
  contract_version: string;
  available_capabilities: string[];
  unavailable_capabilities: string[];
  testable_with_current_primitives: number;
  total_static_findings: number;
  highest_value_missing_capabilities: CapabilityGapEntry[];
}

export interface StaticDynamicCorrelation {
  audit_id: number;
  target_package: string;
  contract_version: string;
  total_static_findings: number;
  recommended_count: number;
  optional_count: number;
  static_sufficient_count: number;
  not_testable_count: number;
  already_validated_count: number;
  blocked_count: number;
  correlation_mode: string;
  model: string;
  generated_at: string;
  capability_gaps: CapabilityGapEntry[];
  candidates: CorrelationCandidate[];
}

export interface CorrelationStartPocResponse {
  mission: FindingValidationMission;
  next_step: string;
}

export interface FindingValidationTimelineItem {
  sequence: number;
  scenario_step_id: string;
  scenario_title: string;
  purpose: string;
  tool_name: string;
  friendly_action_label?: string;
  observation_summary?: string;
  status: string;
  decision_summary: string;
  expected_observation: string;
  observation: Record<string, unknown>;
  evidence_goal: string[];
  troubleshooting: boolean;
  failure_message: string;
  created_at: string;
}

export interface FindingValidationTimeline {
  mission_id: number;
  finding_id: number;
  agent_run_id: number | null;
  status: string;
  items: FindingValidationTimelineItem[];
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
  agent_run: number | null;
  agent_run_step: number | null;
  agent_run_artifact: number | null;
  evidence_type: string;
  source: string;
  snippet: string;
  redacted: boolean;
  sha256: string;
  provenance: Record<string, unknown>;
  created_at: string;
  evidence_title?: string;
  evidence_preview_type?: string;
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
  dynamic_assessments: {
    count: number;
    bounded: boolean;
    planner_is_execution_authority: boolean;
    finding_authority: string;
    items: Array<Record<string, unknown>>;
  };
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
}

export interface DynamicHostAgentStatus {
  connected: boolean;
  enabled: boolean;
  code: string;
  detail: string;
  configured_url?: string;
  last_checked_at?: string;
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

export interface OpenAIBudgetStatus {
  scope: string;
  max_mission_generation_calls: number;
  max_adaptive_decision_calls: number;
  max_total_openai_calls: number;
  mission_generation_call_count: number;
  adaptive_decision_call_count: number;
  current_openai_call_count: number;
  remaining_total_calls: number;
  provider_response_ids: string[];
  budget_exhausted_reason: string;
  exhausted: boolean;
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

export interface AgentRuntime {
  id: number;
  name: string;
  runtime_type: "INTERNAL_CONTROLLER" | "CONTAINER_SANDBOX";
  status: "AVAILABLE" | "UNAVAILABLE" | "DEGRADED" | "DISABLED";
  description: string;
  capabilities: {
    objectives?: string[];
    tools?: string[];
  };
  isolation_level:
    | "INTERNAL_ONLY"
    | "CONTAINER_PLANNED"
    | "CONTAINER_ISOLATED";
  enabled: boolean;
  configuration_enabled: boolean;
  available: boolean;
  last_seen_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface AgentDeviceSummary {
  serial: string;
  android_version: string;
  api_level: number | null;
  abi: string;
  root_uid: number | null;
  selinux: string;
  proxy: string;
  focused_app: string;
}

export interface AgentScreenshotSummary {
  content_type?: string;
  width?: number | null;
  height?: number | null;
  size_bytes?: number;
  sha256?: string;
  captured_at?: string;
  object_reference_id?: number | null;
}

export interface FridaStatusSummary {
  status?: string;
  frida_client_installed?: boolean;
  frida_client_version?: string;
  frida_server_reachable?: boolean;
  frida_server_version?: string;
  version_agreement?: boolean;
  frida_rpc?: string;
  emulator_serial?: string;
  android_version?: string;
  api_level?: number | null;
  abi?: string;
  root_available?: boolean;
  target_package?: string;
  target_pid?: number | null;
  attach_capability?: boolean;
  process_count?: number | null;
}

export interface FridaLogcatSummary {
  t0?: string;
  t1?: string;
  t2?: string;
  line_count?: number | null;
  lines?: string[];
  sha256?: string;
  redaction_applied?: boolean;
}

export interface AgentRunResultSummary {
  objective?: string;
  runtime_type?: "INTERNAL_CONTROLLER" | "CONTAINER_SANDBOX" | "";
  runtime_name?: string;
  isolation_level?: string;
  host_agent_reachable?: boolean;
  emulator_reachable?: boolean;
  device?: AgentDeviceSummary;
  screenshot_captured?: boolean;
  screenshot?: AgentScreenshotSummary;
  environment_ready?: boolean;
  summary?: string;
  assessment_scope?: string;
  app_installed?: boolean;
  app_already_present?: boolean;
  package_name?: string;
  app_launched?: boolean;
  ui_dumped?: boolean;
  ui_dump?: {
    node_count?: number | null;
    focused_package?: string;
    text_values?: string[];
    resource_ids?: string[];
    raw_preview?: string;
    xml_sha256?: string;
  };
  logcat_captured?: boolean;
  logcat_excerpt?: {
    line_count?: number;
    lines?: string[];
    redaction_applied?: boolean;
  };
  tap_executed?: boolean;
  tap_skipped?: boolean;
  type_executed?: boolean;
  type_skipped?: boolean;
  force_stop_completed?: boolean;
  interaction_completed?: boolean;
  operation?: "status" | "setup" | "ps" | "attach" | "";
  completed?: boolean;
  result?: FridaStatusSummary & Record<string, unknown>;
  script_name?: string;
  execution_succeeded?: boolean;
  evidence_confirmed?: boolean;
  pid?: number | null;
  frida_client_version?: string;
  frida_server_version?: string;
  attach_succeeded?: boolean;
  frida_event?: Record<string, unknown>;
  frida_event_received?: boolean;
  before_screenshot?: AgentScreenshotSummary;
  after_screenshot?: AgentScreenshotSummary;
  before_ui?: AgentRunResultSummary["ui_dump"];
  after_ui?: AgentRunResultSummary["ui_dump"];
  before_ui_node_count?: number | null;
  after_ui_node_count?: number | null;
  screenshot_changed?: boolean;
  ui_changed?: boolean;
  visual_state_changed?: boolean;
  logcat?: FridaLogcatSummary;
  event_count?: number;
  error_count?: number;
  cleanup_state?: string;
  interpretation?: string;
  limitations?: string;
  assessment_plan_id?: number;
  approved_plan_hash?: string;
  target_package?: string;
  execution_mode?: string;
  execution_channel?: string;
  capability_envelope_hash?: string;
  decision_provider?: string;
  decision_model?: string;
  decision_count?: number;
  model_call_count?: number;
  coverage?: Record<string, string>;
  termination_reason?: string;
  hypothesis_status_counts?: Record<string, number>;
  findings_authority?: string;
  step_status_counts?: Record<string, number>;
  tool_call_count?: number;
  artifact_count?: number;
  evidence_count?: number;
  observations_are_untrusted_data?: boolean;
  finding_count_created?: number;
  finding_count_total?: number;
  risk?: { score?: number | null; severity?: string };
  compliance?: { standard?: string; score?: number | null };
  report?: { id?: number; type?: string; status?: string };
  post_processing?: Record<string, unknown>;
  provider_failure?: {
    code?: string;
    provider_http_status?: number;
    provider_error_type?: string;
    provider_error_code?: string;
    provider_error_param?: string;
  };
  pre_execution_failure?: boolean;
  no_device_action_performed?: boolean;
  plan_approval_preserved?: boolean;
}

export interface AssessmentRunSummary {
  contract_version: "msap.assessment-summary/v1";
  audit_id: number;
  target_package: string;
  assessment_status: AgentRun["status"];
  assessment_plan_id: number;
  plan_hash: string;
  execution_mode: "SEQUENTIAL_PLAN" | "ADAPTIVE_AGENT";
  capability_envelope_hash: string;
  agent_run_id: number;
  steps_total: number;
  steps_succeeded: number;
  step_status_counts: Record<string, number>;
  tool_call_count: number;
  decision_count: number;
  model_call_count: number;
  coverage: Record<string, string>;
  termination_reason: string;
  observation_count: number;
  artifact_count: number;
  evidence_count: number;
  run_finding_count: number;
  audit_finding_count: number;
  finding_severity_counts: Record<string, number>;
  run_findings: Array<{
    id: number;
    rule_id: string;
    title: string;
    severity: string;
    confidence: string;
    status: string;
    category: string;
  }>;
  dynamic_validations: Array<{
    id: number;
    finding_id: number;
    rule_id: string;
    playbook_id: string;
    validation_status: string;
    oracle_result: string | { status?: string; summary?: string; oracle_id?: string };
    limitations: string;
  }>;
  risk: { score: number | null; severity: string };
  compliance: { standard: string; score: number | null };
  report: { id: number | null; status: string; type: string };
  provenance: Record<string, string>;
}

export type AgentObjective =
  | "DEVICE_READINESS_CHECK"
  | "BASIC_APP_INTERACTION_CHECK"
  | "FRIDA_RUNTIME_ACTION"
  | "FRIDA_RUNTIME_UI_MODIFICATION_PROOF"
  | "FRIDA_CUSTOM_SCRIPT"
  | "ASSESSMENT_PLAN_EXECUTION";

export interface BasicAppInteractionInput {
  audit_id: number;
  apk_file_id?: number;
  package_name?: string;
  tap?: { x: number; y: number };
  text?: string;
}

export interface FridaRuntimeActionInput {
  audit_id: number;
  package_name: string;
  operation: "status" | "setup" | "ps" | "attach";
  mode?: "attach" | "spawn";
  timeout?: number;
}

export interface FridaProofInput {
  audit_id: number;
  package_name: string;
}

export interface FridaCustomScriptInput extends FridaProofInput {
  mode?: "attach" | "spawn";
  source: string;
  timeout?: number;
  capture_logcat?: boolean;
  confirm: true;
}

export type AgentObjectiveInput =
  | BasicAppInteractionInput
  | FridaRuntimeActionInput
  | FridaProofInput
  | FridaCustomScriptInput;

export interface AgentRun {
  id: number;
  audit: number | null;
  device: number | null;
  device_serial: string | null;
  runtime: number | null;
  runtime_name: string | null;
  runtime_type: "INTERNAL_CONTROLLER" | "CONTAINER_SANDBOX" | null;
  isolation_level:
    | "INTERNAL_ONLY"
    | "CONTAINER_PLANNED"
    | "CONTAINER_ISOLATED"
    | null;
  assessment_plan: number | null;
  approved_plan_hash: string;
  target_package: string;
  execution_mode: "SEQUENTIAL_PLAN" | "ADAPTIVE_AGENT";
  capability_envelope: Record<string, unknown> & {
    allowed_capabilities?: string[];
    allowed_hypothesis_families?: string[];
    maximum_decisions?: number;
    maximum_tool_calls?: number;
    maximum_run_duration_seconds?: number;
    maximum_model_provider_calls?: number;
  };
  capability_envelope_hash: string;
  decision_provider: string;
  decision_model: string;
  decision_count: number;
  model_call_count: number;
  consecutive_failure_count: number;
  coverage_state: Record<string, string>;
  termination_reason: string;
  objective: AgentObjective;
  objective_input: Record<string, unknown>;
  status:
    | "QUEUED"
    | "RUNNING"
    | "PAUSED"
    | "SUCCEEDED"
    | "FAILED"
    | "CANCELLED"
    | "TIMEOUT";
  requested_by: number | null;
  requested_by_username: string | null;
  started_at: string | null;
  finished_at: string | null;
  duration_seconds: number | null;
  result_summary: AgentRunResultSummary;
  failure_category: string;
  failure_message: string;
  pre_execution_failure: boolean;
  plan_approval_preserved: boolean;
  adaptive_retryable: boolean;
  adaptive_retry_block_reason: string;
  tool_call_count: number;
  cancellation_requested_at: string | null;
  cancelled_by: number | null;
  created_at: string;
  updated_at: string;
}

export interface AgentHypothesis {
  id: number;
  run: number;
  hypothesis_id: string;
  family: string;
  title: string;
  description: string;
  evidence_requirements: string[];
  status:
    | "UNTESTED"
    | "ACTIVE"
    | "SUPPORTED"
    | "REJECTED"
    | "INCONCLUSIVE"
    | "BLOCKED";
  confidence: number;
  oracle_result: {
    oracle_id?: string;
    status?: string;
    evidence_ids?: number[];
    reason_code?: string;
    safe_summary?: string;
    confidence?: number;
  };
  created_at: string;
  updated_at: string;
}

export interface AgentActionDecision {
  id: number;
  run: number;
  sequence: number;
  contract_version: string;
  hypothesis: number | null;
  hypothesis_identifier: string | null;
  run_step: number | null;
  decision_type: "TOOL_ACTION" | "COMPLETE" | "NEEDS_AUDITOR";
  tool_name: string;
  arguments: Record<string, unknown>;
  rationale_summary: string;
  expected_observation: string;
  evidence_goals: string[];
  confidence: number;
  provider: "OPENAI" | "DETERMINISTIC";
  model: string;
  provider_metadata: Record<string, string | number>;
  decision_input_hash: string;
  decision_output_hash: string;
  validation_status: "PENDING" | "PASSED" | "FAILED";
  policy_status: "PENDING" | "PASSED" | "FAILED";
  execution_status:
    | "NOT_EXECUTED"
    | "RUNNING"
    | "SUCCEEDED"
    | "FAILED"
    | "REJECTED";
  observation_hash: string;
  failure_code: string;
  created_at: string;
  validated_at: string | null;
  executed_at: string | null;
}

export interface AgentRunStep {
  id: number;
  run: number;
  sequence_number: number;
  tool_name:
    | "get_device_status"
    | "list_packages"
    | "install_verified_apk"
    | "launch_package"
    | "force_stop_package"
    | "clear_package_data"
    | "take_screenshot"
    | "start_logcat"
    | "stop_logcat"
    | "get_logcat_excerpt"
    | "dump_ui"
    | "tap_coordinates"
    | "type_text"
    | "frida_status"
    | "frida_ps"
    | "frida_setup"
    | "frida_attach"
    | "frida_run_js"
    | "assessment_plan_observation";
  plan_step_identifier: string;
  plan_step_sequence: number | null;
  tool_call_index: number;
  is_control_step: boolean;
  dependencies: string[];
  evidence_requirements: string[];
  status:
    | "PENDING"
    | "RUNNING"
    | "SUCCEEDED"
    | "FAILED"
    | "SKIPPED"
    | "TIMEOUT"
    | "CANCELLED";
  input_summary: Record<string, unknown>;
  output_summary: Record<string, unknown>;
  observation: Record<string, unknown>;
  retry_count: number;
  max_retries: number;
  timeout_seconds: number;
  started_at: string | null;
  finished_at: string | null;
  duration_seconds: number | null;
  failure_message: string;
  created_at: string;
}

export interface AgentRunArtifact {
  id: number;
  run: number;
  step: number | null;
  artifact_type:
    | "SCREENSHOT"
    | "TOOL_OUTPUT"
    | "LOG"
    | "JSON_RESULT"
    | "OTHER";
  name: string;
  content_type: string;
  object_reference: number | null;
  download_url: string;
  metadata: Record<string, unknown>;
  size_bytes: number | null;
  sha256: string;
  created_at: string;
}

export type AssessmentPlanStatus =
  | "DRAFT"
  | "GENERATED"
  | "VALIDATED"
  | "APPROVED"
  | "REJECTED"
  | "EXECUTING"
  | "COMPLETED"
  | "FAILED"
  | "CANCELLED";

export interface AssessmentPlanStep {
  id: number;
  plan: number;
  sequence: number;
  step_identifier: string;
  objective: string;
  rationale: string;
  required_tools: string[];
  tool_arguments: Record<string, Record<string, unknown>>;
  expected_observation: string;
  success_condition: string;
  evidence_requirements: string[];
  dependencies: string[];
  status:
    | "PROPOSED"
    | "VALIDATED"
    | "APPROVED"
    | "EXECUTING"
    | "COMPLETED"
    | "FAILED"
    | "SKIPPED"
    | "CANCELLED";
  created_at: string;
  updated_at: string;
}

export interface AssessmentPlan {
  id: number;
  audit: number;
  source_finding: number | null;
  plan_kind: "INITIAL" | "ADAPTIVE";
  parent_plan: number | null;
  source_run: number | null;
  adaptive_cycle: number;
  target_package: string;
  planner_provider: "DETERMINISTIC" | "OPENAI";
  planner_model: string;
  objective: string;
  scope: string;
  status: AssessmentPlanStatus;
  validation_status: "PENDING" | "PASSED" | "FAILED";
  policy_status: "PENDING" | "PASSED" | "FAILED";
  generated_plan: Record<string, unknown>;
  normalized_plan: Record<string, unknown>;
  provider_metadata: {
    provider_status?: string;
    response_id?: string;
    retry_count?: number;
    latency_ms?: number;
    input_tokens?: number;
    cached_input_tokens?: number;
    output_tokens?: number;
    reasoning_tokens?: number;
    total_tokens?: number;
  };
  validation_errors: string[];
  planner_input_hash: string;
  plan_hash: string;
  agentic_capability_preview: {
    contract_version?: string;
    allowed_capabilities?: string[];
    allowed_hypothesis_families?: string[];
    maximum_decisions?: number;
    maximum_tool_calls?: number;
    maximum_run_duration_seconds?: number;
    maximum_provider_calls?: number;
    additional_approval_capabilities?: string[];
  };
  created_by: number | null;
  created_by_username: string | null;
  approved_by: number | null;
  approved_by_username: string | null;
  validated_at: string | null;
  approved_at: string | null;
  created_at: string;
  updated_at: string;
  steps: AssessmentPlanStep[];
  scenario_contract?: Record<string, unknown>;
}
