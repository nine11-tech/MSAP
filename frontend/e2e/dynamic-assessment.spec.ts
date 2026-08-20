import { expect, test, type Page, type Route } from "@playwright/test";

const now = "2026-08-16T12:00:00Z";

function plan(status: "GENERATED" | "VALIDATED" | "APPROVED" | "EXECUTING" | "COMPLETED") {
  return {
    id: 101,
    audit: 1,
    plan_kind: "INITIAL",
    parent_plan: null,
    source_run: null,
    adaptive_cycle: 0,
    target_package: "owasp.sat.agoat",
    planner_provider: "OPENAI",
    planner_model: "gpt-5.6-luna",
    objective: "Perform a bounded adaptive runtime security assessment.",
    scope: "Assess only owasp.sat.agoat on the managed emulator.",
    status,
    validation_status: "PASSED",
    policy_status: "PASSED",
    generated_plan: {},
    normalized_plan: {},
    provider_metadata: {
      provider_status: "completed",
      input_tokens: 1200,
      output_tokens: 700,
      reasoning_tokens: 0,
      retry_count: 0,
    },
    validation_errors: [],
    planner_input_hash: "a".repeat(64),
    plan_hash: "b".repeat(64),
    agentic_capability_preview: {
      contract_version: "msap.agent-capability-envelope/v1",
      allowed_capabilities: ["get_device_status", "launch_package", "dump_ui"],
      allowed_hypothesis_families: ["UI_SENSITIVE_DATA_EXPOSURE"],
      maximum_decisions: 4,
      maximum_tool_calls: 4,
      maximum_run_duration_seconds: 180,
      maximum_provider_calls: 4,
      additional_approval_capabilities: [],
    },
    created_by: 1,
    created_by_username: "analyst",
    approved_by: status === "APPROVED" || status === "EXECUTING" || status === "COMPLETED" ? 1 : null,
    approved_by_username: status === "APPROVED" || status === "EXECUTING" || status === "COMPLETED" ? "analyst" : null,
    validated_at: now,
    approved_at: status === "APPROVED" || status === "EXECUTING" || status === "COMPLETED" ? now : null,
    created_at: now,
    updated_at: now,
    steps: [
      {
        id: 1,
        plan: 101,
        sequence: 1,
        step_identifier: "establish_runtime",
        objective: "Establish managed device readiness",
        rationale: "Collect bounded runtime state before application interaction.",
        required_tools: ["get_device_status"],
        tool_arguments: { get_device_status: {} },
        expected_observation: "Managed emulator readiness state.",
        success_condition: "The managed device is ready.",
        evidence_requirements: ["tool_output"],
        dependencies: [],
        status: "PROPOSED",
        created_at: now,
        updated_at: now,
      },
      {
        id: 2,
        plan: 101,
        sequence: 2,
        step_identifier: "inspect_ui",
        objective: "Inspect the authorized application interface",
        rationale: "Collect bounded UI evidence after target launch.",
        required_tools: ["launch_package", "dump_ui"],
        tool_arguments: { launch_package: { package_name: "owasp.sat.agoat" }, dump_ui: { package_name: "owasp.sat.agoat" } },
        expected_observation: "Target-correlated UI nodes.",
        success_condition: "Bounded UI evidence is persisted.",
        evidence_requirements: ["ui_hierarchy", "screenshot"],
        dependencies: ["establish_runtime"],
        status: "PROPOSED",
        created_at: now,
        updated_at: now,
      },
    ],
  };
}

function run(status: "RUNNING" | "SUCCEEDED" | "FAILED", adaptiveRetryable = false) {
  const failed = status === "FAILED";
  return {
    id: 202,
    audit: 1,
    device: 1,
    device_serial: "emulator-5554",
    runtime: 1,
    runtime_name: "Internal Controller",
    runtime_type: "INTERNAL_CONTROLLER",
    isolation_level: "INTERNAL_ONLY",
    assessment_plan: 101,
    approved_plan_hash: "b".repeat(64),
    target_package: "owasp.sat.agoat",
    execution_mode: "ADAPTIVE_AGENT",
    capability_envelope: { maximum_decisions: 4, maximum_tool_calls: 4, maximum_run_duration_seconds: 180 },
    capability_envelope_hash: "c".repeat(64),
    decision_provider: "OPENAI",
    decision_model: "gpt-5.6-luna",
    decision_count: failed ? 0 : 2,
    model_call_count: failed ? 1 : 2,
    consecutive_failure_count: 0,
    coverage_state: {
      device_runtime_readiness: "ASSESSED",
      application_interaction: "ASSESSED",
      ui_exposure: "ASSESSED",
      logging: "NOT_STARTED",
      runtime_instrumentation: "NOT_STARTED",
      network_tls: "NOT_ASSESSABLE_WITH_CURRENT_CAPABILITIES",
      local_storage: "NOT_ASSESSABLE_WITH_CURRENT_CAPABILITIES",
    },
    termination_reason: status === "SUCCEEDED" ? "MODEL_COMPLETE" : failed ? "PROVIDER_FAILURE" : "",
    objective: "ASSESSMENT_PLAN_EXECUTION",
    objective_input: {},
    status,
    requested_by: 1,
    requested_by_username: "analyst",
    started_at: now,
    finished_at: status === "RUNNING" ? null : "2026-08-16T12:00:42Z",
    duration_seconds: status === "RUNNING" ? null : 42,
    result_summary: failed
      ? { provider_failure: { code: "PROVIDER_SCHEMA_LOCAL_REJECTED" }, pre_execution_failure: true, no_device_action_performed: true, plan_approval_preserved: true, report: { id: 5, type: "JSON", status: "READY" } }
      : { finding_count_total: 1, report: { id: 5, type: "JSON", status: status === "SUCCEEDED" ? "READY" : "PENDING" } },
    failure_category: failed ? "AI_PROVIDER_FAILURE" : "",
    failure_message: failed ? "AI schema is not compatible with the provider. No request was sent." : "",
    pre_execution_failure: failed,
    plan_approval_preserved: failed,
    adaptive_retryable: failed && adaptiveRetryable,
    adaptive_retry_block_reason: failed && adaptiveRetryable ? "ADAPTIVE_RETRY_ALLOWED" : "ADAPTIVE_RETRY_PERMISSION_DENIED",
    tool_call_count: failed ? 0 : 2,
    cancellation_requested_at: null,
    cancelled_by: null,
    created_at: now,
    updated_at: now,
  };
}

const steps = [
  {
    id: 301, run: 202, sequence_number: 1, tool_name: "get_device_status", plan_step_identifier: "adaptive_1", plan_step_sequence: null, tool_call_index: 1, is_control_step: false, dependencies: [], evidence_requirements: ["tool_output"], status: "SUCCEEDED", input_summary: {}, output_summary: { ready: true, android_version: "15" }, observation: { ready: true }, retry_count: 0, max_retries: 0, timeout_seconds: 12, started_at: now, finished_at: now, duration_seconds: 0.4, failure_message: "", created_at: now,
  },
  {
    id: 302, run: 202, sequence_number: 2, tool_name: "launch_package", plan_step_identifier: "adaptive_2", plan_step_sequence: null, tool_call_index: 1, is_control_step: false, dependencies: [], evidence_requirements: ["tool_output"], status: "SUCCEEDED", input_summary: { package_name: "owasp.sat.agoat" }, output_summary: { launched: true, focused_app: "owasp.sat.agoat" }, observation: { launched: true }, retry_count: 0, max_retries: 0, timeout_seconds: 12, started_at: now, finished_at: now, duration_seconds: 0.7, failure_message: "", created_at: now,
  },
];

const hypotheses = [
  { id: 401, run: 202, hypothesis_id: "ui_sensitive_data_exposure", family: "UI_SENSITIVE_DATA_EXPOSURE", title: "Sensitive UI exposure", description: "Bounded UI evidence", evidence_requirements: ["ui_hierarchy"], status: "REJECTED", confidence: 0.9, oracle_result: { oracle_id: "msap.oracle.ui/v1", status: "REJECTED", evidence_ids: [501], safe_summary: "No deterministic sensitive UI marker was supported." }, created_at: now, updated_at: now },
];

const decisions = [
  { id: 601, run: 202, sequence: 1, contract_version: "msap.agent-action-decision/v1", hypothesis: 401, hypothesis_identifier: "ui_sensitive_data_exposure", run_step: 301, decision_type: "TOOL_ACTION", tool_name: "get_device_status", arguments: {}, rationale_summary: "Establish managed device readiness before interacting with the target.", expected_observation: "Managed emulator readiness.", evidence_goals: ["tool_output"], confidence: 0.92, provider: "OPENAI", model: "gpt-5.6-luna", provider_metadata: {}, decision_input_hash: "d".repeat(64), decision_output_hash: "e".repeat(64), validation_status: "PASSED", policy_status: "PASSED", execution_status: "SUCCEEDED", observation_hash: "f".repeat(64), failure_code: "", created_at: now, validated_at: now, executed_at: now },
  { id: 602, run: 202, sequence: 2, contract_version: "msap.agent-action-decision/v1", hypothesis: 401, hypothesis_identifier: "ui_sensitive_data_exposure", run_step: 302, decision_type: "TOOL_ACTION", tool_name: "launch_package", arguments: { package_name: "owasp.sat.agoat" }, rationale_summary: "The readiness observation confirms the lab is available, so launch the authorized target.", expected_observation: "The target becomes foregrounded.", evidence_goals: ["tool_output"], confidence: 0.94, provider: "OPENAI", model: "gpt-5.6-luna", provider_metadata: {}, decision_input_hash: "1".repeat(64), decision_output_hash: "2".repeat(64), validation_status: "PASSED", policy_status: "PASSED", execution_status: "SUCCEEDED", observation_hash: "3".repeat(64), failure_code: "", created_at: now, validated_at: now, executed_at: now },
];

const evidence = [
  { id: 501, audit: 1, finding: 701, indicator: null, storage_reference: null, agent_run: 202, agent_run_step: 302, agent_run_artifact: null, evidence_type: "ui_hierarchy", source: "adaptive-agent", snippet: "17 bounded UI nodes captured for the authorized target.", redacted: true, sha256: "4".repeat(64), provenance: {}, created_at: now },
];

const artifacts = [
  { id: 801, run: 202, step: 302, artifact_type: "SCREENSHOT", name: "androgoat-ui.png", content_type: "image/png", object_reference: 9, download_url: "http://127.0.0.1:8000/artifacts/androgoat-ui.png", metadata: {}, size_bytes: 128, sha256: "5".repeat(64), created_at: now },
];

const assessmentSummary = {
  contract_version: "msap.assessment-summary/v1",
  audit_id: 1,
  target_package: "owasp.sat.agoat",
  assessment_status: "SUCCEEDED",
  assessment_plan_id: 101,
  plan_hash: "b".repeat(64),
  execution_mode: "ADAPTIVE_AGENT",
  capability_envelope_hash: "c".repeat(64),
  agent_run_id: 202,
  steps_total: 2,
  steps_succeeded: 2,
  step_status_counts: { SUCCEEDED: 2 },
  tool_call_count: 2,
  decision_count: 2,
  model_call_count: 2,
  coverage: run("SUCCEEDED").coverage_state,
  termination_reason: "MODEL_COMPLETE",
  observation_count: 2,
  artifact_count: 1,
  evidence_count: 1,
  run_finding_count: 1,
  audit_finding_count: 1,
  finding_severity_counts: { Medium: 1 },
  run_findings: [{ id: 701, rule_id: "MSAP-DYN-UI-001", title: "Sensitive UI evidence requires review", severity: "Medium", confidence: "HIGH", status: "OPEN", category: "UI" }],
  risk: { score: 28, severity: "Low" },
  compliance: { standard: "MASVS", score: 88 },
  report: { id: 5, status: "READY", type: "JSON" },
  provenance: {},
};

async function fulfillJson(route: Route, body: unknown, status = 200) {
  await route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });
}

async function installMockApi(page: Page, options: { planningFailure?: boolean; planningSchemaFailure?: boolean; preExecutionFailure?: boolean; initialFailure?: boolean; viewer?: boolean } = {}) {
  let planState: ReturnType<typeof plan> | null = options.initialFailure ? plan("APPROVED") : null;
  let runState: ReturnType<typeof run> | null = options.initialFailure ? run("FAILED", !options.viewer) : null;
  let runPolls = 0;

  await page.route("**/artifacts/androgoat-ui.png", async (route) => {
    await route.fulfill({ contentType: "image/png", body: Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=", "base64") });
  });
  await page.route("http://127.0.0.1:8000/api/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const path = url.pathname.replace(/^\/api\//, "");
    const method = request.method();
    if (path === "auth/csrf/") return fulfillJson(route, { csrfToken: "test-csrf" });
    if (path === "auth/me/") return fulfillJson(route, { id: 1, username: options.viewer ? "viewer" : "analyst", email: "", first_name: "Security", last_name: options.viewer ? "Viewer" : "Analyst", role: options.viewer ? "VIEWER" : "ANALYST", is_staff: false, permissions: [] });
    if (path.startsWith("system/status/")) return fulfillJson(route, { overall_status: "OPERATIONAL", checked_at: now, components: [{ id: "minio", label: "Object storage", status: "OPERATIONAL", latency_ms: 4, message: "Ready", last_successful_check: now }, { id: "celery", label: "Assessment worker", status: "OPERATIONAL", latency_ms: 5, message: "Ready", last_successful_check: now }] });
    if (path === "audits/") return fulfillJson(route, [{ id: 1, project: 1, name: "AndroGoat Acceptance", status: "ANALYSIS_COMPLETED", created_at: now, updated_at: now }]);
    if (path === "apk-files/") return fulfillJson(route, [{ id: 10, audit: 1, package_name: "owasp.sat.agoat", version_name: "1.0", sha256: "6".repeat(64), size_bytes: 1024, storage_reference: 1, storage_status: "VERIFIED", created_at: now }]);
    if (path === "dynamic/host-agent/status/") return fulfillJson(route, { connected: true, enabled: true, code: "HOST_AGENT_CONNECTED", detail: "Ready", agent: { version: "1.0" }, device: { serial: "emulator-5554", state: "device", root_uid: 0, api_level: 35, android_version: "15", abi: "x86_64", selinux: "Enforcing", focused_app: "owasp.sat.agoat/.MainActivity" }, last_sync_at: now });
    if (path === "dynamic/host-agent/packages/") return fulfillJson(route, { packages: ["owasp.sat.agoat"], count: 1, truncated: false });
    if (path === "dynamic/finding-validations/budget-status/") return fulfillJson(route, { scope: "GLOBAL", max_mission_generation_calls: 1, max_adaptive_decision_calls: 6, max_total_openai_calls: 7, mission_generation_call_count: 0, adaptive_decision_call_count: 0, current_openai_call_count: 0, remaining_total_calls: 7, provider_response_ids: [], budget_exhausted_reason: "", exhausted: false });
    if (path === "dynamic/agent/runtimes/") return fulfillJson(route, [{ id: 1, name: "Internal Controller", runtime_type: "INTERNAL_CONTROLLER", status: "AVAILABLE", description: "", capabilities: { tools: ["get_device_status", "launch_package", "dump_ui"] }, isolation_level: "INTERNAL_ONLY", enabled: true, configuration_enabled: true, available: true, last_seen_at: now, created_at: now, updated_at: now }]);
    if (path === "dynamic/agent/plans/" && method === "GET") return fulfillJson(route, planState ? [planState] : []);
    if (path === "dynamic/agent/runs/" && method === "GET") return fulfillJson(route, runState ? [runState] : []);
    if (path === "dynamic/agent/plans/" && method === "POST") {
      if (options.planningSchemaFailure) return fulfillJson(route, { code: "PROVIDER_SCHEMA_LOCAL_REJECTED", detail: "AI schema is not compatible with the provider. No request was sent." }, 503);
      if (options.planningFailure) return fulfillJson(route, { code: "PLANNER_PROVIDER_API_ERROR", detail: "Provider unavailable." }, 502);
      planState = plan("GENERATED");
      return fulfillJson(route, planState, 201);
    }
    if (path === "dynamic/agent/plans/101/validate/" && method === "POST") { planState = plan("VALIDATED"); return fulfillJson(route, planState); }
    if (path === "dynamic/agent/plans/101/approve/" && method === "POST") { planState = plan("APPROVED"); return fulfillJson(route, planState); }
    if (path === "dynamic/agent/plans/101/execute-adaptive/" && method === "POST") { planState = plan("EXECUTING"); runState = run("RUNNING"); return fulfillJson(route, { run: runState, task_id: "task-1", execution_mode: "ADAPTIVE_AGENT" }, 202); }
    if (path === "dynamic/agent/plans/101/" && method === "GET") return fulfillJson(route, runState?.status === "SUCCEEDED" ? plan("COMPLETED") : runState?.status === "FAILED" ? plan("APPROVED") : planState || plan("GENERATED"));
    if (path === "dynamic/agent/runs/202/" && method === "GET") { runPolls += 1; runState = options.preExecutionFailure ? run("FAILED", true) : runPolls >= 2 ? run("SUCCEEDED") : run("RUNNING"); return fulfillJson(route, runState); }
    if (path === "dynamic/agent/runs/202/retry-adaptive/" && method === "POST") { planState = plan("EXECUTING"); runState = { ...run("RUNNING"), id: 203, decision_count: 0, model_call_count: 0, tool_call_count: 0 }; return fulfillJson(route, { run: runState, task_id: "retry-task", execution_mode: "ADAPTIVE_AGENT", retry_of_agent_run_id: 202 }, 202); }
    if (path === "dynamic/agent/runs/203/" && method === "GET") return fulfillJson(route, runState);
    if (path.startsWith("dynamic/agent/runs/203/") && method === "GET") return fulfillJson(route, []);
    if (path === "dynamic/agent/runs/202/steps/") return fulfillJson(route, options.preExecutionFailure || options.initialFailure ? [] : steps);
    if (path === "dynamic/agent/runs/202/artifacts/") return fulfillJson(route, options.preExecutionFailure || options.initialFailure ? [] : artifacts);
    if (path === "dynamic/agent/runs/202/evidence/") return fulfillJson(route, options.preExecutionFailure || options.initialFailure ? [] : evidence);
    if (path === "dynamic/agent/runs/202/decisions/") return fulfillJson(route, options.preExecutionFailure || options.initialFailure ? [] : decisions);
    if (path === "dynamic/agent/runs/202/hypotheses/") return fulfillJson(route, hypotheses);
    if (path === "dynamic/agent/runs/202/assessment-summary/") return fulfillJson(route, assessmentSummary);
    return fulfillJson(route, []);
  });
}

async function openAdvancedTools(page: Page) {
  await page.getByText("Advanced Operator Tools", { exact: true }).click();
}

test("guided stages keep future and advanced controls out of the default finding-driven view", async ({ page }) => {
  await installMockApi(page);
  await page.goto("/dynamic/advanced");
  await expect(page.getByRole("heading", { name: "Advanced Operator Console" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Finding-Driven Dynamic Validation" })).toBeVisible();
  await expect(page.getByText("AI call budget 7/7", { exact: false })).toBeVisible();
  await expect(page.locator("details.advanced-operator-panel")).not.toHaveAttribute("open", "");
  await expect(page.getByRole("heading", { name: "Configure Security Assessment" })).toHaveCount(0);
  await page.getByText("Advanced Operator Tools", { exact: true }).click();
  await expect(page.getByRole("heading", { name: "Configure Security Assessment" })).toBeVisible();
  await expect(page.locator(".assessment-workflow > span")).toHaveCount(5);
  await expect(page.getByRole("heading", { name: "AI Assessment Plan" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Start Security Assessment" })).toHaveCount(0);
  await expect(page.locator("details.advanced-ai-settings")).not.toHaveAttribute("open", "");
  await page.getByText("Advanced AI Settings").click();
  await expect(page.locator(".advanced-ai-settings select").first()).toHaveValue("ECONOMY");
  await expect(page.locator(".auditor-primary-action strong")).toContainText("Economy · GPT-5.6 Luna");
});

test("auditor can generate, review, approve, start, watch evidence, and reach results", async ({ page }) => {
  await installMockApi(page);
  await page.goto("/dynamic/advanced");
  await openAdvancedTools(page);
  await page.getByRole("button", { name: "Generate AI Assessment" }).click();
  await expect(page.getByRole("heading", { name: "AI Assessment Plan" })).toBeVisible();
  await expect(page.getByText("Security checks passed", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Approve Assessment" })).toHaveCount(0);
  await expect(page.locator("details.plan-details-disclosure")).not.toHaveAttribute("open", "");
  await page.getByRole("button", { name: "Review & Continue" }).click();
  await expect(page.getByRole("heading", { name: "Assessment Ready for Approval" })).toBeVisible();
  await expect(page.getByText("Destructive actions")).toBeVisible();
  await page.getByRole("button", { name: "Approve Assessment" }).click();
  await expect(page.getByRole("button", { name: "Start Security Assessment" })).toBeVisible();
  await page.getByRole("button", { name: "Start Security Assessment" }).click();
  await expect(page.getByRole("heading", { name: "AI Security Agent" })).toBeVisible();
  await expect(page.getByText("Check device readiness")).toBeVisible();
  await expect(page.getByText("Launch AndroGoat")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Live evidence" })).toBeVisible();
  await expect(page.locator(".evidence-group-grid p").first()).toContainText("17 bounded UI nodes captured");
  await expect(page.getByRole("heading", { name: "Assessment completed" })).toBeVisible({ timeout: 10_000 });
  await expect(page.getByText("Sensitive UI evidence requires review")).toBeVisible();
  await expect(page.getByRole("link", { name: "View Assessment Report" }).first()).toBeVisible();
});

test("planning failure is safe and does not advance or offer execution", async ({ page }) => {
  await installMockApi(page, { planningFailure: true });
  await page.goto("/dynamic/advanced");
  await openAdvancedTools(page);
  await page.getByRole("button", { name: "Generate AI Assessment" }).click();
  await expect(page.getByText("AI planning could not be completed.")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Configure Security Assessment" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Approve Assessment" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Start Security Assessment" })).toHaveCount(0);
});

test("local planner schema rejection explains that no provider request was sent", async ({ page }) => {
  await installMockApi(page, { planningSchemaFailure: true });
  await page.goto("/dynamic/advanced");
  await openAdvancedTools(page);
  await page.getByRole("button", { name: "Generate AI Assessment" }).click();
  await expect(page.getByText("AI schema is not compatible with the provider. No request was sent.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Approve Assessment" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Start Security Assessment" })).toHaveCount(0);
});

test("provider schema failure before execution is accurate, empty, retryable, and collapsed", async ({ page }) => {
  const requests: string[] = [];
  await page.on("request", (request) => requests.push(request.url()));
  await installMockApi(page, { preExecutionFailure: true });
  await page.goto("/dynamic/advanced");
  await openAdvancedTools(page);
  await page.getByRole("button", { name: "Generate AI Assessment" }).click();
  await page.getByRole("button", { name: "Review & Continue" }).click();
  await page.getByRole("button", { name: "Approve Assessment" }).click();
  await page.getByRole("button", { name: "Start Security Assessment" }).click();

  await expect(page.getByText("AI assessment could not start. No Android actions were executed.")).toBeVisible({ timeout: 10_000 });
  await expect(page.getByText("AI schema failure · rejected before execution", { exact: true })).toBeVisible();
  await expect(page.getByText("No evidence yet", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Retry Adaptive Assessment" })).toBeVisible();
  await expect(page.locator("details.pre-execution-failure-details")).not.toHaveAttribute("open", "");
  await expect(page.getByRole("link", { name: "View Assessment Report" }).first()).toBeVisible();

  await page.getByRole("button", { name: "Retry Adaptive Assessment" }).click();
  await expect(page.getByRole("heading", { name: "AI Security Agent" })).toBeVisible();
  expect(requests.filter((url) => url.endsWith("/dynamic/agent/runs/202/retry-adaptive/")).length).toBe(1);
  expect(requests.filter((url) => url.includes("/tool-call/")).length).toBe(0);
});

test("viewer sees the safe pre-execution failure but cannot retry or mutate", async ({ page }) => {
  await installMockApi(page, { initialFailure: true, viewer: true });
  await page.goto("/dynamic/advanced");
  await openAdvancedTools(page);

  await expect(page.getByText("AI assessment could not start. No Android actions were executed.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Retry Adaptive Assessment" })).toHaveCount(0);
  await expect(page.locator(".agent-foundation-card button").first()).toBeDisabled();
});
