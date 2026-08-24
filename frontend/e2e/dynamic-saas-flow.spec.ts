import { expect, test, type Page, type Route } from "@playwright/test";

const now = "2026-08-20T10:00:00Z";

const audits = [
  { id: 1, project: 1, name: "AndroGoat Demo Audit", status: "ANALYSIS_COMPLETED", created_at: now, updated_at: now },
];

const apkFiles = [
  { id: 10, audit: 1, package_name: "owasp.sat.agoat", version_name: "1.0", sha256: "6".repeat(64), size_bytes: 1024, storage_reference: 1, storage_status: "VERIFIED", created_at: now },
];

const findings = [
  {
    id: 701,
    audit: 1,
    rule_id: "SDK-ROOT-001",
    title: "Runtime root detection UI can be instrumented",
    severity: "Medium",
    confidence: "HIGH",
    standard: "MASVS",
    category: "MASVS-RESILIENCE",
    description: "Root detection via RootBeer can be proven dynamically.",
    dynamic_validation_playbooks: ["ROOT_DETECTION_SCREEN_VALIDATION"],
    created_at: now,
  },
  {
    id: 702,
    audit: 1,
    rule_id: "CUSTOM-HARDCODED-SECRET",
    title: "Hardcoded secret",
    severity: "High",
    confidence: "HIGH",
    standard: "MASVS",
    category: "CRYPTO",
    description: "Static string evidence only.",
    dynamic_validation_playbooks: [],
    created_at: now,
  },
];

const correlation = {
  audit_id: 1,
  target_package: "owasp.sat.agoat",
  total_static_findings: 2,
  dynamically_testable_count: 1,
  recommended_count: 1,
  optional_count: 0,
  static_sufficient_count: 0,
  not_testable_count: 1,
  already_validated_count: 0,
  blocked_count: 0,
  needs_capability_count: 0,
  correlation_mode: "DETERMINISTIC_PLAYBOOK",
  model: "msap-demo-v1",
  capability_gaps: [],
  generated_at: now,
  candidates: [
    {
      finding_id: 701,
      finding_title: "Runtime root detection UI can be instrumented",
      severity: "Medium",
      confidence: "HIGH",
      rule_id: "SDK-ROOT-001",
      category: "MASVS-RESILIENCE",
      classification: "RECOMMENDED_DYNAMIC_VALIDATION",
      priority: 8,
      security_hypothesis:
        "Static analysis indicates runtime root-detection behavior that should be proven dynamically.",
      dynamic_validation_value:
        "Runtime validation can show whether the behavior is observable on the emulator.",
      recommended_poc_summary:
        "PoC: reset the approved demo state, launch the target app, execute the approved interaction, run the backend-owned Frida proof, capture before/after screenshots, capture the UI hierarchy, capture a bounded log excerpt.",
      likely_capabilities: ["frida_run_js", "take_screenshot", "dump_ui"],
      expected_evidence: ["Screenshot", "UI hierarchy", "Approved Frida event", "Tool output"],
      prerequisites: "Target app installed and Frida bridge ready.",
      limitations: "Lab-only and auditor-approved.",
      estimated_complexity: "medium",
      current_validation_status: "",
      missing_capabilities: [],
      start_poc_available: true,
    },
    {
      finding_id: 702,
      finding_title: "Hardcoded secret",
      severity: "High",
      confidence: "HIGH",
      rule_id: "CUSTOM-HARDCODED-SECRET",
      category: "CRYPTO",
      classification: "NOT_TESTABLE_WITH_CURRENT_CAPABILITIES",
      priority: 1,
      security_hypothesis: "Static-only evidence unless runtime exposure is observed.",
      dynamic_validation_value: "",
      recommended_poc_summary: "Static-only evidence unless runtime exposure is observed.",
      likely_capabilities: [],
      expected_evidence: [],
      prerequisites: "",
      limitations: "No supported runtime validation family maps to this static finding.",
      estimated_complexity: "low",
      current_validation_status: "",
      missing_capabilities: [],
      start_poc_available: false,
    },
  ],
};

function mission(status: string) {
  return {
    id: 801,
    audit: 1,
    apk: 10,
    finding: 701,
    finding_title: "Runtime root detection UI can be instrumented",
    finding_rule_id: "SDK-ROOT-001",
    finding_severity: "Medium",
    assessment_plan: 101,
    assessment_plan_status: "VALIDATED",
    agent_run: status === "RUNNING" || status === "INCONCLUSIVE" ? 202 : null,
    agent_run_status: status === "INCONCLUSIVE" ? "SUCCEEDED" : status === "RUNNING" ? "RUNNING" : null,
    dynamic_validation_result: status === "INCONCLUSIVE" ? 9 : null,
    dynamic_validation_result_status: status === "INCONCLUSIVE" ? "INCONCLUSIVE" : null,
    target_package: "owasp.sat.agoat",
    status,
    scenario_contract: {
      steps: [
        { sequence: 1, step_id: "launch", objective: "Launch the target app", expected_observation: "Target app foregrounded.", tools: [{ name: "launch_package" }] },
        { sequence: 2, step_id: "screenshot", objective: "Capture baseline screenshot", expected_observation: "Screenshot artifact created.", tools: [{ name: "take_screenshot" }] },
        { sequence: 3, step_id: "proof", objective: "Run approved Frida proof", expected_observation: "Controlled runtime events recorded.", tools: [{ name: "frida_run_js" }] },
      ],
      required_evidence_types: ["screenshot", "ui_hierarchy", "frida_events", "tool_output"],
    },
    scenario_hash: "f".repeat(64),
    mission_hash: "g".repeat(64),
    validation_family: "RUNTIME_TAMPERING_VALIDATION",
    playbook_id: "ROOT_DETECTION_SCREEN_VALIDATION",
    hypothesis: "The root detection control can be observed with bounded runtime evidence.",
    final_conclusion: "PoC evidence was collected; the deterministic oracle result was inconclusive and requires manual review.",
    limitations: "Lab-only and auditor-approved.",
    oracle_result: { result_contract: { result: "INCONCLUSIVE" } },
    provider: "DETERMINISTIC",
    model: "msap-demo-v1",
    provider_metadata: {},
    allowed_capabilities: ["reset_root_detection_demo", "launch_package", "tap_coordinates", "take_screenshot", "frida_run_js", "dump_ui"],
    budgets: {},
    evidence_ids: status === "INCONCLUSIVE" ? [901, 902] : [],
    evidence_count: status === "INCONCLUSIVE" ? 2 : 0,
    result_label: status === "INCONCLUSIVE" ? "Inconclusive" : status === "APPROVED" ? "Approved" : status === "VALIDATED" ? "Ready for approval" : "Running",
    result_explanation:
      "The PoC executed and collected evidence, but the deterministic oracle did not observe every signal required to confirm the finding.",
    scenario_summary: "6-step PoC using Reset approved demo state, Launch target app, Capture screenshot.",
    created_by: 1,
    approved_by: status === "VALIDATED" ? null : 1,
    approved_at: status === "VALIDATED" ? null : now,
    started_at: status === "VALIDATED" ? null : now,
    completed_at: status === "INCONCLUSIVE" ? now : null,
    created_at: now,
    updated_at: now,
  };
}

const timelineItems = [
  {
    sequence: 1,
    scenario_step_id: "launch",
    scenario_title: "Launch the target app",
    purpose: "",
    tool_name: "launch_package",
    friendly_action_label: "Launch target app",
    observation_summary: "The target app was launched and is foregrounded.",
    status: "SUCCEEDED",
    decision_summary: "",
    expected_observation: "Target app foregrounded.",
    observation: { launched: true },
    evidence_goal: ["tool_output"],
    troubleshooting: false,
    failure_message: "",
    created_at: now,
  },
  {
    sequence: 2,
    scenario_step_id: "screenshot",
    scenario_title: "Capture baseline screenshot",
    purpose: "",
    tool_name: "take_screenshot",
    friendly_action_label: "Capture screenshot",
    observation_summary: "Screenshot captured.",
    status: "SUCCEEDED",
    decision_summary: "",
    expected_observation: "Screenshot artifact created.",
    observation: { screenshot_created: true },
    evidence_goal: ["screenshot"],
    troubleshooting: false,
    failure_message: "",
    created_at: now,
  },
  {
    sequence: 3,
    scenario_step_id: "proof",
    scenario_title: "Run approved Frida proof",
    purpose: "",
    tool_name: "frida_run_js",
    friendly_action_label: "Run controlled instrumentation proof",
    observation_summary: "Approved Frida runtime proof executed.",
    status: "SUCCEEDED",
    decision_summary: "",
    expected_observation: "Controlled runtime events recorded.",
    observation: { event_count: 2 },
    evidence_goal: ["frida_events", "tool_output"],
    troubleshooting: false,
    failure_message: "",
    created_at: now,
  },
];

const missionEvidence = [
  {
    id: 901,
    audit: 1,
    finding: 701,
    indicator: null,
    storage_reference: null,
    agent_run: 202,
    agent_run_step: null,
    agent_run_artifact: null,
    evidence_type: "screenshot",
    source: "mission-agent",
    snippet: "Baseline screenshot captured",
    redacted: false,
    sha256: "1".repeat(64),
    provenance: {},
    created_at: now,
    evidence_title: "Screenshot",
    evidence_preview_type: "screenshot",
  },
  {
    id: 902,
    audit: 1,
    finding: 701,
    indicator: null,
    storage_reference: null,
    agent_run: 202,
    agent_run_step: null,
    agent_run_artifact: null,
    evidence_type: "logcat",
    source: "mission-agent",
    snippet: "target-correlated log lines (redacted)",
    redacted: true,
    sha256: "2".repeat(64),
    provenance: {},
    created_at: now,
    evidence_title: "Bounded log excerpt",
    evidence_preview_type: "logs",
  },
];

async function fulfillJson(route: Route, body: unknown, status = 200) {
  await route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });
}

async function installMockApi(page: Page) {
  let missionState = mission("VALIDATED");
  let missionPolls = 0;
  let fridaProposals: Array<Record<string, unknown>> = [];

  await page.route("http://127.0.0.1:8000/api/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const path = url.pathname.replace(/^\/api\//, "");
    const method = request.method();
    if (path === "auth/csrf/") return fulfillJson(route, { csrfToken: "test-csrf" });
    if (path === "auth/me/") return fulfillJson(route, { id: 1, username: "analyst", email: "", first_name: "Security", last_name: "Analyst", role: "ANALYST", is_staff: false, permissions: [] });
    if (path.startsWith("system/status/")) return fulfillJson(route, { overall_status: "OPERATIONAL", checked_at: now, components: [] });
    if (path === "audits/") return fulfillJson(route, audits);
    if (path === "apk-files/") return fulfillJson(route, apkFiles);
    if (path === "findings/") return fulfillJson(route, findings);
    if (path === "dynamic/host-agent/status/") return fulfillJson(route, { connected: true, enabled: true, code: "HOST_AGENT_CONNECTED", detail: "Ready", agent: { version: "1.0" }, device: { serial: "emulator-5554", state: "device", root_uid: 0, api_level: 35, android_version: "15", focused_app: "owasp.sat.agoat/.MainActivity" }, last_sync_at: now });
    if (path === "dynamic/host-agent/packages/") return fulfillJson(route, { packages: ["owasp.sat.agoat"], count: 1, truncated: false });
    if (path === "dynamic/agent/runtimes/") return fulfillJson(route, [{ id: 1, name: "Internal Controller", runtime_type: "INTERNAL_CONTROLLER", status: "AVAILABLE", description: "", capabilities: { tools: ["get_device_status", "launch_package", "dump_ui"] }, isolation_level: "INTERNAL_ONLY", enabled: true, configuration_enabled: true, available: true, last_seen_at: now, created_at: now, updated_at: now }]);
    if (path === "dynamic/playbooks/") return fulfillJson(route, { contract_version: "msap.dynamic-playbook-catalog/v1", items: [] });
    if (path === "dynamic/finding-validations/budget-status/") return fulfillJson(route, { scope: "GLOBAL", max_mission_generation_calls: 1, max_adaptive_decision_calls: 6, max_total_openai_calls: 7, mission_generation_call_count: 0, adaptive_decision_call_count: 0, current_openai_call_count: 0, remaining_total_calls: 7, provider_response_ids: [], budget_exhausted_reason: "", exhausted: false });
    if (path === "dynamic/static-dynamic-correlation/1/start/" && method === "POST") return fulfillJson(route, correlation);
    if (path === "dynamic/static-dynamic-correlation/1/capability-gaps/") return fulfillJson(route, {
      audit_id: 1,
      target_package: "owasp.sat.agoat",
      available_capabilities: ["frida_run_js", "take_screenshot", "dump_ui"],
      highest_value_missing_capabilities: [],
      generated_at: now,
    });
    if (path === "dynamic/static-dynamic-correlation/1/start-poc/" && method === "POST") {
      missionState = mission("VALIDATED");
      return fulfillJson(route, { mission: missionState, next_step: "approve" }, 201);
    }
    if (path === "dynamic/finding-validations/801/approve/" && method === "POST") {
      missionState = mission("APPROVED");
      return fulfillJson(route, missionState);
    }
    if (path === "dynamic/finding-validations/801/start/" && method === "POST") {
      missionState = mission("RUNNING");
      return fulfillJson(route, {
        mission: missionState,
        run: { id: 202, audit: 1, target_package: "owasp.sat.agoat", objective: "ASSESSMENT_PLAN_EXECUTION", execution_mode: "ADAPTIVE_AGENT", status: "RUNNING" },
        task_id: "task-1",
        execution_mode: "ADAPTIVE_AGENT",
      }, 202);
    }
    if (path === "dynamic/agent/runs/202/frida-script-proposals/" && method === "GET") {
      return fulfillJson(route, fridaProposals);
    }
    if (path === "dynamic/agent/runs/202/frida-script-proposals/" && method === "POST") {
      const proposal = {
        id: 501,
        run: 202,
        audit: 1,
        finding: 701,
        mission: 801,
        hypothesis: null,
        hypothesis_identifier: null,
        title: "Generated Frida observation probe",
        rationale: "Collect one bounded Java runtime event from the authorized target.",
        expected_evidence: ["Frida event emitted by the target process", "Script hash and bounded execution metadata"],
        source_identifier: "__MSAP_APPROVED_GENERATED_FRIDA_SCRIPT__:501:abcdabcdabcdabcd",
        source_sha256: `${"a".repeat(64)}`,
        source_code: "Java.perform(function () { try { send({type: 'generated_probe'}); } catch (e) { send({type: 'generated_probe_error', error: String(e)}); } });",
        source_size_bytes: 145,
        generator_provider: "OPENAI",
        generator_model: "gpt-5.6-luna",
        provider_metadata: {},
        validation_warnings: [],
        status: "GENERATED",
        created_by: 1,
        created_by_username: "analyst",
        approved_by: null,
        approved_by_username: null,
        approved_at: null,
        executed_at: null,
        last_error: "",
        suggested_fix: "",
        created_at: now,
        updated_at: now,
      };
      fridaProposals = [proposal];
      return fulfillJson(route, proposal, 201);
    }
    if (path === "dynamic/agent/runs/202/frida-script-proposals/501/approve/" && method === "POST") {
      fridaProposals = fridaProposals.map((proposal) => proposal.id === 501 ? {
        ...proposal,
        status: "APPROVED",
        approved_by: 1,
        approved_by_username: "analyst",
        approved_at: now,
      } : proposal);
      return fulfillJson(route, fridaProposals[0]);
    }
    if (path === "dynamic/agent/runs/202/frida-script-proposals/501/reject/" && method === "POST") {
      fridaProposals = fridaProposals.map((proposal) => proposal.id === 501 ? {
        ...proposal,
        status: "REJECTED",
      } : proposal);
      return fulfillJson(route, fridaProposals[0]);
    }
    if (path === "dynamic/agent/runs/202/resume-adaptive/" && method === "POST") {
      missionState = mission("RUNNING");
      return fulfillJson(route, {
        run: { id: 202, audit: 1, target_package: "owasp.sat.agoat", objective: "ASSESSMENT_PLAN_EXECUTION", execution_mode: "ADAPTIVE_AGENT", status: "QUEUED" },
        task_id: "resume-task-1",
        execution_mode: "ADAPTIVE_AGENT",
      }, 202);
    }
    if (path === "dynamic/finding-validations/801/" && method === "GET") {
      missionPolls += 1;
      missionState = missionPolls >= 4 ? mission("INCONCLUSIVE") : mission("RUNNING");
      return fulfillJson(route, missionState);
    }
    if (path === "dynamic/finding-validations/801/timeline/") {
      missionState = missionPolls >= 4 ? mission("INCONCLUSIVE") : mission("RUNNING");
      return fulfillJson(route, { mission_id: 801, finding_id: 701, agent_run_id: 202, status: missionState.status, items: timelineItems });
    }
    if (path === "dynamic/finding-validations/801/evidence/") {
      missionState = missionPolls >= 4 ? mission("INCONCLUSIVE") : mission("RUNNING");
      return fulfillJson(route, missionPolls >= 4 ? missionEvidence : missionEvidence.slice(0, 1));
    }
    if (path === "audits/1/report/pdf/") {
      const pdf = Buffer.from("%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF", "utf8");
      return route.fulfill({
        status: 200,
        contentType: "application/pdf",
        headers: { "Content-Disposition": 'attachment; filename="MSAP_Audit_1_Security_Report.pdf"' },
        body: pdf,
      });
    }
    return fulfillJson(route, []);
  });
}

async function selectDemoAudit(page: Page) {
  await page.getByLabel("Audit").selectOption("1");
  await expect(page.getByRole("button", { name: "Start Static → Dynamic Correlation" })).toBeEnabled();
}

test("Dynamic Lab opens the simple SaaS flow with one obvious starting action", async ({ page }) => {
  await installMockApi(page);
  await page.goto("/dynamic");
  await selectDemoAudit(page);
  await expect(page.getByRole("heading", { name: "MSAP Dynamic Validation" })).toBeVisible();
  await expect(page.getByText("Turn static findings into evidence-backed dynamic PoCs.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Start Static → Dynamic Correlation" })).toBeVisible();
  await expect(page.getByText("Lab ready")).toBeVisible();
  await expect(page.getByText("owasp.sat.agoat", { exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: "Advanced Operator Console" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Lab readiness", exact: true })).toHaveCount(0);
});

test("correlation renders candidate cards; Start PoC only for testable candidates", async ({ page }) => {
  await installMockApi(page);
  await page.goto("/dynamic");
  await selectDemoAudit(page);
  await page.getByRole("button", { name: "Start Static → Dynamic Correlation" }).click();
  await expect(page.getByRole("heading", { name: "Correlation results" })).toBeVisible();
  await expect(page.getByText("2 correlated static findings")).toBeVisible();
  const testable = page.locator(".dynamic-candidate-card", { hasText: "Runtime root detection UI can be instrumented" });
  await expect(testable.getByRole("button", { name: "Start PoC" })).toBeVisible();
  await page.getByRole("button", { name: "Not testable" }).click();
  const notTestable = page.locator(".dynamic-candidate-card", { hasText: "Hardcoded secret" });
  await expect(notTestable.getByText("No PoC available")).toBeVisible();
  await expect(notTestable.getByRole("button", { name: "Start PoC" })).toHaveCount(0);
});

test("Start PoC -> review, approval and run are separate steps with human summaries and no raw JSON", async ({ page }) => {
  await installMockApi(page);
  await page.goto("/dynamic");
  await selectDemoAudit(page);
  await page.getByRole("button", { name: "Start Static → Dynamic Correlation" }).click();
  await page.locator(".dynamic-candidate-card").first().getByRole("button", { name: "Start PoC" }).click();

  await expect(page.getByRole("heading", { name: "Step 3 · Review the PoC" })).toBeVisible();
  await expect(page.getByText("The root detection control can be observed with bounded runtime evidence.")).toBeVisible();
  await expect(page.getByText("Launch the target app")).toBeVisible();
  await expect(page.getByRole("button", { name: "Approve PoC" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Run PoC" })).toHaveCount(0);
  await expect(page.locator("pre")).toHaveCount(0);
  await expect(page.getByText("scenario_contract", { exact: true })).toHaveCount(0);

  await page.getByRole("button", { name: "Approve PoC" }).click();
  await expect(page.getByRole("button", { name: "Run PoC" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Approve PoC" })).toHaveCount(0);

  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "Run PoC" }).click();
  await expect(page.getByText("Validating: Runtime root detection UI can be instrumented")).toBeVisible();
  await expect(page.getByText("The target app was launched and is foregrounded.")).toBeVisible();
  await expect(page.getByText("Screenshot captured.")).toBeVisible();
  await expect(page.getByText("Approved Frida runtime proof executed.")).toBeVisible();
  await expect(page.locator("pre")).toHaveCount(0);

  await expect(page.getByRole("heading", { name: "Dynamic validation result" })).toBeVisible({ timeout: 10_000 });
  await expect(page.getByText("Inconclusive", { exact: true })).toBeVisible();
  await expect(page.getByText("The PoC executed and collected evidence, but the deterministic oracle did not observe every signal required to confirm the finding.")).toBeVisible();
  await expect(page.getByText("Evidence collected: 2 records")).toBeVisible();
  await expect(page.getByRole("button", { name: "Validate another finding" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Download Validation Report" })).toBeVisible();
  await page.getByRole("button", { name: "Download Validation Report" }).click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toContain("MSAP_Audit_1_Security_Report.pdf");
});

test("evidence panel hides raw content behind expandable cards", async ({ page }) => {
  await installMockApi(page);
  await page.goto("/dynamic");
  await selectDemoAudit(page);
  await page.getByRole("button", { name: "Start Static → Dynamic Correlation" }).click();
  await page.locator(".dynamic-candidate-card").first().getByRole("button", { name: "Start PoC" }).click();
  await page.getByRole("button", { name: "Approve PoC" }).click();
  await page.getByRole("button", { name: "Run PoC" }).click();

  await expect(page.getByRole("heading", { name: "Evidence collected" })).toBeVisible({ timeout: 10_000 });
  await expect(page.getByText("Baseline screenshot captured")).toBeVisible();
  await expect(page.getByText("Raw evidence JSON")).toHaveCount(0);
  await expect(page.getByText("target-correlated log lines (redacted)")).not.toBeVisible();
});

test("Frida generated script proposal is reviewed and approved separately", async ({ page }) => {
  await installMockApi(page);
  await page.goto("/dynamic");
  await selectDemoAudit(page);
  await page.getByRole("button", { name: "Start Static → Dynamic Correlation" }).click();
  await page.locator(".dynamic-candidate-card").first().getByRole("button", { name: "Start PoC" }).click();
  await page.getByRole("button", { name: "Approve PoC" }).click();
  await page.getByRole("button", { name: "Run PoC" }).click();

  await expect(page.getByRole("heading", { name: "Frida instrumentation approval" })).toBeVisible();
  await expect(page.getByText("No generated Frida script proposal yet")).toBeVisible();
  await page.getByRole("button", { name: "Generate Frida Script" }).click();
  await expect(page.getByText("Generated Frida observation probe")).toBeVisible();
  await expect(page.getByText("Collect one bounded Java runtime event from the authorized target.")).toBeVisible();
  await expect(page.getByText("gpt-5.6-luna")).toBeVisible();
  await expect(page.getByText("Java.perform")).not.toBeVisible();
  await page.getByText("Review script before approval").click();
  await expect(page.getByText("Java.perform")).toBeVisible();
  await page.getByRole("button", { name: "Approve Script Hook" }).click();
  await expect(page.getByText("Frida script approved. Resume the agent when you are ready.")).toBeVisible();
  await expect(page.getByText("Approved script")).toBeVisible();
});

test("advanced operator console is a separate route, not shown on the main page", async ({ page }) => {
  await installMockApi(page);
  await page.goto("/dynamic");
  await selectDemoAudit(page);
  await expect(page.getByRole("heading", { name: "Advanced Operator Console" })).toHaveCount(0);
  await expect(page.locator("pre")).toHaveCount(0);
  await expect(page.getByText("AI budget 7/7", { exact: true })).toBeVisible();
  await page.goto("/dynamic/advanced");
  await expect(page.getByRole("heading", { name: "Advanced Operator Console" })).toBeVisible();
  await page.getByRole("link", { name: "Back to Dynamic Lab" }).click();
  await expect(page.getByRole("heading", { name: "MSAP Dynamic Validation" })).toBeVisible();
});
