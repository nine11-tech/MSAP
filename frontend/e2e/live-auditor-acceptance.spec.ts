import { expect, test, type Page } from "@playwright/test";
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";

const liveEnabled = process.env.MSAP_LIVE_ACCEPTANCE === "1";
const preflightOnly = process.env.MSAP_LIVE_PREFLIGHT_ONLY === "1";
const inspectExisting = process.env.MSAP_LIVE_INSPECT_EXISTING === "1";
const retryRunId = Number(process.env.MSAP_LIVE_RETRY_RUN_ID || 0);
const username = process.env.MSAP_E2E_USERNAME || "";
const password = process.env.MSAP_E2E_PASSWORD || "";
const apiBase = process.env.MSAP_E2E_API_BASE_URL || "http://127.0.0.1:8000/api";
const evidenceDirectory = path.resolve(
  process.cwd(),
  process.env.MSAP_E2E_EVIDENCE_DIR || "../.runtime/msap-demo/browser-acceptance",
);

type JsonRecord = Record<string, unknown>;

async function browserApiGet(page: Page, endpoint: string): Promise<JsonRecord | JsonRecord[]> {
  return page.evaluate(
    async ({ url }) => {
      const response = await fetch(url, { credentials: "include" });
      if (!response.ok) throw new Error(`GET ${url} returned ${response.status}`);
      return response.json();
    },
    { url: `${apiBase}/${endpoint}` },
  );
}

async function capture(page: Page, name: string) {
  await page.screenshot({
    path: path.join(evidenceDirectory, name),
    fullPage: true,
  });
}

async function waitForDecisionCountOrTerminal(page: Page, runId: number, expectedCount: number) {
  const deadline = Date.now() + 3 * 60_000;
  while (Date.now() < deadline) {
    const [decisions, run] = await Promise.all([
      browserApiGet(page, `dynamic/agent/runs/${runId}/decisions/`) as Promise<JsonRecord[]>,
      browserApiGet(page, `dynamic/agent/runs/${runId}/`) as Promise<JsonRecord>,
    ]);
    if (decisions.length >= expectedCount) return;
    if (["SUCCEEDED", "FAILED", "TIMEOUT", "PAUSED", "CANCELLED"].includes(String(run.status))) {
      throw new Error(
        `AgentRun ${runId} reached ${String(run.status)} after ${decisions.length} decision(s): ${String(run.termination_reason || "controlled termination")}`,
      );
    }
    await page.waitForTimeout(1_000);
  }
  throw new Error(`AgentRun ${runId} did not produce ${expectedCount} decisions within the bounded wait.`);
}

function safeUsage(metadata: unknown) {
  const value = (metadata || {}) as JsonRecord;
  return {
    response_id: value.response_id || null,
    input_tokens: value.input_tokens ?? null,
    cached_input_tokens: value.cached_input_tokens ?? null,
    output_tokens: value.output_tokens ?? null,
    reasoning_tokens: value.reasoning_tokens ?? null,
    total_tokens: value.total_tokens ?? null,
    latency_ms: value.latency_ms ?? null,
    retry_count: value.retry_count ?? null,
  };
}

test.skip(!liveEnabled, "Set MSAP_LIVE_ACCEPTANCE=1 for the explicit real-service run.");

test("real auditor workflow uses Luna, the adaptive agent, Android evidence, findings, and report", async ({ page }) => {
  test.setTimeout(8 * 60_000);
  expect(username, "MSAP_E2E_USERNAME is required").not.toBe("");
  expect(password, "MSAP_E2E_PASSWORD is required").not.toBe("");
  mkdirSync(evidenceDirectory, { recursive: true });

  await page.goto("/dynamic");
  const loginHeading = page.getByRole("heading", { name: "Secure assessment workspace" });
  const assessmentHeading = page.getByRole("heading", { name: "Dynamic Security Assessment" });
  await expect(loginHeading.or(assessmentHeading)).toBeVisible();
  if (await loginHeading.isVisible()) {
    await page.getByLabel("Username").fill(username);
    await page.locator("#password").fill(password);
    await page.getByRole("button", { name: "Sign in securely" }).click();
  }
  await expect(assessmentHeading).toBeVisible();

  if (inspectExisting) {
    await expect(
      page.getByText("AI assessment reasoning could not continue.")
        .or(page.getByText("The AI assessment decision did not pass the authorized security checks.")),
    ).toBeVisible();
    await capture(page, "09-controlled-agent-failure.png");
    await page.getByRole("heading", { name: "Live evidence" }).scrollIntoViewIfNeeded();
    await capture(page, "10-controlled-empty-evidence.png");
    const reportLink = page.getByRole("link", { name: "View Assessment Report" }).first();
    if (await reportLink.isVisible().catch(() => false)) {
      await reportLink.click();
      await expect(page.getByRole("button", { name: "Download PDF Report" })).toBeVisible();
      await capture(page, "11-controlled-assessment-report.png");
    }
    return;
  }

  let plan: JsonRecord;
  let runId: number;

  if (retryRunId) {
    const sourceRun = (await browserApiGet(
      page,
      `dynamic/agent/runs/${retryRunId}/`,
    )) as JsonRecord;
    expect(sourceRun.status).toBe("FAILED");
    expect(sourceRun.pre_execution_failure).toBe(true);
    expect(sourceRun.adaptive_retryable).toBe(true);
    expect(sourceRun.tool_call_count).toBe(0);
    expect(sourceRun.execution_mode).toBe("ADAPTIVE_AGENT");
    expect(sourceRun.decision_provider).toBe("OPENAI");
    expect(sourceRun.decision_model).toBe("gpt-5.6-luna");
    plan = (await browserApiGet(
      page,
      `dynamic/agent/plans/${Number(sourceRun.assessment_plan)}/`,
    )) as JsonRecord;
    expect(Number(plan.id)).toBe(Number(sourceRun.assessment_plan));
    expect(plan.planner_provider).toBe("OPENAI");
    expect(plan.planner_model).toBe("gpt-5.6-luna");
    expect(plan.validation_status).toBe("PASSED");
    expect(plan.policy_status).toBe("PASSED");
    expect(plan.target_package).toBe("owasp.sat.agoat");

    await expect(
      page.getByText("AI assessment could not start. No Android actions were executed."),
    ).toBeVisible();
    await capture(page, "01-retryable-pre-execution-failure.png");
    const retryButton = page.getByRole("button", { name: "Retry Adaptive Assessment" });
    await expect(retryButton).toBeVisible();
    await retryButton.scrollIntoViewIfNeeded();
    await capture(page, "02-retry-button.png");
    if (preflightOnly) return;

    const retryResponsePromise = page.waitForResponse(
      (response) => response.request().method() === "POST"
        && response.url().endsWith(`/api/dynamic/agent/runs/${retryRunId}/retry-adaptive/`),
    );
    await retryButton.click();
    const retryResponse = await retryResponsePromise;
    const retryPayload = (await retryResponse.json()) as {
      run: JsonRecord;
      retry_of_agent_run_id: number;
      code?: string;
      detail?: string;
    };
    expect(
      retryResponse.ok(),
      `${retryPayload.code || retryResponse.status()}: ${retryPayload.detail || "Retry request failed"}`,
    ).toBeTruthy();
    expect(retryPayload.retry_of_agent_run_id).toBe(retryRunId);
    runId = Number(retryPayload.run.id);
    expect(runId).not.toBe(retryRunId);
    expect(retryPayload.run.execution_mode).toBe("ADAPTIVE_AGENT");
    expect(retryPayload.run.decision_provider).toBe("OPENAI");
    expect(retryPayload.run.decision_model).toBe("gpt-5.6-luna");
  } else {

  for (const label of ["Start New Assessment", "Cancel Review", "New Assessment"]) {
    const button = page.getByRole("button", { name: label }).first();
    if (await button.isVisible().catch(() => false)) {
      await button.click();
      break;
    }
  }
  await expect(page.getByRole("heading", { name: "Configure Security Assessment" })).toBeVisible();
  await expect(page.getByText("Android lab ready")).toBeVisible();

  const auditSelect = page.getByLabel("Audit");
  const auditOptions = await auditSelect.locator("option").allTextContents();
  const preferredAudit = auditOptions.find((value) => /AndroGoat/i.test(value));
  if (preferredAudit) await auditSelect.selectOption({ label: preferredAudit });
  const targetSelect = page.getByLabel("Target application");
  await expect(targetSelect).toContainText("owasp.sat.agoat");
  const targetOptions = await targetSelect.locator("option").allTextContents();
  const authorizedTarget = targetOptions.find((value) => value.includes("owasp.sat.agoat"));
  expect(authorizedTarget, "The audit-authorized AndroGoat target is required").toBeTruthy();
  await targetSelect.selectOption({ label: authorizedTarget! });
  await expect(page.getByText("Standard Dynamic Assessment", { exact: true })).toBeVisible();
  if (await page.getByText("Not detected", { exact: true }).isVisible().catch(() => false)) {
    await page.getByText("Manual Controls", { exact: true }).click();
    await page.getByRole("button", { name: "Install", exact: true }).click();
  }
  await expect(page.getByText("Installed", { exact: true })).toBeVisible();
  await capture(page, "01-target-setup.png");

  await page.getByText("Advanced AI Settings").click();
  await expect(page.locator(".advanced-ai-settings select").first()).toHaveValue("ECONOMY");
  await expect(page.locator(".auditor-primary-action strong")).toContainText("GPT-5.6 Luna");
  await page.getByText("Advanced AI Settings").click();
  if (preflightOnly) return;

  const planResponsePromise = page.waitForResponse(
    (response) => response.request().method() === "POST" && /\/api\/dynamic\/agent\/plans\/$/.test(response.url()),
  );
  await page.getByRole("button", { name: "Generate AI Assessment" }).click();
  const planResponse = await planResponsePromise;
  expect(planResponse.ok()).toBeTruthy();
  plan = (await planResponse.json()) as JsonRecord;
  expect(plan.planner_provider).toBe("OPENAI");
  expect(plan.planner_model).toBe("gpt-5.6-luna");
  expect(plan.validation_status).toBe("PASSED");
  expect(plan.policy_status).toBe("PASSED");
  expect(plan.target_package).toBe("owasp.sat.agoat");
  await expect(page.getByRole("heading", { name: "AI Assessment Plan" })).toBeVisible();
  await expect(page.getByText("Security checks passed", { exact: true })).toBeVisible();
  await capture(page, "02-ai-plan-review.png");

  await page.getByRole("button", { name: "Review & Continue" }).click();
  await expect(page.getByRole("heading", { name: "Assessment Ready for Approval" })).toBeVisible();
  await expect(page.getByText("Destructive actions")).toBeVisible();
  await expect(page.getByText("Not permitted", { exact: true })).toBeVisible();
  await capture(page, "03-approval-boundary.png");

  await page.getByRole("button", { name: "Approve Assessment" }).click();
  await expect(page.getByRole("button", { name: "Start Security Assessment" })).toBeVisible();
  await capture(page, "03b-approved-assessment.png");

  const executeResponsePromise = page.waitForResponse(
    (response) => response.request().method() === "POST" && /\/execute-adaptive\/$/.test(response.url()),
  );
  await page.getByRole("button", { name: "Start Security Assessment" }).click();
  const executeResponse = await executeResponsePromise;
  expect(executeResponse.ok()).toBeTruthy();
  const executePayload = (await executeResponse.json()) as { run: JsonRecord };
  runId = Number(executePayload.run.id);
  expect(executePayload.run.execution_mode).toBe("ADAPTIVE_AGENT");
  expect(executePayload.run.decision_provider).toBe("OPENAI");
  expect(executePayload.run.decision_model).toBe("gpt-5.6-luna");
  }

  await waitForDecisionCountOrTerminal(page, runId, 1);
  await expect(page.locator(".agent-activity-card").first()).toBeVisible({ timeout: 20_000 });
  await capture(page, "04-live-agent-decision-1.png");

  await waitForDecisionCountOrTerminal(page, runId, 2);
  await expect(page.locator(".agent-activity-card").nth(1)).toBeVisible({ timeout: 20_000 });
  await capture(page, "05-live-agent-decision-2.png");

  await expect(page.getByRole("heading", { name: "Live evidence" })).toBeVisible();
  await page.getByRole("heading", { name: "Live evidence" }).scrollIntoViewIfNeeded();
  await capture(page, "06-live-evidence.png");

  let terminalRun: JsonRecord = {};
  await expect.poll(async () => {
    terminalRun = (await browserApiGet(page, `dynamic/agent/runs/${runId}/`)) as JsonRecord;
    return String(terminalRun.status || "");
  }, { timeout: 5 * 60_000 }).toMatch(/^(SUCCEEDED|FAILED|TIMEOUT|PAUSED|CANCELLED)$/);

  const decisions = (await browserApiGet(page, `dynamic/agent/runs/${runId}/decisions/`)) as JsonRecord[];
  const steps = (await browserApiGet(page, `dynamic/agent/runs/${runId}/steps/`)) as JsonRecord[];
  const evidence = (await browserApiGet(page, `dynamic/agent/runs/${runId}/evidence/`)) as JsonRecord[];
  const artifacts = (await browserApiGet(page, `dynamic/agent/runs/${runId}/artifacts/`)) as JsonRecord[];
  const hypotheses = (await browserApiGet(page, `dynamic/agent/runs/${runId}/hypotheses/`)) as JsonRecord[];
  const summary = (await browserApiGet(page, `dynamic/agent/runs/${runId}/assessment-summary/`)) as JsonRecord;

  writeFileSync(
    path.join(evidenceDirectory, "acceptance-result.json"),
    JSON.stringify({
      captured_at: new Date().toISOString(),
      plan: {
        id: plan.id,
        hash: plan.plan_hash,
        provider: plan.planner_provider,
        model: plan.planner_model,
        validation: plan.validation_status,
        policy: plan.policy_status,
        target: plan.target_package,
        usage: safeUsage(plan.provider_metadata),
      },
      run: {
        id: runId,
        retry_of_agent_run_id: retryRunId || null,
        status: terminalRun.status,
        execution_mode: terminalRun.execution_mode,
        provider: terminalRun.decision_provider,
        model: terminalRun.decision_model,
        termination_reason: terminalRun.termination_reason,
        decision_count: terminalRun.decision_count,
        tool_call_count: terminalRun.tool_call_count,
      },
      decisions: decisions.map((decision, index) => ({
        sequence: decision.sequence,
        hypothesis: decision.hypothesis_identifier,
        decision_type: decision.decision_type,
        tool: decision.tool_name,
        rationale: decision.rationale_summary,
        input_hash: decision.decision_input_hash,
        previous_observation_hash: index ? decisions[index - 1].observation_hash : null,
        observation_hash: decision.observation_hash,
        validation: decision.validation_status,
        policy: decision.policy_status,
        execution: decision.execution_status,
        usage: safeUsage(decision.provider_metadata),
      })),
      steps: steps.map((step) => ({
        sequence: step.sequence_number,
        tool: step.tool_name,
        status: step.status,
        output_summary: step.output_summary,
      })),
      evidence: evidence.map((item) => ({ id: item.id, type: item.evidence_type, sha256: item.sha256, source: item.source })),
      artifacts: artifacts.map((item) => ({ id: item.id, type: item.artifact_type, name: item.name, sha256: item.sha256 })),
      hypotheses: hypotheses.map((item) => ({ id: item.hypothesis_id, status: item.status, oracle_result: item.oracle_result })),
      results: {
        finding_count: summary.run_finding_count,
        findings: summary.run_findings,
        risk: summary.risk,
        compliance: summary.compliance,
        report: summary.report,
      },
    }, null, 2),
  );

  expect(terminalRun.status).toBe("SUCCEEDED");
  expect(decisions.length).toBeGreaterThanOrEqual(2);
  expect(decisions.length).toBeLessThanOrEqual(4);
  expect(decisions[0].decision_input_hash).not.toBe(decisions[1].decision_input_hash);
  expect(decisions[0].observation_hash).toBeTruthy();
  expect(steps.filter((step) => step.status === "SUCCEEDED").length).toBeGreaterThanOrEqual(2);
  expect(evidence.length).toBeGreaterThan(0);

  await expect(page.getByRole("heading", { name: "Assessment completed" })).toBeVisible({ timeout: 30_000 });
  await expect(page.getByRole("heading", { name: "Assessment results" })).toBeVisible();
  await capture(page, "07-final-results.png");

  const findingsLink = page.getByRole("link", { name: "View Findings" });
  await findingsLink.click();
  await expect(page.getByRole("heading", { name: "Security findings" })).toBeVisible();
  await page.goBack();
  await expect(page.getByRole("heading", { name: "Assessment completed" })).toBeVisible();
  await page.getByRole("link", { name: "View Assessment Report" }).first().click();
  await expect(page.getByRole("button", { name: "Download PDF Report" })).toBeVisible();
  await expect(page.getByText("Approved dynamic assessments", { exact: false })).toBeVisible();
  await capture(page, "08-assessment-report.png");
});
