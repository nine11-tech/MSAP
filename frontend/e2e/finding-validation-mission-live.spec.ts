import { expect, test, type Page } from "@playwright/test";
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";

const liveEnabled = process.env.MSAP_LIVE_ACCEPTANCE === "1";
const username = process.env.MSAP_E2E_USERNAME || "";
const password = process.env.MSAP_E2E_PASSWORD || "";
const apiBase = process.env.MSAP_E2E_API_BASE_URL || "http://localhost:8000/api";
const auditId = process.env.MSAP_E2E_AUDIT_ID || "4";
const existingMissionId = process.env.MSAP_E2E_EXISTING_MISSION_ID || "";
const existingRunId = process.env.MSAP_E2E_EXISTING_RUN_ID || "";
const evidenceDirectory = path.resolve(
  process.cwd(),
  process.env.MSAP_E2E_EVIDENCE_DIR || "../.runtime/msap-demo/browser-acceptance",
);

type JsonRecord = Record<string, unknown>;

async function browserApiGet(page: Page, endpoint: string): Promise<JsonRecord | JsonRecord[]> {
  return page.evaluate(
    async ({ url }) => {
      const response = await fetch(url, { credentials: "include" });
      if (!response.ok) throw new Error(`GET ${url} returned ${response.status}: ${await response.text()}`);
      return response.json();
    },
    { url: `${apiBase}/${endpoint}` },
  );
}

async function browserApiPost(page: Page, endpoint: string, body: JsonRecord = {}): Promise<JsonRecord> {
  return page.evaluate(
    async ({ url, payload }) => {
      const csrfResponse = await fetch(`${url.origin}/api/auth/csrf/`, { credentials: "include" });
      if (!csrfResponse.ok) throw new Error(`CSRF returned ${csrfResponse.status}: ${await csrfResponse.text()}`);
      const csrf = await csrfResponse.json();
      const response = await fetch(`${url.origin}/api/${url.endpoint}`, {
        method: "POST",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": String(csrf.csrfToken || ""),
        },
        body: JSON.stringify(payload),
      });
      if (!response.ok) throw new Error(`POST ${url.endpoint} returned ${response.status}: ${await response.text()}`);
      return response.json();
    },
    {
      url: {
        origin: new URL(apiBase).origin,
        endpoint,
      },
      payload: body,
    },
  );
}

async function capture(page: Page, name: string) {
  await page.screenshot({ path: path.join(evidenceDirectory, name), fullPage: true });
}

async function waitForMissionTerminal(page: Page, missionId: number) {
  const terminal = new Set([
    "CONFIRMED",
    "NOT_REPRODUCED",
    "INCONCLUSIVE",
    "BLOCKED",
    "NOT_DYNAMICALLY_TESTABLE",
    "FAILED",
  ]);
  let mission: JsonRecord = {};
  const deadline = Date.now() + 5 * 60_000;
  while (Date.now() < deadline) {
    mission = (await browserApiGet(page, `dynamic/finding-validations/${missionId}/`)) as JsonRecord;
    if (terminal.has(String(mission.status || ""))) return mission;
    await page.waitForTimeout(2_000);
  }
  expect(String(mission.status || ""), `Mission ${missionId} did not reach a terminal status`).toBe("TERMINAL");
  return mission;
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
    provider_request_sent: value.provider_request_sent ?? null,
  };
}

test.skip(!liveEnabled, "Set MSAP_LIVE_ACCEPTANCE=1 for the explicit real-service mission run.");

test("real static finding becomes approved mission, agent execution, evidence, and validation result", async ({ page }) => {
  test.setTimeout(8 * 60_000);
  expect(username, "MSAP_E2E_USERNAME is required").not.toBe("");
  expect(password, "MSAP_E2E_PASSWORD is required").not.toBe("");
  mkdirSync(evidenceDirectory, { recursive: true });

  await page.goto(`/dynamic/advanced?audit=${auditId}`);
  const loginHeading = page.getByRole("heading", { name: "Secure assessment workspace" });
  const dynamicHeading = page.getByRole("heading", { name: "Advanced Operator Console" });
  await expect(loginHeading.or(dynamicHeading)).toBeVisible();
  if (await loginHeading.isVisible()) {
    await page.getByLabel("Username").fill(username);
    await page.locator("#password").fill(password);
    await page.getByRole("button", { name: "Sign in securely" }).click();
  }
  await expect(dynamicHeading).toBeVisible();
  await expect(page.getByRole("heading", { name: "Finding-Driven Dynamic Validation" })).toBeVisible();

  const findings = (await browserApiGet(page, `findings/?audit=${auditId}`)) as JsonRecord[];
  const selectedFinding = findings.find((finding) => {
    const playbooks = Array.isArray(finding.dynamic_validation_playbooks)
      ? finding.dynamic_validation_playbooks as unknown[]
      : [];
    return playbooks.includes("ROOT_DETECTION_SCREEN_VALIDATION")
      || playbooks.includes("DEBUGGABLE_APP_VERIFICATION")
      || playbooks.includes("ROOT_DETECTION_LAB_BYPASS");
  });
  expect(selectedFinding, "A supported AndroGoat static finding is required").toBeTruthy();

  await page.goto(`/dynamic/advanced?audit=${auditId}&finding=${String(selectedFinding!.id)}`);
  await expect(page.getByRole("heading", { name: "Finding-Driven Dynamic Validation" })).toBeVisible();
  await expect(page.getByRole("button", { name: /Validate Dynamically|Validate Again|Generate Validation Mission/ }).first()).toBeVisible({ timeout: 30_000 });
  await capture(page, "fv-01-static-findings.png");

  let missionId = Number(existingMissionId || 0);
  let runId = Number(existingRunId || 0);
  if (!missionId) {
    const generateButton = page.getByRole("button", { name: /Validate Dynamically|Validate Again|Generate Validation Mission/ }).first();
    const missionResponsePromise = page.waitForResponse(
      (response) => response.request().method() === "POST" && /\/dynamic-validation\/generate\/$/.test(response.url()),
      { timeout: 90_000 },
    );
    await generateButton.click();
    const missionResponse = await missionResponsePromise;
    expect(missionResponse.ok(), `${missionResponse.status()}: ${await missionResponse.text()}`).toBeTruthy();
    const generatedMission = (await missionResponse.json()) as JsonRecord;
    missionId = Number(generatedMission.id);
    expect(missionId).toBeGreaterThan(0);
    expect(generatedMission.status).toBe("VALIDATED");
    expect(generatedMission.provider).toBe("OPENAI");
    expect(generatedMission.model).toBe("gpt-5.6-luna");

    await expect(page.getByRole("button", { name: "Approve Validation Mission" })).toBeVisible({ timeout: 30_000 });
    await expect(page.getByText("Shell, ADB shell, host filesystem", { exact: false })).toBeVisible();
    await capture(page, "fv-02-mission-review.png");

    const approveResponsePromise = page.waitForResponse(
      (response) => response.request().method() === "POST" && response.url().endsWith(`/api/dynamic/finding-validations/${missionId}/approve/`),
    );
    await page.getByRole("button", { name: "Approve Validation Mission" }).click();
    const approveResponse = await approveResponsePromise;
    expect(approveResponse.ok(), `${approveResponse.status()}: ${await approveResponse.text()}`).toBeTruthy();
    await expect(page.getByRole("button", { name: "Start Dynamic Validation" })).toBeVisible({ timeout: 30_000 });
    await capture(page, "fv-03-approval-boundary.png");

    const startResponsePromise = page.waitForResponse(
      (response) => response.request().method() === "POST" && response.url().endsWith(`/api/dynamic/finding-validations/${missionId}/start/`),
    );
    await page.getByRole("button", { name: "Start Dynamic Validation" }).click();
    const startResponse = await startResponsePromise;
    expect(startResponse.ok(), `${startResponse.status()}: ${await startResponse.text()}`).toBeTruthy();
    const startPayload = (await startResponse.json()) as { run: JsonRecord; mission: JsonRecord };
    runId = Number(startPayload.run.id);
    expect(runId).toBeGreaterThan(0);
    expect(startPayload.run.execution_mode).toBe("ADAPTIVE_AGENT");
    await capture(page, "fv-04-live-poc-started.png");
  } else {
    let mission = (await browserApiGet(page, `dynamic/finding-validations/${missionId}/`)) as JsonRecord;
    expect(mission.provider).toBe("OPENAI");
    expect(mission.model).toBe("gpt-5.6-luna");
    if (!runId && mission.status === "VALIDATED") {
      mission = await browserApiPost(page, `dynamic/finding-validations/${missionId}/approve/`);
      expect(mission.status).toBe("APPROVED");
    }
    if (!runId && mission.status === "APPROVED") {
      const started = await browserApiPost(page, `dynamic/finding-validations/${missionId}/start/`) as { run: JsonRecord; mission: JsonRecord };
      mission = started.mission;
      runId = Number(started.run.id);
      expect(started.run.execution_mode).toBe("ADAPTIVE_AGENT");
    }
    runId = runId || Number(mission.agent_run);
    expect(runId).toBeGreaterThan(0);
    await capture(page, "fv-02-existing-mission.png");
  }

  await expect.poll(async () => {
    const timeline = (await browserApiGet(page, `dynamic/finding-validations/${missionId}/timeline/`)) as JsonRecord;
    return Array.isArray(timeline.items) ? timeline.items.length : 0;
  }, { timeout: 3 * 60_000 }).toBeGreaterThanOrEqual(2);
  await expect(page.locator(".mission-timeline .agent-activity-card").first()).toBeVisible({ timeout: 30_000 });
  await capture(page, "fv-05-live-poc-timeline.png");

  const terminalMission = await waitForMissionTerminal(page, missionId);
  const evidence = (await browserApiGet(page, `dynamic/finding-validations/${missionId}/evidence/`)) as JsonRecord[];
  const timeline = (await browserApiGet(page, `dynamic/finding-validations/${missionId}/timeline/`)) as JsonRecord;
  const run = (await browserApiGet(page, `dynamic/agent/runs/${runId}/`)) as JsonRecord;
  const steps = (await browserApiGet(page, `dynamic/agent/runs/${runId}/steps/`)) as JsonRecord[];
  const missionResult = terminalMission.dynamic_validation_result
    ? (await browserApiGet(
        page,
        `dynamic/validation-results/${Number(terminalMission.dynamic_validation_result)}/`,
      )) as JsonRecord
    : ((await browserApiGet(page, `dynamic/validation-results/?audit=${auditId}`)) as JsonRecord[])
        .find((item) => Number(item.agent_run) === runId && Number(item.finding) === Number(selectedFinding!.id));

  expect(run.status).toBe("SUCCEEDED");
  expect(steps.filter((step) => step.status === "SUCCEEDED").length).toBeGreaterThanOrEqual(2);
  expect(evidence.length).toBeGreaterThan(0);
  expect(terminalMission.dynamic_validation_result).toBeTruthy();
  expect(missionResult).toBeTruthy();
  expect(["CONFIRMED", "INCONCLUSIVE", "NOT_REPRODUCED", "BLOCKED", "FAILED"]).toContain(String(terminalMission.status));

  await expect(page.getByText(/Dynamic Validation Result/i).first()).toBeVisible({ timeout: 30_000 });
  await capture(page, "fv-06-validation-result.png");
  await page.getByRole("link", { name: "View Validation Report" }).first().click();
  await expect(page.getByRole("button", { name: "Download PDF Report" })).toBeVisible();
  await capture(page, "fv-07-validation-report.png");

  writeFileSync(
    path.join(evidenceDirectory, "finding-validation-result.json"),
    JSON.stringify({
      captured_at: new Date().toISOString(),
      selected_finding: {
        id: selectedFinding!.id,
        title: selectedFinding!.title,
        rule_id: selectedFinding!.rule_id,
        severity: selectedFinding!.severity,
        playbooks: selectedFinding!.dynamic_validation_playbooks,
      },
      mission: {
        id: missionId,
        status: terminalMission.status,
        provider: terminalMission.provider,
        model: terminalMission.model,
        scenario_hash: terminalMission.scenario_hash,
        mission_hash: terminalMission.mission_hash,
        validation_family: terminalMission.validation_family,
        playbook_id: terminalMission.playbook_id,
        final_conclusion: terminalMission.final_conclusion,
        limitations: terminalMission.limitations,
        usage: safeUsage(terminalMission.provider_metadata),
      },
      run: {
        id: runId,
        status: run.status,
        execution_mode: run.execution_mode,
        provider: run.decision_provider,
        model: run.decision_model,
        decision_count: run.decision_count,
        tool_call_count: run.tool_call_count,
        termination_reason: run.termination_reason,
      },
      poc_steps: Array.isArray(timeline.items) ? timeline.items : [],
      gateway_actions: steps.map((step) => ({
        sequence: step.sequence_number,
        tool: step.tool_name,
        status: step.status,
        retry_count: step.retry_count,
      })),
      evidence: evidence.map((item) => ({
        id: item.id,
        type: item.evidence_type,
        source: item.source,
        sha256: item.sha256,
      })),
      oracle_result: terminalMission.oracle_result,
      dynamic_validation_result: missionResult,
    }, null, 2),
  );
});
