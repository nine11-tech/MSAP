import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import {
  approveAssessmentPlan,
  cancelAssessmentExecution,
  captureDynamicHostAgentScreenshot,
  createAgentRun,
  createAssessmentPlan,
  executeAdaptiveAssessment,
  executeAssessmentPlan,
  getAgentRun,
  getAgentRunAssessmentSummary,
  getAssessmentPlan,
  getDynamicHostAgentStatus,
  installDynamicAuditApk,
  listAgentRunArtifacts,
  listAgentRunDecisions,
  listAgentRunEvidence,
  listAgentRunHypotheses,
  listAgentRuns,
  listAgentRunSteps,
  listAgentRuntimes,
  listAssessmentPlans,
  listApkFiles,
  listAudits,
  listDynamicHostAgentPackages,
  runDynamicHostAgentPackageAction,
  retryAdaptiveAssessment,
  validateAssessmentPlan,
} from "../api/msap";
import type {
  AgentActionDecision,
  AgentHypothesis,
  AgentRun,
  AgentRunArtifact,
  AgentRuntime,
  AgentRunStep,
  AgentObjective,
  AssessmentPlan,
  AssessmentRunSummary,
  ApkFile,
  Audit,
  DynamicHostAgentInstallResult,
  DynamicHostAgentStatus,
  Evidence,
  SystemComponent,
} from "../api/types";
import { useAuth } from "../auth/AuthContext";
import {
  Card,
  ErrorMessage,
  LoadingState,
  PageHeader,
  SectionHeader,
  errorMessage,
  formatDate,
} from "../components/Common";
import { useSystemStatus } from "../status/SystemStatusContext";

type WorkingAction =
  | ""
  | "refresh"
  | "screenshot"
  | "install"
  | "launch-package"
  | "force-stop"
  | "clear-data"
  | "uninstall"
  | "agent-run"
  | "frida-status"
  | "frida-setup"
  | "frida-ps"
  | "frida-attach"
  | "frida-proof"
  | "frida-custom"
  | "planner-generate"
  | "planner-validate"
  | "planner-approve"
  | "planner-execute"
  | "planner-retry"
  | "planner-cancel";

type PackageAction =
  | "launch-package"
  | "force-stop"
  | "clear-data"
  | "uninstall";

type AgentRuntimeType = "INTERNAL_CONTROLLER" | "CONTAINER_SANDBOX";
type AgentTargetType = "VERIFIED_APK" | "INSTALLED_PACKAGE";
type AssessmentExecutionMode = "ADAPTIVE_AGENT" | "SEQUENTIAL_PLAN";
type AssessmentPresetId =
  | "STANDARD"
  | "RUNTIME"
  | "UI_SENSITIVE_DATA"
  | "LOGGING_RUNTIME"
  | "CUSTOM";
type AIModelProfile = "ECONOMY" | "BALANCED" | "ADVANCED";
type AuditorStage = "TARGET" | "PLAN" | "APPROVE" | "ASSESS" | "RESULTS";

const ASSESSMENT_PRESETS: Array<{
  id: AssessmentPresetId;
  name: string;
  description: string;
  objective: string;
  scope: string;
  recommended?: boolean;
}> = [
  {
    id: "STANDARD",
    name: "Standard Dynamic Assessment",
    description: "A small, evidence-led assessment across runtime, UI, logs, and approved instrumentation.",
    recommended: true,
    objective:
      "Perform a bounded adaptive runtime security assessment of the authorized application. Establish application state, test a small number of useful runtime security hypotheses using only approved capabilities, collect evidence, and stop once meaningful evidence has been gathered.",
    scope:
      "Assess only the selected audit-authorized application on the managed emulator. Use only the approved MSAP capability envelope. Prioritize a minimal evidence-driven sequence. Do not access unrelated applications, host resources, credentials, arbitrary files, shells, or unrestricted commands.",
  },
  {
    id: "RUNTIME",
    name: "Runtime & Instrumentation",
    description: "Prioritize runtime readiness and controlled built-in instrumentation evidence.",
    objective:
      "Perform a bounded runtime and instrumentation assessment of the authorized application using only approved built-in capabilities and deterministic evidence evaluation.",
    scope:
      "Assess only the selected audit-authorized application on the managed emulator. Collect bounded runtime and approved instrumentation evidence. Do not use arbitrary scripts, shells, host resources, credentials, or unrelated applications.",
  },
  {
    id: "UI_SENSITIVE_DATA",
    name: "UI & Sensitive Data",
    description: "Inspect bounded interface state and evidence relevant to visible data exposure.",
    objective:
      "Assess the authorized application interface for bounded, evidence-supported indicators of sensitive data exposure without assigning model-generated findings or severity.",
    scope:
      "Assess only the selected audit-authorized application. Use approved UI, screenshot, and application-state capabilities on the managed emulator. Do not access unrelated applications, credentials, arbitrary files, or host resources.",
  },
  {
    id: "LOGGING_RUNTIME",
    name: "Logging & Runtime Behavior",
    description: "Collect a short target-correlated runtime and logging evidence window.",
    objective:
      "Assess bounded logging and runtime behavior of the authorized application and preserve evidence for deterministic oracle evaluation.",
    scope:
      "Assess only the selected audit-authorized application. Use run-scoped bounded logging and runtime capabilities on the managed emulator. Do not collect unrelated application data, credentials, arbitrary files, shells, or host resources.",
  },
  {
    id: "CUSTOM",
    name: "Custom",
    description: "Review and edit a bounded objective and scope for a specialized audit goal.",
    objective: "",
    scope: "",
  },
];

const AI_MODEL_PROFILES: Array<{
  id: AIModelProfile;
  name: string;
  model: string;
  description: string;
}> = [
  {
    id: "ECONOMY",
    name: "Economy",
    model: "GPT-5.6 Luna",
    description: "Recommended · lowest normal assessment cost",
  },
  {
    id: "BALANCED",
    name: "Balanced",
    model: "GPT-5.6 Terra",
    description: "Optional quality and cost balance",
  },
  {
    id: "ADVANCED",
    name: "Advanced / Legacy",
    model: "GPT-5.5",
    description: "Comparison and compatibility testing",
  },
];

const WORKFLOW_STAGES: AuditorStage[] = [
  "TARGET",
  "PLAN",
  "APPROVE",
  "ASSESS",
  "RESULTS",
];

export function DynamicLabPage() {
  const [searchParams] = useSearchParams();
  const requestedAuditId = Number(searchParams.get("audit") || 0) || null;
  const [audits, setAudits] = useState<Audit[]>([]);
  const [apkFiles, setApkFiles] = useState<ApkFile[]>([]);
  const [selectedAuditId, setSelectedAuditId] = useState<number | "">("");
  const [selectedApkId, setSelectedApkId] = useState<number | "">("");
  const [agentStatus, setAgentStatus] = useState<DynamicHostAgentStatus | null>(
    null,
  );
  const [packages, setPackages] = useState<string[]>([]);
  const [packageName, setPackageName] = useState("");
  const [installResult, setInstallResult] =
    useState<DynamicHostAgentInstallResult | null>(null);
  const [agentRuntimes, setAgentRuntimes] = useState<AgentRuntime[]>([]);
  const [agentRun, setAgentRun] = useState<AgentRun | null>(null);
  const [agentSteps, setAgentSteps] = useState<AgentRunStep[]>([]);
  const [agentArtifacts, setAgentArtifacts] = useState<AgentRunArtifact[]>([]);
  const [agentEvidence, setAgentEvidence] = useState<Evidence[]>([]);
  const [agentDecisions, setAgentDecisions] = useState<AgentActionDecision[]>([]);
  const [agentHypotheses, setAgentHypotheses] = useState<AgentHypothesis[]>([]);
  const [assessmentExecutionMode, setAssessmentExecutionMode] =
    useState<AssessmentExecutionMode>("ADAPTIVE_AGENT");
  const [selectedAgentRuntime, setSelectedAgentRuntime] =
    useState<AgentRuntimeType>("INTERNAL_CONTROLLER");
  const [selectedObjective, setSelectedObjective] =
    useState<AgentObjective>("DEVICE_READINESS_CHECK");
  const [agentTargetType, setAgentTargetType] =
    useState<AgentTargetType>("VERIFIED_APK");
  const [agentPackageName, setAgentPackageName] = useState("");
  const [agentTapX, setAgentTapX] = useState("");
  const [agentTapY, setAgentTapY] = useState("");
  const [agentText, setAgentText] = useState("");
  const [fridaPackageName, setFridaPackageName] = useState("");
  const [fridaScript, setFridaScript] = useState("");
  const [fridaScriptConfirmed, setFridaScriptConfirmed] = useState(false);
  const [fridaMode, setFridaMode] = useState<"attach" | "spawn">("attach");
  const [fridaTimeout, setFridaTimeout] = useState(12);
  const [assessmentPlan, setAssessmentPlan] = useState<AssessmentPlan | null>(null);
  const [startingFreshAssessment, setStartingFreshAssessment] = useState(false);
  const [assessmentSummary, setAssessmentSummary] =
    useState<AssessmentRunSummary | null>(null);
  const [plannerPackageName, setPlannerPackageName] = useState("");
  const [plannerProvider, setPlannerProvider] = useState<
    "" | "DETERMINISTIC" | "OPENAI"
  >("");
  const standardPreset = ASSESSMENT_PRESETS[0];
  const [assessmentPreset, setAssessmentPreset] =
    useState<AssessmentPresetId>("STANDARD");
  const [aiModelProfile, setAiModelProfile] =
    useState<AIModelProfile>("ECONOMY");
  const [plannerObjective, setPlannerObjective] = useState(
    standardPreset.objective,
  );
  const [plannerScope, setPlannerScope] = useState(standardPreset.scope);
  const [screenshotUrl, setScreenshotUrl] = useState("");
  const screenshotUrlRef = useRef("");
  const startingFreshAssessmentRef = useRef(false);
  const [loading, setLoading] = useState(true);
  const [working, setWorking] = useState<WorkingAction>("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const { hasRole } = useAuth();
  const canOperate = hasRole("ADMIN", "ANALYST");
  const { status: systemStatus, refresh: refreshSystemStatus } =
    useSystemStatus();

  const loadWorkspace = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [auditData, apkData, hostData, packageData, runtimeData, runData, planData] = await Promise.all([
        listAudits(),
        listApkFiles(),
        getDynamicHostAgentStatus(),
        listDynamicHostAgentPackages(),
        listAgentRuntimes(),
        listAgentRuns(),
        listAssessmentPlans(),
      ]);
      setAudits(auditData);
      setApkFiles(apkData);
      setAgentStatus(hostData);
      setPackages(packageData.packages);
      setAgentRuntimes(runtimeData);
      setAssessmentPlan(planData[0] || null);
      const latestRun = runData[0] || null;
      setAgentRun(latestRun);
      if (latestRun) {
        const [stepData, artifactData, evidenceData, decisionData, hypothesisData, summaryData] = await Promise.all([
          listAgentRunSteps(latestRun.id),
          listAgentRunArtifacts(latestRun.id),
          latestRun.objective === "ASSESSMENT_PLAN_EXECUTION"
            ? listAgentRunEvidence(latestRun.id)
            : Promise.resolve([]),
          latestRun.execution_mode === "ADAPTIVE_AGENT"
            ? listAgentRunDecisions(latestRun.id)
            : Promise.resolve([]),
          latestRun.execution_mode === "ADAPTIVE_AGENT"
            ? listAgentRunHypotheses(latestRun.id)
            : Promise.resolve([]),
          latestRun.objective === "ASSESSMENT_PLAN_EXECUTION" &&
          ["SUCCEEDED", "FAILED", "TIMEOUT"].includes(latestRun.status)
            ? getAgentRunAssessmentSummary(latestRun.id)
            : Promise.resolve(null),
        ]);
        setAgentSteps(stepData);
        setAgentArtifacts(artifactData);
        setAgentEvidence(evidenceData);
        setAgentDecisions(decisionData);
        setAgentHypotheses(hypothesisData);
        setAssessmentSummary(summaryData);
      } else {
        setAgentSteps([]);
        setAgentArtifacts([]);
        setAgentEvidence([]);
        setAgentDecisions([]);
        setAgentHypotheses([]);
        setAssessmentSummary(null);
      }
      setSelectedAuditId((current) => {
        if (current && auditData.some((audit) => audit.id === current)) {
          return current;
        }
        if (
          requestedAuditId &&
          auditData.some((audit) => audit.id === requestedAuditId)
        ) {
          return requestedAuditId;
        }
        return auditData[0]?.id || "";
      });
    } catch (requestError) {
      setError(errorMessage(requestError));
    } finally {
      setLoading(false);
    }
  }, [requestedAuditId]);

  useEffect(() => {
    void loadWorkspace();
  }, [loadWorkspace]);

  useEffect(() => {
    if (!selectedAuditId) return;
    let active = true;
    const auditId = selectedAuditId;
    void Promise.all([listAssessmentPlans(auditId), listAgentRuns(auditId)])
      .then(async ([plansForAudit, runsForAudit]) => {
        const latestAssessmentRun = runsForAudit.find(
          (run) => run.objective === "ASSESSMENT_PLAN_EXECUTION",
        );
        const latestOperatorRun = runsForAudit[0] || null;
        const displayedRun = latestAssessmentRun || latestOperatorRun;
        const displayedPlan = plansForAudit[0] || null;
        if (!active || startingFreshAssessmentRef.current) return;
        setAssessmentPlan(displayedPlan);
        setAgentRun(displayedRun);
        if (!displayedRun) {
          setAgentSteps([]);
          setAgentArtifacts([]);
          setAgentEvidence([]);
          setAgentDecisions([]);
          setAgentHypotheses([]);
          setAssessmentSummary(null);
          return;
        }
        const isAssessment = displayedRun.objective === "ASSESSMENT_PLAN_EXECUTION";
        const terminal = ["SUCCEEDED", "FAILED", "TIMEOUT"].includes(displayedRun.status);
        const [steps, artifacts, evidence, decisions, hypotheses, summary] = await Promise.all([
          listAgentRunSteps(displayedRun.id),
          listAgentRunArtifacts(displayedRun.id),
          isAssessment ? listAgentRunEvidence(displayedRun.id) : Promise.resolve([]),
          displayedRun.execution_mode === "ADAPTIVE_AGENT"
            ? listAgentRunDecisions(displayedRun.id)
            : Promise.resolve([]),
          displayedRun.execution_mode === "ADAPTIVE_AGENT"
            ? listAgentRunHypotheses(displayedRun.id)
            : Promise.resolve([]),
          isAssessment && terminal
            ? getAgentRunAssessmentSummary(displayedRun.id)
            : Promise.resolve(null),
        ]);
        if (!active || startingFreshAssessmentRef.current) return;
        setAgentSteps(steps);
        setAgentArtifacts(artifacts);
        setAgentEvidence(evidence);
        setAgentDecisions(decisions);
        setAgentHypotheses(hypotheses);
        setAssessmentSummary(summary);
      })
      .catch((requestError) => {
        if (active) setError(errorMessage(requestError));
      });
    return () => {
      active = false;
    };
  }, [selectedAuditId]);

  useEffect(() => {
    if (
      !agentRun ||
      agentRun.objective !== "ASSESSMENT_PLAN_EXECUTION" ||
      !["QUEUED", "RUNNING"].includes(agentRun.status)
    ) {
      return;
    }
    const runId = agentRun.id;
    const timer = window.setInterval(() => {
      void Promise.all([
        getAgentRun(runId),
        listAgentRunSteps(runId),
        listAgentRunArtifacts(runId),
        listAgentRunEvidence(runId),
        agentRun.execution_mode === "ADAPTIVE_AGENT"
          ? listAgentRunDecisions(runId)
          : Promise.resolve([]),
        agentRun.execution_mode === "ADAPTIVE_AGENT"
          ? listAgentRunHypotheses(runId)
          : Promise.resolve([]),
      ]).then(async ([run, steps, artifacts, evidence, decisions, hypotheses]) => {
        const terminal = ["SUCCEEDED", "FAILED", "TIMEOUT"].includes(run.status);
        const completedSummary = terminal
          ? await getAgentRunAssessmentSummary(run.id)
          : null;
        if (
          terminal &&
          completedSummary?.report.status !== "READY" &&
          !run.result_summary.post_processing
        ) {
          return;
        }
        setAgentRun(run);
        setAgentSteps(steps);
        setAgentArtifacts(artifacts);
        setAgentEvidence(evidence);
        setAgentDecisions(decisions);
        setAgentHypotheses(hypotheses);
        setAssessmentSummary(completedSummary);
        if (run.assessment_plan) {
          setAssessmentPlan(await getAssessmentPlan(run.assessment_plan));
        }
      }).catch((requestError) => setError(errorMessage(requestError)));
    }, 1500);
    return () => window.clearInterval(timer);
  }, [agentRun]);

  useEffect(
    () => () => {
      if (screenshotUrlRef.current) {
        URL.revokeObjectURL(screenshotUrlRef.current);
      }
    },
    [],
  );

  const verifiedApks = useMemo(
    () =>
      apkFiles.filter(
        (apk) =>
          apk.audit === selectedAuditId && apk.storage_status === "VERIFIED",
      ),
    [apkFiles, selectedAuditId],
  );
  const authorizedFridaPackages = useMemo(
    () => Array.from(new Set(packages)).sort(),
    [packages],
  );
  const authorizedPlannerPackages = useMemo(
    () =>
      Array.from(
        new Set(
          verifiedApks
            .map((apk) => apk.package_name)
            .filter((value): value is string => Boolean(value)),
        ),
      ).sort(),
    [verifiedApks],
  );

  useEffect(() => {
    setSelectedApkId((current) => {
      if (current && verifiedApks.some((apk) => apk.id === current)) {
        return current;
      }
      return verifiedApks[0]?.id || "";
    });
    setInstallResult(null);
  }, [selectedAuditId, verifiedApks]);

  useEffect(() => {
    setFridaPackageName((current) =>
      current && authorizedFridaPackages.includes(current)
        ? current
        : authorizedFridaPackages[0] || "",
    );
  }, [authorizedFridaPackages]);

  useEffect(() => {
    setPlannerPackageName((current) =>
      current && authorizedPlannerPackages.includes(current)
        ? current
        : authorizedPlannerPackages[0] || "",
    );
  }, [authorizedPlannerPackages]);

  useEffect(() => {
    const apk = verifiedApks.find((item) => item.id === selectedApkId);
    if (!apk?.package_name) return;
    setPackageName(apk.package_name);
    setPlannerPackageName(apk.package_name);
  }, [selectedApkId, verifiedApks]);

  const device = agentStatus?.device;
  const emulatorOnline = device?.state === "device";
  const internalRuntime = agentRuntimes.find(
    (runtime) => runtime.runtime_type === "INTERNAL_CONTROLLER",
  );
  const containerRuntime = agentRuntimes.find(
    (runtime) => runtime.runtime_type === "CONTAINER_SANDBOX",
  );
  const activeRuntime =
    selectedAgentRuntime === "CONTAINER_SANDBOX"
      ? containerRuntime
      : internalRuntime;
  const foundationAvailable = Boolean(activeRuntime?.available);
  const minio = componentById(systemStatus?.components, "minio");
  const celery = componentById(systemStatus?.components, "celery");
  const selectedApk = verifiedApks.find((apk) => apk.id === selectedApkId);
  const selectedTargetPackage = packageName.trim() || selectedApk?.package_name || "";
  const targetInstalled = Boolean(
    selectedTargetPackage && packages.includes(selectedTargetPackage),
  );
  const targetForeground = Boolean(
    selectedTargetPackage && device?.focused_app?.includes(selectedTargetPackage),
  );
  const selectedAudit = audits.find((audit) => audit.id === selectedAuditId);
  const matchingAssessmentRun =
    agentRun?.objective === "ASSESSMENT_PLAN_EXECUTION" &&
    assessmentPlan &&
    agentRun.assessment_plan === assessmentPlan.id
      ? agentRun
      : null;
  const auditorStage: AuditorStage = (() => {
    if (startingFreshAssessment) return "TARGET";
    if (!assessmentPlan) return "TARGET";
    if (
      matchingAssessmentRun &&
      ["SUCCEEDED", "FAILED", "TIMEOUT", "CANCELLED", "PAUSED"].includes(
        matchingAssessmentRun.status,
      )
    ) {
      return "RESULTS";
    }
    if (
      matchingAssessmentRun ||
      ["APPROVED", "EXECUTING"].includes(assessmentPlan.status)
    ) {
      return "ASSESS";
    }
    if (assessmentPlan.status === "VALIDATED") return "APPROVE";
    return "PLAN";
  })();

  function applyAssessmentPreset(presetId: AssessmentPresetId) {
    setAssessmentPreset(presetId);
    const preset = ASSESSMENT_PRESETS.find((item) => item.id === presetId);
    if (preset && presetId !== "CUSTOM") {
      setPlannerObjective(preset.objective);
      setPlannerScope(preset.scope);
    }
  }

  function handleStartNewAssessment() {
    startingFreshAssessmentRef.current = true;
    setStartingFreshAssessment(true);
    setAssessmentPlan(null);
    setAgentRun(null);
    setAgentSteps([]);
    setAgentArtifacts([]);
    setAgentEvidence([]);
    setAgentDecisions([]);
    setAgentHypotheses([]);
    setAssessmentSummary(null);
    setNotice("Ready to configure a new assessment for this authorized target.");
    setError("");
  }

  async function handleRefresh() {
    setWorking("refresh");
    setError("");
    setNotice("");
    try {
      const [hostData] = await Promise.all([
        getDynamicHostAgentStatus(),
        refreshSystemStatus(),
      ]);
      setAgentStatus(hostData);
      setNotice("Device and service status refreshed.");
    } catch (requestError) {
      setError(errorMessage(requestError));
    } finally {
      setWorking("");
    }
  }

  async function handleScreenshot() {
    setWorking("screenshot");
    setError("");
    setNotice("");
    try {
      const blob = await captureDynamicHostAgentScreenshot();
      if (screenshotUrlRef.current) {
        URL.revokeObjectURL(screenshotUrlRef.current);
      }
      const objectUrl = URL.createObjectURL(blob);
      screenshotUrlRef.current = objectUrl;
      setScreenshotUrl(objectUrl);
      setNotice("Screenshot captured.");
    } catch (requestError) {
      setError(errorMessage(requestError));
    } finally {
      setWorking("");
    }
  }

  async function refreshPackages(showNotice = true) {
    const result = await listDynamicHostAgentPackages();
    setPackages(result.packages);
    if (showNotice) {
      setNotice(
        result.truncated
          ? `${result.count} packages loaded (bounded result).`
          : `${result.count} packages loaded.`,
      );
    }
  }

  async function handleInstall() {
    if (!selectedAuditId || !selectedApkId) return;
    setWorking("install");
    setError("");
    setNotice("");
    setInstallResult(null);
    try {
      const result = await installDynamicAuditApk(
        selectedAuditId,
        selectedApkId,
      );
      setInstallResult(result);
      if (!result.success) {
        throw new Error(result.detail || "APK installation failed.");
      }
      if (result.package_name) {
        setPackageName(result.package_name);
      }
      await refreshPackages(false);
      setNotice(`Installed ${result.package_name || `APK #${result.apk_file}`}.`);
    } catch (requestError) {
      setError(errorMessage(requestError));
    } finally {
      setWorking("");
    }
  }

  async function handlePackageAction(action: PackageAction) {
    const target = packageName.trim();
    if (!target) return;
    if (
      action === "clear-data" &&
      !window.confirm(`Clear all application data for ${target}?`)
    ) {
      return;
    }
    if (
      action === "uninstall" &&
      !window.confirm(`Uninstall ${target} from the managed emulator?`)
    ) {
      return;
    }

    setWorking(action);
    setError("");
    setNotice("");
    try {
      const result = await runDynamicHostAgentPackageAction(action, target);
      if (!result.success) {
        throw new Error(result.detail || `${packageActionLabel(action)} failed.`);
      }
      const focused =
        action === "launch-package" && result.focused_activity
          ? ` Focused activity: ${result.focused_activity}.`
          : "";
      setNotice(`${packageActionLabel(action)} completed.${focused}`);
      await refreshPackages(false);
      setAgentStatus(await getDynamicHostAgentStatus());
    } catch (requestError) {
      setError(errorMessage(requestError));
    } finally {
      setWorking("");
    }
  }

  async function handleAgentRun() {
    setWorking("agent-run");
    setError("");
    setNotice("");
    try {
      let request: Parameters<typeof createAgentRun>[0];
      if (selectedObjective === "DEVICE_READINESS_CHECK") {
        request = {
          objective: selectedObjective,
          runtime_type: selectedAgentRuntime,
          ...(selectedAuditId ? { audit: selectedAuditId } : {}),
        };
      } else {
        if (!selectedAuditId) {
          throw new Error("Select an audit for the basic app interaction check.");
        }
        const objectiveInput: NonNullable<
          Parameters<typeof createAgentRun>[0]["objective_input"]
        > = { audit_id: selectedAuditId };
        if (agentTargetType === "VERIFIED_APK") {
          if (!selectedApkId) {
            throw new Error("Select a verified APK.");
          }
          objectiveInput.apk_file_id = selectedApkId;
        } else {
          if (!agentPackageName) {
            throw new Error("Select an installed package.");
          }
          objectiveInput.package_name = agentPackageName;
        }
        if ((agentTapX === "") !== (agentTapY === "")) {
          throw new Error("Provide both tap coordinates or leave both empty.");
        }
        if (agentTapX !== "" && agentTapY !== "") {
          objectiveInput.tap = { x: Number(agentTapX), y: Number(agentTapY) };
        }
        if (agentText) objectiveInput.text = agentText;
        request = {
          objective: selectedObjective,
          runtime_type: selectedAgentRuntime,
          audit: selectedAuditId,
          objective_input: objectiveInput,
        };
      }
      const run = await createAgentRun(request);
      const [steps, artifacts] = await Promise.all([
        listAgentRunSteps(run.id),
        listAgentRunArtifacts(run.id),
      ]);
      setAgentRun(run);
      setAgentSteps(steps);
      setAgentArtifacts(artifacts);
      setNotice(
        run.status === "SUCCEEDED"
          ? `${objectiveLabel(selectedObjective)} completed.`
          : `${objectiveLabel(selectedObjective)} completed with a controlled failure.`,
      );
    } catch (requestError) {
      setError(errorMessage(requestError));
    } finally {
      setWorking("");
    }
  }

  async function handleFridaRun(
    action: "status" | "setup" | "ps" | "attach" | "proof" | "custom",
  ) {
    if (!selectedAuditId) {
      setError("Select an audit for runtime instrumentation.");
      return;
    }
    if (!fridaPackageName) {
      setError("Select an audit-authorized target package.");
      return;
    }
    if (action === "custom" && (!fridaScript.trim() || !fridaScriptConfirmed)) {
      setError("Enter JavaScript and explicitly confirm custom script execution.");
      return;
    }
    const workingAction = `frida-${action}` as WorkingAction;
    setWorking(workingAction);
    setError("");
    setNotice("");
    try {
      let request: Parameters<typeof createAgentRun>[0];
      if (["status", "setup", "ps", "attach"].includes(action)) {
        request = {
          objective: "FRIDA_RUNTIME_ACTION",
          runtime_type: selectedAgentRuntime,
          audit: selectedAuditId,
          objective_input: {
            audit_id: selectedAuditId,
            package_name: fridaPackageName,
            operation: action as "status" | "setup" | "ps" | "attach",
            mode: fridaMode,
            timeout: fridaTimeout,
          },
        };
      } else if (action === "proof") {
        request = {
          objective: "FRIDA_RUNTIME_UI_MODIFICATION_PROOF",
          runtime_type: selectedAgentRuntime,
          audit: selectedAuditId,
          objective_input: {
            audit_id: selectedAuditId,
            package_name: fridaPackageName,
          },
        };
      } else {
        request = {
          objective: "FRIDA_CUSTOM_SCRIPT",
          runtime_type: selectedAgentRuntime,
          audit: selectedAuditId,
          objective_input: {
            audit_id: selectedAuditId,
            package_name: fridaPackageName,
            mode: fridaMode,
            source: fridaScript,
            timeout: fridaTimeout,
            capture_logcat: true,
            confirm: true,
          },
        };
      }
      const run = await createAgentRun(request);
      const [steps, artifacts] = await Promise.all([
        listAgentRunSteps(run.id),
        listAgentRunArtifacts(run.id),
      ]);
      setAgentRun(run);
      setAgentSteps(steps);
      setAgentArtifacts(artifacts);
      setNotice(
        run.status === "SUCCEEDED"
          ? `${objectiveLabel(run.objective)} completed.`
          : `${objectiveLabel(run.objective)} ended with a controlled failure.`,
      );
    } catch (requestError) {
      setError(errorMessage(requestError));
    } finally {
      setWorking("");
    }
  }

  async function handleGenerateAssessmentPlan() {
    if (!selectedAuditId || !plannerPackageName) {
      setError("Select an audit and its authorized target package.");
      return;
    }
    if (!plannerObjective.trim() || !plannerScope.trim()) {
      setError("Provide a bounded assessment objective and scope.");
      return;
    }
    setWorking("planner-generate");
    setError("");
    setNotice("");
    try {
      const plan = await createAssessmentPlan({
        audit: selectedAuditId,
        target_package: plannerPackageName,
        objective: plannerObjective.trim(),
        scope: plannerScope.trim(),
        model_profile: aiModelProfile,
        ...(plannerProvider ? { planner_provider: plannerProvider } : {}),
      });
      startingFreshAssessmentRef.current = false;
      setStartingFreshAssessment(false);
      setAssessmentPlan(plan);
      setNotice(`Assessment plan #${plan.id} generated. No tools were executed.`);
    } catch (requestError) {
      setError(assessmentFailureMessage(requestError, "planning"));
    } finally {
      setWorking("");
    }
  }

  async function handleValidateAssessmentPlan() {
    if (!assessmentPlan) return;
    setWorking("planner-validate");
    setError("");
    setNotice("");
    try {
      const plan = await validateAssessmentPlan(assessmentPlan.id);
      setAssessmentPlan(plan);
      setNotice(`Assessment plan #${plan.id} passed review and is ready for approval.`);
    } catch (requestError) {
      setError(assessmentFailureMessage(requestError, "policy"));
    } finally {
      setWorking("");
    }
  }

  async function handleApproveAssessmentPlan() {
    if (!assessmentPlan) return;
    setWorking("planner-approve");
    setError("");
    setNotice("");
    try {
      const plan = await approveAssessmentPlan(assessmentPlan.id);
      setAssessmentPlan(plan);
      setNotice(`Assessment plan #${plan.id} approved. Start remains a separate auditor action.`);
    } catch (requestError) {
      setError(assessmentFailureMessage(requestError, "approval"));
    } finally {
      setWorking("");
    }
  }

  async function handleExecuteAssessmentPlan() {
    if (!assessmentPlan) return;
    setWorking("planner-execute");
    setError("");
    setNotice("");
    try {
      const response = assessmentExecutionMode === "ADAPTIVE_AGENT"
        ? await executeAdaptiveAssessment(
            assessmentPlan.id,
            plannerProvider || undefined,
          )
        : await executeAssessmentPlan(assessmentPlan.id);
      const [steps, artifacts, evidence, decisions, hypotheses, plan] = await Promise.all([
        listAgentRunSteps(response.run.id),
        listAgentRunArtifacts(response.run.id),
        listAgentRunEvidence(response.run.id),
        response.run.execution_mode === "ADAPTIVE_AGENT"
          ? listAgentRunDecisions(response.run.id)
          : Promise.resolve([]),
        response.run.execution_mode === "ADAPTIVE_AGENT"
          ? listAgentRunHypotheses(response.run.id)
          : Promise.resolve([]),
        getAssessmentPlan(assessmentPlan.id),
      ]);
      setAgentRun(response.run);
      setAgentSteps(steps);
      setAgentArtifacts(artifacts);
      setAgentEvidence(evidence);
      setAgentDecisions(decisions);
      setAgentHypotheses(hypotheses);
      setAssessmentSummary(null);
      setAssessmentPlan(plan);
      setNotice(
        `Approved strategy #${assessmentPlan.id} queued as ${
          response.run.execution_mode === "ADAPTIVE_AGENT"
            ? "an adaptive assessment"
            : "a sequential assessment"
        } in AgentRun #${response.run.id}.`,
      );
    } catch (requestError) {
      setError(assessmentFailureMessage(requestError, "execution"));
    } finally {
      setWorking("");
    }
  }

  async function handleCancelAssessmentExecution() {
    if (!agentRun || agentRun.objective !== "ASSESSMENT_PLAN_EXECUTION") return;
    setWorking("planner-cancel");
    setError("");
    try {
      const run = await cancelAssessmentExecution(agentRun.id);
      setAgentRun(run);
      if (run.assessment_plan) {
        setAssessmentPlan(await getAssessmentPlan(run.assessment_plan));
      }
      setNotice(`Cancellation recorded for AgentRun #${run.id}.`);
    } catch (requestError) {
      setError(errorMessage(requestError));
    } finally {
      setWorking("");
    }
  }

  async function handleRetryAdaptiveAssessment() {
    if (!agentRun?.adaptive_retryable || !agentRun.assessment_plan) return;
    setWorking("planner-retry");
    setError("");
    setNotice("");
    try {
      const response = await retryAdaptiveAssessment(agentRun.id);
      const [steps, artifacts, evidence, decisions, hypotheses, plan] = await Promise.all([
        listAgentRunSteps(response.run.id),
        listAgentRunArtifacts(response.run.id),
        listAgentRunEvidence(response.run.id),
        listAgentRunDecisions(response.run.id),
        listAgentRunHypotheses(response.run.id),
        getAssessmentPlan(agentRun.assessment_plan),
      ]);
      setAgentRun(response.run);
      setAgentSteps(steps);
      setAgentArtifacts(artifacts);
      setAgentEvidence(evidence);
      setAgentDecisions(decisions);
      setAgentHypotheses(hypotheses);
      setAssessmentSummary(null);
      setAssessmentPlan(plan);
      setNotice(
        `Approved plan #${plan.id} queued safely as AgentRun #${response.run.id}.`,
      );
    } catch (requestError) {
      setError(assessmentFailureMessage(requestError, "execution"));
    } finally {
      setWorking("");
    }
  }

  if (loading && !agentStatus) {
    return <LoadingState label="Loading Dynamic Lab..." />;
  }

  return (
    <div className="dynamic-mvp-page">
      <PageHeader
        eyebrow="Authorized Android workspace"
        title="Dynamic Security Assessment"
        description="Assess an authorized Android application using bounded AI planning and controlled runtime evidence."
      />

      {error ? <ErrorMessage message={error} /> : null}
      {notice ? (
        <div className="alert alert-success" role="status">
          {notice}
        </div>
      ) : null}

      <nav className="assessment-workflow" aria-label="Assessment workflow">
        {WORKFLOW_STAGES.map((stage, index) => {
          const currentIndex = WORKFLOW_STAGES.indexOf(auditorStage);
          return (
            <span
              key={stage}
              className={
                index < currentIndex
                  ? "is-complete"
                  : index === currentIndex
                    ? "is-current"
                    : "is-future"
              }
              aria-current={index === currentIndex ? "step" : undefined}
            >
              <b>{index < currentIndex ? "✓" : index + 1}</b>
              {stage.charAt(0) + stage.slice(1).toLowerCase()}
            </span>
          );
        })}
      </nav>

      {auditorStage === "TARGET" ? (
        <Card className="dynamic-mvp-section auditor-stage-card target-stage-card">
          <SectionHeader
            title="Configure Security Assessment"
            description="Choose an audit-authorized target and a bounded assessment preset."
            actions={
              <span className={`lab-readiness ${emulatorOnline ? "is-ready" : "is-unavailable"}`}>
                <i aria-hidden="true" />
                Android lab {emulatorOnline ? "ready" : "unavailable"}
              </span>
            }
          />

          <div className="auditor-target-grid">
            <div className="auditor-target-selectors">
              <label>
                <span>Audit</span>
                <select
                  value={selectedAuditId}
                  onChange={(event) =>
                    setSelectedAuditId(event.target.value ? Number(event.target.value) : "")
                  }
                  disabled={Boolean(working)}
                >
                  <option value="">Select audit</option>
                  {audits.map((audit) => (
                    <option key={audit.id} value={audit.id}>{audit.name}</option>
                  ))}
                </select>
              </label>
              <label>
                <span>Target application</span>
                <select
                  value={selectedApkId}
                  onChange={(event) =>
                    setSelectedApkId(event.target.value ? Number(event.target.value) : "")
                  }
                  disabled={!selectedAuditId || Boolean(working)}
                >
                  <option value="">Select authorized target</option>
                  {verifiedApks.map((apk) => (
                    <option key={apk.id} value={apk.id}>
                      {applicationDisplayName(apk.package_name)} · {apk.package_name}
                    </option>
                  ))}
                </select>
              </label>
            </div>

            <section className="authorized-target-card" aria-label="Authorized target summary">
              <div className="authorized-target-icon" aria-hidden="true">AG</div>
              <div>
                <span className="eyebrow">Authorized application</span>
                <h3>{applicationDisplayName(plannerPackageName || selectedTargetPackage)}</h3>
                <p className="mono">{plannerPackageName || selectedTargetPackage || "No target selected"}</p>
              </div>
              <dl>
                <div><dt>Version</dt><dd>{selectedApk?.version_name || installResult?.package_metadata.version_name || "Unavailable"}</dd></div>
                <div><dt>Installation</dt><dd className={targetInstalled ? "state-text-ready" : ""}>{targetInstalled ? "Installed" : "Not detected"}</dd></div>
                <div><dt>App state</dt><dd className={targetForeground ? "state-text-ready" : ""}>{targetForeground ? "Foreground" : "Not active"}</dd></div>
                <div><dt>Device</dt><dd className={emulatorOnline ? "state-text-ready" : "state-text-failed"}>{emulatorOnline ? `Ready · Android ${device?.android_version || ""}` : "Unavailable"}</dd></div>
                <div><dt>Audit</dt><dd>{selectedAudit?.name || "Not selected"}</dd></div>
              </dl>
            </section>
          </div>

          <section className="assessment-preset-section" aria-labelledby="assessment-type-title">
            <div className="auditor-section-heading">
              <div>
                <span className="eyebrow">Assessment type</span>
                <h3 id="assessment-type-title">What should the agent assess?</h3>
              </div>
              <span>Safe objective and scope templates</span>
            </div>
            <div className="assessment-preset-grid">
              {ASSESSMENT_PRESETS.map((preset) => (
                <button
                  key={preset.id}
                  type="button"
                  className={`assessment-preset${assessmentPreset === preset.id ? " is-selected" : ""}`}
                  aria-pressed={assessmentPreset === preset.id}
                  onClick={() => applyAssessmentPreset(preset.id)}
                  disabled={Boolean(working)}
                >
                  <span>{preset.name}</span>
                  {preset.recommended ? <b>Recommended</b> : null}
                  <small>{preset.description}</small>
                </button>
              ))}
            </div>
          </section>

          <details className="auditor-disclosure customize-assessment">
            <summary>Customize Assessment</summary>
            <div className="custom-assessment-fields">
              <label>
                <span>Objective</span>
                <textarea
                  value={plannerObjective}
                  onChange={(event) => {
                    setPlannerObjective(event.target.value);
                    setAssessmentPreset("CUSTOM");
                  }}
                  maxLength={500}
                  rows={4}
                  disabled={Boolean(working)}
                />
              </label>
              <label>
                <span>Authorized scope</span>
                <textarea
                  value={plannerScope}
                  onChange={(event) => {
                    setPlannerScope(event.target.value);
                    setAssessmentPreset("CUSTOM");
                  }}
                  maxLength={2000}
                  rows={4}
                  disabled={Boolean(working)}
                />
              </label>
            </div>
          </details>

          <details className="auditor-disclosure advanced-ai-settings">
            <summary>Advanced AI Settings</summary>
            <div className="advanced-ai-grid">
              <label>
                <span>AI profile</span>
                <select
                  value={aiModelProfile}
                  onChange={(event) => setAiModelProfile(event.target.value as AIModelProfile)}
                  disabled={Boolean(working)}
                >
                  {AI_MODEL_PROFILES.map((profile) => (
                    <option key={profile.id} value={profile.id}>
                      {profile.name} · {profile.model}
                    </option>
                  ))}
                </select>
                <small>{AI_MODEL_PROFILES.find((profile) => profile.id === aiModelProfile)?.description}</small>
              </label>
              <label>
                <span>Provider policy</span>
                <select
                  value={plannerProvider}
                  onChange={(event) => setPlannerProvider(event.target.value as "" | "DETERMINISTIC" | "OPENAI")}
                  disabled={Boolean(working)}
                >
                  <option value="">Server default</option>
                  <option value="OPENAI">OpenAI</option>
                  <option value="DETERMINISTIC">Deterministic reference</option>
                </select>
                <small>No arbitrary model IDs or provider endpoints are accepted.</small>
              </label>
              <label>
                <span>Execution mode</span>
                <select
                  value={assessmentExecutionMode}
                  onChange={(event) => setAssessmentExecutionMode(event.target.value as AssessmentExecutionMode)}
                  disabled={Boolean(working)}
                >
                  <option value="ADAPTIVE_AGENT">Adaptive Security Agent</option>
                  <option value="SEQUENTIAL_PLAN">Sequential Approved Plan</option>
                </select>
                <small>Reasoning is low and budgets remain backend-owned.</small>
              </label>
            </div>
          </details>

          <div className="auditor-primary-action">
            <div>
              <strong>{AI_MODEL_PROFILES.find((profile) => profile.id === aiModelProfile)?.name} · {AI_MODEL_PROFILES.find((profile) => profile.id === aiModelProfile)?.model}</strong>
              <span>Plan generation only. No Android action runs before approval.</span>
            </div>
            <button
              className="button button-primary button-prominent"
              onClick={() => void handleGenerateAssessmentPlan()}
              disabled={!canOperate || !selectedAuditId || !plannerPackageName || !plannerObjective.trim() || !plannerScope.trim() || Boolean(working)}
            >
              {working === "planner-generate" ? "Generating AI Assessment…" : "Generate AI Assessment"}
            </button>
          </div>

          <details className="auditor-disclosure manual-controls">
            <summary>Manual Controls</summary>
            <div className="manual-control-toolbar">
              <button className="button button-secondary" onClick={() => void handleInstall()} disabled={!canOperate || !selectedAuditId || !selectedApkId || !emulatorOnline || Boolean(working)}>Install</button>
              <button className="button button-secondary" onClick={() => void handlePackageAction("launch-package")} disabled={!canOperate || !packageName.trim() || !emulatorOnline || Boolean(working)}>Launch</button>
              <button className="button button-secondary" onClick={() => void handlePackageAction("force-stop")} disabled={!canOperate || !packageName.trim() || !emulatorOnline || Boolean(working)}>Force Stop</button>
              <button className="button button-secondary" onClick={() => void handlePackageAction("clear-data")} disabled={!canOperate || !packageName.trim() || !emulatorOnline || Boolean(working)}>Clear Data</button>
              <button className="button button-danger" onClick={() => void handlePackageAction("uninstall")} disabled={!canOperate || !packageName.trim() || !emulatorOnline || Boolean(working)}>Uninstall</button>
              <button className="button button-secondary" onClick={() => void handleScreenshot()} disabled={!canOperate || !agentStatus?.connected || !emulatorOnline || Boolean(working)}>Screenshot</button>
              <button className="button button-secondary" onClick={() => void handleRefresh()} disabled={Boolean(working)}>Refresh Lab</button>
            </div>
            {screenshotUrl ? <img className="manual-screenshot-preview" src={screenshotUrl} alt="Latest managed emulator screenshot" /> : null}
            <div className="device-service-strip" aria-label="Operational services">
              <ServiceIndicator label="Object storage" component={minio} />
              <ServiceIndicator label="Assessment worker" component={celery} />
              <span className="service-indicator">Host agent: {agentStatus?.connected ? "Online" : "Offline"}</span>
            </div>
          </details>

          {!canOperate ? <p className="muted dynamic-role-note">Viewer access is read-only.</p> : null}
          {selectedAuditId && !verifiedApks.length ? <p className="muted dynamic-role-note">No verified target is authorized for this audit.</p> : null}
        </Card>
      ) : null}

      {auditorStage === "PLAN" && assessmentPlan ? (
        <Card className="dynamic-mvp-section auditor-stage-card plan-stage-card">
          <SectionHeader
            title="AI Assessment Plan"
            description={`Generated by ${modelDisplayName(assessmentPlan.planner_model)} for ${applicationDisplayName(assessmentPlan.target_package)}.`}
            actions={<span className="planner-only-badge">PLAN ONLY · NO EXECUTION</span>}
          />
          <AssessmentPlanResult plan={assessmentPlan} />
          <div className="auditor-stage-actions">
            <button className="button button-secondary" onClick={handleStartNewAssessment} disabled={Boolean(working)}>Start New Assessment</button>
            {assessmentPlan.status === "GENERATED" ? (
              <button className="button button-primary button-prominent" onClick={() => void handleValidateAssessmentPlan()} disabled={!canOperate || Boolean(working)}>
                {working === "planner-validate" ? "Checking Assessment…" : "Review & Continue"}
              </button>
            ) : null}
          </div>
        </Card>
      ) : null}

      {auditorStage === "APPROVE" && assessmentPlan ? (
        <Card className="dynamic-mvp-section auditor-stage-card approval-stage-card">
          <SectionHeader
            title="Assessment Ready for Approval"
            description="Review the immutable execution boundary, then make an explicit auditor decision."
            actions={<span className="planner-only-badge">AUDITOR APPROVAL REQUIRED</span>}
          />
          <div className="approval-hero">
            <div>
              <span className="eyebrow">Target</span>
              <h3>{applicationDisplayName(assessmentPlan.target_package)}</h3>
              <p className="mono">{assessmentPlan.target_package}</p>
            </div>
            <div>
              <span className="eyebrow">AI</span>
              <h3>{modelDisplayName(assessmentPlan.planner_model)}</h3>
              <p>Low reasoning · strict structured output</p>
            </div>
            <div>
              <span className="eyebrow">Execution mode</span>
              <h3>{assessmentExecutionMode === "ADAPTIVE_AGENT" ? "Adaptive Security Agent" : "Sequential Approved Plan"}</h3>
              <p>Starts only after a second explicit action</p>
            </div>
          </div>
          <div className="approval-boundary-grid">
            <StatusFact label="Capabilities" value={`${assessmentPlan.agentic_capability_preview.allowed_capabilities?.length || 0} approved safe capabilities`} />
            <StatusFact label="Decisions" value={String(assessmentPlan.agentic_capability_preview.maximum_decisions || "Bounded")} />
            <StatusFact label="Tool actions" value={String(assessmentPlan.agentic_capability_preview.maximum_tool_calls || "Bounded")} />
            <StatusFact label="Deadline" value={assessmentPlan.agentic_capability_preview.maximum_run_duration_seconds ? `${Math.ceil(assessmentPlan.agentic_capability_preview.maximum_run_duration_seconds / 60)} minutes` : "Bounded"} />
            <StatusFact label="Destructive actions" value={assessmentPlan.agentic_capability_preview.additional_approval_capabilities?.length ? "Additional approval required" : "Not permitted"} state={assessmentPlan.agentic_capability_preview.additional_approval_capabilities?.length ? "warning" : "online"} />
          </div>
          <section className="approval-security-areas">
            <span>Security areas</span>
            <div>
              {(assessmentPlan.agentic_capability_preview.allowed_hypothesis_families || []).map((family) => (
                <span key={family}>{hypothesisFamilyLabel(family)}</span>
              ))}
            </div>
          </section>
          <div className="security-check-list" aria-label="Backend security checks">
            <span>✓ Target authorization</span>
            <span>✓ Capability policy</span>
            <span>✓ Argument validation</span>
            <span>✓ Resource bounds</span>
          </div>
          <div className="auditor-stage-actions">
            <button className="button button-secondary" onClick={handleStartNewAssessment} disabled={Boolean(working)}>Cancel Review</button>
            <button className="button button-primary button-prominent" onClick={() => void handleApproveAssessmentPlan()} disabled={!canOperate || Boolean(working)}>
              {working === "planner-approve" ? "Approving Assessment…" : "Approve Assessment"}
            </button>
          </div>
        </Card>
      ) : null}

      {(auditorStage === "ASSESS" || auditorStage === "RESULTS") && assessmentPlan ? (
        <Card className="dynamic-mvp-section auditor-stage-card assessment-stage-card">
          {!matchingAssessmentRun ? (
            <div className="assessment-start-state">
              <span className="assessment-start-icon" aria-hidden="true">✓</span>
              <span className="eyebrow">Approval recorded</span>
              <h2>Start the AI Security Agent</h2>
              <p>
                {applicationDisplayName(assessmentPlan.target_package)} is approved for a bounded {assessmentExecutionMode === "ADAPTIVE_AGENT" ? "adaptive" : "sequential"} assessment. Starting creates a separate auditable AgentRun.
              </p>
              <div className="assessment-start-facts">
                <span>{modelDisplayName(assessmentPlan.planner_model)}</span>
                <span>{assessmentPlan.agentic_capability_preview.maximum_decisions || "Bounded"} decisions max</span>
                <span>{assessmentPlan.agentic_capability_preview.maximum_tool_calls || "Bounded"} actions max</span>
              </div>
              <div className="auditor-stage-actions">
                <button className="button button-secondary" onClick={handleStartNewAssessment} disabled={Boolean(working)}>New Assessment</button>
                <button className="button button-primary button-prominent" onClick={() => void handleExecuteAssessmentPlan()} disabled={!canOperate || assessmentPlan.status !== "APPROVED" || Boolean(working)}>
                  {working === "planner-execute" ? "Starting Security Assessment…" : "Start Security Assessment"}
                </button>
              </div>
            </div>
          ) : (
            <AssessmentExecutionResult
              run={matchingAssessmentRun}
              steps={agentSteps}
              artifacts={agentArtifacts}
              evidence={agentEvidence}
              decisions={agentDecisions}
              hypotheses={agentHypotheses}
              summary={assessmentSummary}
              canCancel={canOperate && ["QUEUED", "RUNNING", "PAUSED"].includes(matchingAssessmentRun.status)}
              canRetry={canOperate && matchingAssessmentRun.adaptive_retryable}
              cancelling={working === "planner-cancel"}
              retrying={working === "planner-retry"}
              onCancel={() => void handleCancelAssessmentExecution()}
              onRetry={() => void handleRetryAdaptiveAssessment()}
            />
          )}
          {auditorStage === "RESULTS" ? (
            <div className="auditor-stage-actions results-next-actions">
              <button className="button button-secondary" onClick={handleStartNewAssessment}>New Assessment</button>
              {assessmentSummary?.report.status === "READY" ? (
                <Link className="button button-primary" to={`/audits/${assessmentSummary.audit_id}/report`}>View Assessment Report</Link>
              ) : null}
            </div>
          ) : null}
        </Card>
      ) : null}

      <details className="advanced-operator-panel">
        <summary>
          <span>
            <strong>Advanced Operator Controls</strong>
            <small>Readiness checks, deterministic mobile tools, runtime instrumentation, and debug evidence.</small>
          </span>
          <span className="advanced-toggle-label">Show advanced</span>
        </summary>
        <div className="advanced-operator-content">
      <Card className="dynamic-mvp-section agent-foundation-card">
        <SectionHeader
          title="Deterministic Mobile Checks"
          actions={
            <button
              className="button button-primary"
              onClick={() => void handleAgentRun()}
              disabled={!canOperate || !foundationAvailable || Boolean(working)}
            >
              {working === "agent-run"
                ? "Running Check..."
                : `Run ${objectiveLabel(selectedObjective)}`}
            </button>
          }
        />

        <div className="agent-foundation-intro">
          <span
            className={`agent-foundation-status ${
              foundationAvailable ? "is-available" : "is-unavailable"
            }`}
          >
            {foundationAvailable
              ? "Foundation available"
              : "Foundation unavailable"}
          </span>
          <p>
            Run bounded readiness or application-interaction checks for operator
            diagnostics. These controls remain separate from the approved AI assessment.
          </p>
          {!canOperate ? (
            <p className="muted dynamic-role-note">
              Viewer access is read-only; only an Analyst or Admin can start a run.
            </p>
          ) : null}
        </div>

        <div className="agent-runtime-controls">
          <label>
            <span>Objective</span>
            <select
              value={selectedObjective}
              onChange={(event) =>
                setSelectedObjective(event.target.value as AgentObjective)
              }
              disabled={Boolean(working)}
            >
              <option value="DEVICE_READINESS_CHECK">Device Readiness Check</option>
              <option value="BASIC_APP_INTERACTION_CHECK">
                Basic App Interaction Check
              </option>
            </select>
          </label>
          <label>
            <span>Run mode</span>
            <select
              value={selectedAgentRuntime}
              onChange={(event) =>
                setSelectedAgentRuntime(event.target.value as AgentRuntimeType)
              }
              disabled={Boolean(working)}
            >
              <option
                value="INTERNAL_CONTROLLER"
                disabled={!internalRuntime?.available}
              >
                Internal Controller
              </option>
              <option
                value="CONTAINER_SANDBOX"
                disabled={!containerRuntime?.available}
              >
                Container Sandbox
                {containerRuntime?.available ? "" : " (Unavailable)"}
              </option>
            </select>
          </label>
          <div className="dynamic-device-facts agent-runtime-facts">
            <StatusFact
              label="Active runtime"
              value={runtimeTypeLabel(selectedAgentRuntime)}
              state={foundationAvailable ? "online" : "offline"}
            />
            <StatusFact
              label="Isolation level"
              value={isolationLabel(activeRuntime?.isolation_level)}
            />
            <StatusFact label="Run mode" value="Deterministic mobile tools" />
            <StatusFact
              label="Container runtime enabled"
              value={yesNo(containerRuntime?.configuration_enabled)}
              state={containerRuntime?.configuration_enabled ? "online" : "neutral"}
            />
          </div>
        </div>

        {selectedObjective === "BASIC_APP_INTERACTION_CHECK" ? (
          <div className="agent-objective-controls">
            <label>
              <span>Audit</span>
              <select
                value={selectedAuditId}
                onChange={(event) => setSelectedAuditId(Number(event.target.value) || "")}
                disabled={Boolean(working)}
              >
                <option value="">Select audit</option>
                {audits.map((audit) => (
                  <option key={audit.id} value={audit.id}>{audit.name}</option>
                ))}
              </select>
            </label>
            <label>
              <span>App source</span>
              <select
                value={agentTargetType}
                onChange={(event) => setAgentTargetType(event.target.value as AgentTargetType)}
                disabled={Boolean(working)}
              >
                <option value="VERIFIED_APK">Verified APK</option>
                <option value="INSTALLED_PACKAGE">Installed package</option>
              </select>
            </label>
            {agentTargetType === "VERIFIED_APK" ? (
              <label>
                <span>Verified APK</span>
                <select
                  value={selectedApkId}
                  onChange={(event) => setSelectedApkId(Number(event.target.value) || "")}
                  disabled={Boolean(working)}
                >
                  <option value="">Select verified APK</option>
                  {verifiedApks.map((apk) => (
                    <option key={apk.id} value={apk.id}>
                      {apk.package_name || `APK #${apk.id}`} · {apk.version_name || "unknown version"}
                    </option>
                  ))}
                </select>
              </label>
            ) : (
              <label>
                <span>Installed package</span>
                <select
                  value={agentPackageName}
                  onChange={(event) => setAgentPackageName(event.target.value)}
                  disabled={Boolean(working)}
                >
                  <option value="">Select installed package</option>
                  {packages.map((installedPackage) => (
                    <option key={installedPackage} value={installedPackage}>{installedPackage}</option>
                  ))}
                </select>
              </label>
            )}
            <label>
              <span>Optional tap X</span>
              <input
                type="number"
                min="0"
                max="10000"
                value={agentTapX}
                onChange={(event) => setAgentTapX(event.target.value)}
                disabled={Boolean(working)}
              />
            </label>
            <label>
              <span>Optional tap Y</span>
              <input
                type="number"
                min="0"
                max="10000"
                value={agentTapY}
                onChange={(event) => setAgentTapY(event.target.value)}
                disabled={Boolean(working)}
              />
            </label>
            <label className="agent-objective-text">
              <span>Optional text (128 safe characters maximum)</span>
              <input
                type="text"
                maxLength={128}
                value={agentText}
                onChange={(event) => setAgentText(event.target.value)}
                disabled={Boolean(working)}
                autoComplete="off"
              />
            </label>
            {agentTargetType === "INSTALLED_PACKAGE" && packages.length === 0 ? (
              <p className="muted agent-objective-note">
                Load installed packages in the APK & Package Controls section first.
              </p>
            ) : null}
          </div>
        ) : null}

        {agentRun &&
        !isFridaObjective(agentRun.objective) &&
        agentRun.objective !== "ASSESSMENT_PLAN_EXECUTION" ? (
          <div className="agent-run-layout">
            <section className="agent-run-result" aria-label="Latest agent run result">
              <div className="agent-run-heading">
                <div>
                  <span className="eyebrow">Latest deterministic run</span>
                  <h3>{objectiveLabel(agentRun.objective)} #{agentRun.id}</h3>
                </div>
                <span className={`agent-run-state state-${agentRun.status.toLowerCase()}`}>
                  {agentRun.status}
                </span>
              </div>

              <div className="dynamic-device-facts agent-result-facts">
                <StatusFact
                  label="Executed by"
                  value={runtimeTypeLabel(agentRun.runtime_type)}
                  detail={isolationLabel(agentRun.isolation_level)}
                />
                {agentRun.objective === "BASIC_APP_INTERACTION_CHECK" ? (
                  <>
                    <StatusFact
                      label="App source"
                      value={agentRun.result_summary.app_installed ? "Installed verified APK" : "Already present"}
                    />
                    <StatusFact label="Package" value={agentRun.result_summary.package_name || "Unavailable"} />
                    <StatusFact label="App launched" value={yesNo(agentRun.result_summary.app_launched)} state={agentRun.result_summary.app_launched ? "online" : "offline"} />
                    <StatusFact label="Screenshot captured" value={yesNo(agentRun.result_summary.screenshot_captured)} state={agentRun.result_summary.screenshot_captured ? "online" : "offline"} />
                    <StatusFact label="UI hierarchy captured" value={yesNo(agentRun.result_summary.ui_dumped)} state={agentRun.result_summary.ui_dumped ? "online" : "offline"} />
                    <StatusFact label="Logcat captured" value={yesNo(agentRun.result_summary.logcat_captured)} state={agentRun.result_summary.logcat_captured ? "online" : "offline"} />
                    <StatusFact label="Tap" value={agentRun.result_summary.tap_skipped ? "Skipped" : yesNo(agentRun.result_summary.tap_executed)} />
                    <StatusFact label="Text input" value={agentRun.result_summary.type_skipped ? "Skipped" : yesNo(agentRun.result_summary.type_executed)} />
                    <StatusFact label="Force stop" value={yesNo(agentRun.result_summary.force_stop_completed)} state={agentRun.result_summary.force_stop_completed ? "online" : "offline"} />
                  </>
                ) : (
                  <>
                    <StatusFact label="Host agent reachable" value={yesNo(agentRun.result_summary.host_agent_reachable)} state={agentRun.result_summary.host_agent_reachable ? "online" : "offline"} />
                    <StatusFact label="Emulator reachable" value={yesNo(agentRun.result_summary.emulator_reachable)} state={agentRun.result_summary.emulator_reachable ? "online" : "offline"} />
                    <StatusFact label="Serial" value={agentRun.result_summary.device?.serial || "Unavailable"} />
                    <StatusFact label="Android / API / ABI" value={deviceIdentity(agentRun)} />
                    <StatusFact label="SELinux" value={agentRun.result_summary.device?.selinux || "Unavailable"} />
                    <StatusFact label="Screenshot captured" value={yesNo(agentRun.result_summary.screenshot_captured)} state={agentRun.result_summary.screenshot_captured ? "online" : "offline"} />
                    <StatusFact label="Environment ready" value={yesNo(agentRun.result_summary.environment_ready)} state={agentRun.result_summary.environment_ready ? "online" : "warning"} />
                  </>
                )}
                <StatusFact
                  label="Run duration"
                  value={formatDuration(agentRun.duration_seconds)}
                />
              </div>

              <p className="agent-result-summary">
                {agentRun.result_summary.summary || agentRun.failure_message}
              </p>
              {agentRun.failure_message ? (
                <p className="agent-failure-message">
                  {agentRun.failure_category}: {agentRun.failure_message}
                </p>
              ) : null}
              <p className="muted agent-scope-note">
                {agentRun.result_summary.assessment_scope ||
                  "Device readiness only; no vulnerability or malware verdict was produced."}
              </p>
            </section>

            <section className="agent-step-card" aria-label="Agent run steps">
              <div className="agent-subsection-heading">
                <h3>Bounded tool sequence</h3>
                <span>
                  {agentSteps.filter((step) => step.status === "SUCCEEDED").length}
                  {" / "}{agentSteps.length} succeeded
                </span>
              </div>
              <ol className="agent-step-list">
                {agentSteps.map((step) => (
                  <li key={step.id}>
                    <span className="agent-step-sequence">{step.sequence_number}</span>
                    <div>
                      <strong className="mono">{step.tool_name}</strong>
                      {step.failure_message ? <small>{step.failure_message}</small> : null}
                    </div>
                    <span className={`agent-step-status state-${step.status.toLowerCase()}`}>
                      {step.status}
                    </span>
                  </li>
                ))}
              </ol>
            </section>

            <AgentEvidenceCard
              artifact={agentArtifacts.find(
                (artifact) => artifact.artifact_type === "SCREENSHOT",
              )}
            />
            {agentRun.objective === "BASIC_APP_INTERACTION_CHECK" ? (
              <>
                <AgentUiEvidence summary={agentRun.result_summary.ui_dump} />
                <AgentLogcatEvidence summary={agentRun.result_summary.logcat_excerpt} />
              </>
            ) : null}
          </div>
        ) : !agentRun ? (
          <div className="agent-empty-result">
            No deterministic agent run has been recorded yet.
          </div>
        ) : null}
      </Card>

      <Card className="dynamic-mvp-section runtime-instrumentation-card">
        <SectionHeader title="Runtime Instrumentation & Debug" />
        <p className="muted">
          Advanced Frida environment checks and controlled scripts for an
          audit-authorized Android package.
        </p>

        <div className="agent-objective-controls runtime-instrumentation-controls">
          <label>
            <span>Environment audit</span>
            <select
              value={selectedAuditId}
              onChange={(event) => setSelectedAuditId(Number(event.target.value) || "")}
              disabled={Boolean(working)}
            >
              <option value="">Select audit</option>
              {audits.map((audit) => (
                <option key={audit.id} value={audit.id}>{audit.name}</option>
              ))}
            </select>
          </label>
          <label>
            <span>Target</span>
            <select
              value={fridaPackageName}
              onChange={(event) => setFridaPackageName(event.target.value)}
              disabled={Boolean(working)}
            >
              <option value="">Select authorized package</option>
              {authorizedFridaPackages.map((target) => (
                <option key={target} value={target}>{target}</option>
              ))}
            </select>
          </label>
        </div>

        <div className="runtime-instrumentation-actions" aria-label="Frida environment actions">
          <button className="button button-secondary" onClick={() => void handleFridaRun("status")} disabled={!canOperate || Boolean(working)}>
            {working === "frida-status" ? "Checking..." : "Check Frida"}
          </button>
          <button className="button button-secondary" onClick={() => void handleFridaRun("setup")} disabled={!canOperate || Boolean(working)}>
            {working === "frida-setup" ? "Setting up..." : "Setup Frida"}
          </button>
          <button className="button button-secondary" onClick={() => void handleFridaRun("ps")} disabled={!canOperate || Boolean(working)}>
            {working === "frida-ps" ? "Enumerating..." : "Frida PS"}
          </button>
          <button className="button button-secondary" onClick={() => void handleFridaRun("attach")} disabled={!canOperate || Boolean(working)}>
            {working === "frida-attach" ? "Attaching..." : "Attach"}
          </button>
        </div>

        <section className="runtime-proof-controls">
          <div>
            <span className="eyebrow">Built-in proof</span>
            <h3>Frida — Runtime UI Modification Proof</h3>
            <p className="muted">Captures before/after screenshots, UI hierarchy, Frida events, and bounded logcat evidence.</p>
          </div>
          <button className="button button-primary" onClick={() => void handleFridaRun("proof")} disabled={!canOperate || Boolean(working)}>
            {working === "frida-proof" ? "Running Proof..." : "Run UI Modification Proof"}
          </button>
        </section>

        <section className="runtime-custom-script">
          <span className="eyebrow">Custom script</span>
          <textarea
            value={fridaScript}
            onChange={(event) => setFridaScript(event.target.value)}
            maxLength={32768}
            rows={7}
            spellCheck={false}
            placeholder={'Java.perform(function () {\n  send({type: "custom", success: true});\n});'}
            disabled={Boolean(working)}
          />
          <label className="runtime-script-confirmation">
            <input
              type="checkbox"
              checked={fridaScriptConfirmed}
              onChange={(event) => setFridaScriptConfirmed(event.target.checked)}
              disabled={Boolean(working)}
            />
            <span>I confirm this bounded JavaScript may execute inside the selected app process.</span>
          </label>
          <details>
            <summary>Advanced options</summary>
            <div className="runtime-advanced-options">
              <label>
                <span>Mode</span>
                <select value={fridaMode} onChange={(event) => setFridaMode(event.target.value as "attach" | "spawn")} disabled={Boolean(working)}>
                  <option value="attach">Attach</option>
                  <option value="spawn">Spawn</option>
                </select>
              </label>
              <label>
                <span>Timeout (seconds)</span>
                <input type="number" min="1" max="30" value={fridaTimeout} onChange={(event) => setFridaTimeout(Number(event.target.value))} disabled={Boolean(working)} />
              </label>
            </div>
          </details>
          <button className="button button-primary" onClick={() => void handleFridaRun("custom")} disabled={!canOperate || !fridaScriptConfirmed || !fridaScript.trim() || Boolean(working)}>
            {working === "frida-custom" ? "Running JS..." : "Run JS"}
          </button>
        </section>

        {agentRun && isFridaObjective(agentRun.objective) ? (
          <RuntimeInstrumentationResult
            run={agentRun}
            steps={agentSteps}
            artifacts={agentArtifacts}
          />
        ) : null}
      </Card>
        </div>
      </details>
    </div>
  );
}

function AssessmentPlanResult({ plan }: { plan: AssessmentPlan }) {
  const evidenceTypes = Array.from(
    new Set(plan.steps.flatMap((step) => step.evidence_requirements)),
  );
  const capabilityCalls = plan.steps.reduce(
    (total, step) => total + step.required_tools.length,
    0,
  );
  const hypothesisFamilies =
    plan.agentic_capability_preview.allowed_hypothesis_families || [];
  return (
    <section className="planner-result" aria-label="Latest AI assessment plan">
      <div className="planner-result-heading">
        <div>
          <span className="eyebrow">Bounded assessment strategy</span>
          <h3>{plan.steps.length} security experiments for {applicationDisplayName(plan.target_package)}</h3>
        </div>
        <span className={`planner-state planner-state-${plan.status.toLowerCase()}`}>
          {plan.validation_status === "PASSED" && plan.policy_status === "PASSED"
            ? "Security checks passed"
            : plan.status}
        </span>
      </div>

      <div className="plan-auditor-summary">
        <div><strong>{plan.steps.length}</strong><span>Experiments</span></div>
        <div><strong>{hypothesisFamilies.length}</strong><span>Security hypotheses</span></div>
        <div><strong>{capabilityCalls}</strong><span>Estimated capability calls</span></div>
        <div><strong>{evidenceTypes.length}</strong><span>Evidence types</span></div>
      </div>

      <div className="plan-evidence-summary">
        <span>Expected evidence</span>
        <p>{evidenceTypes.length ? evidenceTypes.map(evidenceLabel).join(" · ") : "Bounded tool observations"}</p>
      </div>

      <div className="plan-security-areas">
        <span>Security checks</span>
        <div>
          {hypothesisFamilies.length ? hypothesisFamilies.map((family) => (
            <span key={family}>{hypothesisFamilyLabel(family)}</span>
          )) : <span>Runtime evidence collection</span>}
        </div>
      </div>

      <div className="security-check-list" aria-label="Plan validation summary">
        <span>✓ Target authorization</span>
        <span>✓ Capability policy</span>
        <span>✓ Argument validation</span>
        <span>✓ Resource bounds</span>
      </div>

      {plan.validation_errors.length ? (
        <div className="planner-validation-errors" role="alert">
          <strong>Controlled validation failure</strong>
          <ul>
            {plan.validation_errors.map((message, index) => (
              <li key={`${index}-${message}`}>{message}</li>
            ))}
          </ul>
        </div>
      ) : null}

      <details className="plan-details-disclosure">
        <summary>View Technical Plan</summary>
        <div className="plan-details-content">
          <div className="technical-plan-facts">
            <StatusFact label="Plan ID" value={`#${plan.id}`} />
            <StatusFact label="Provider / model" value={plan.planner_provider} detail={plan.planner_model} />
            <StatusFact label="Validation" value={plan.validation_status} />
            <StatusFact label="Policy" value={plan.policy_status} />
            <StatusFact label="Plan hash" value={plan.plan_hash ? `${plan.plan_hash.slice(0, 16)}…` : "Unavailable"} />
            <StatusFact label="Created" value={formatDate(plan.created_at)} />
          </div>
          <div className="planner-scope-summary">
            <div>
              <span>Assessment objective</span>
              <p>{plan.objective}</p>
            </div>
            <div>
              <span>Authorized scope</span>
              <p>{plan.scope}</p>
            </div>
          </div>
          <ol className="planner-step-list">
            {plan.steps.map((step) => (
              <li key={step.id} className="planner-step">
                <div className="planner-step-heading">
                  <span className="planner-step-sequence">{step.sequence}</span>
                  <div>
                    <span className="eyebrow mono">{step.step_identifier}</span>
                    <h4>{step.objective}</h4>
                  </div>
                  <span className="planner-step-state">{step.status}</span>
                </div>
                <p className="planner-step-rationale">{step.rationale}</p>
                <dl className="planner-step-details">
                  <div>
                    <dt>Allowed capabilities</dt>
                    <dd className="planner-chip-list">
                      {step.required_tools.length ? step.required_tools.map((tool) => (
                        <span key={tool} className="planner-tool-chip mono">{tool}</span>
                      )) : <span className="muted">Observation-only step</span>}
                    </dd>
                  </div>
                  <div><dt>Expected observation</dt><dd>{step.expected_observation}</dd></div>
                  <div><dt>Success condition</dt><dd>{step.success_condition}</dd></div>
                  <div>
                    <dt>Required evidence</dt>
                    <dd className="planner-chip-list">
                      {step.evidence_requirements.map((evidence) => (
                        <span key={evidence} className="planner-evidence-chip">{evidenceLabel(evidence)}</span>
                      ))}
                    </dd>
                  </div>
                  <div><dt>Dependencies</dt><dd>{step.dependencies.length ? step.dependencies.join(", ") : "None"}</dd></div>
                </dl>
                {step.required_tools.length ? (
                  <details className="planner-tool-arguments">
                    <summary>Bounded arguments</summary>
                    <pre>{JSON.stringify(step.tool_arguments, null, 2)}</pre>
                  </details>
                ) : null}
              </li>
            ))}
          </ol>
          <details className="planner-tool-arguments">
            <summary>Provider metadata</summary>
            <pre>{JSON.stringify(plan.provider_metadata, null, 2)}</pre>
          </details>
        </div>
      </details>
    </section>
  );
}

function AssessmentExecutionResult({
  run,
  steps,
  artifacts,
  evidence,
  decisions,
  hypotheses,
  summary,
  canCancel,
  canRetry,
  cancelling,
  retrying,
  onCancel,
  onRetry,
}: {
  run: AgentRun;
  steps: AgentRunStep[];
  artifacts: AgentRunArtifact[];
  evidence: Evidence[];
  decisions: AgentActionDecision[];
  hypotheses: AgentHypothesis[];
  summary: AssessmentRunSummary | null;
  canCancel: boolean;
  canRetry: boolean;
  cancelling: boolean;
  retrying: boolean;
  onCancel: () => void;
  onRetry: () => void;
}) {
  const terminal = ["SUCCEEDED", "FAILED", "TIMEOUT", "CANCELLED", "PAUSED"].includes(run.status);
  const completed = run.status === "SUCCEEDED";
  const maximumDecisions = Number(run.capability_envelope.maximum_decisions || 0);
  const maximumToolCalls = Number(run.capability_envelope.maximum_tool_calls || 0);
  const coverageEntries = Object.entries(run.coverage_state);
  const assessableCoverage = coverageEntries.filter(
    ([, status]) => !status.startsWith("NOT_ASSESSABLE"),
  );
  const assessedCoverage = assessableCoverage.filter(
    ([, status]) => status !== "NOT_STARTED",
  ).length;
  const coveragePercent = assessableCoverage.length
    ? Math.round((assessedCoverage / assessableCoverage.length) * 100)
    : 0;
  const screenshotArtifacts = artifacts.filter(
    (artifact) => artifact.artifact_type === "SCREENSHOT" && artifact.download_url,
  );
  const evidenceGroups = groupEvidence(evidence);
  return (
    <section id="assessment-results" className="planner-execution-result ai-agent-workspace" aria-label="AI Security Agent assessment">
      <div className="ai-agent-header">
        <div>
          <span className="eyebrow">{terminal ? "Assessment results" : "Live adaptive assessment"}</span>
          <h2>{terminal ? (completed ? "Assessment completed" : "Assessment stopped") : "AI Security Agent"}</h2>
          <p>{terminal ? (completed ? "Completed for" : "Stopped for") : "Assessing"} <strong>{applicationDisplayName(run.target_package)}</strong> <span className="mono">{run.target_package}</span></p>
        </div>
        <div className="planner-execution-heading-actions">
          <span className={`agent-run-state state-${run.status.toLowerCase()}`}>
            {agentStatusLabel(run.status)}
          </span>
          {canCancel ? (
            <button className="button button-secondary" onClick={onCancel} disabled={cancelling}>
              {cancelling ? "Cancelling…" : "Cancel Assessment"}
            </button>
          ) : null}
        </div>
      </div>

      <div className="agent-live-metrics" aria-label="Assessment progress">
        <div><span>Decisions</span><strong>{run.decision_count} / {maximumDecisions || "?"}</strong></div>
        <div><span>Actions</span><strong>{run.tool_call_count} / {maximumToolCalls || "?"}</strong></div>
        <div><span>Evidence</span><strong>{evidence.length}</strong></div>
        <div><span>Artifacts</span><strong>{artifacts.length}</strong></div>
        <div><span>Elapsed</span><strong>{formatRunElapsedCompact(run)}</strong></div>
        <div><span>Coverage</span><strong>{coveragePercent}%</strong></div>
      </div>

      {run.failure_message ? (
        <div className="agent-failure-message" role="alert">
          <strong>{agentFailureMessage(run)}</strong>
          {run.pre_execution_failure ? (
            <>
              <p>No device action performed.</p>
              <dl className="pre-execution-failure-facts">
                <div><dt>Provider / model</dt><dd>{run.decision_provider} / {run.decision_model}</dd></div>
                <div><dt>Safe failure category</dt><dd>{providerFailureLabel(run)}</dd></div>
                <div><dt>Approved plan</dt><dd>{run.plan_approval_preserved ? "Approval preserved" : "Approval unavailable"}</dd></div>
              </dl>
              {canRetry ? (
                <button className="button button-primary" onClick={onRetry} disabled={retrying}>
                  {retrying ? "Retrying Adaptive Assessment…" : "Retry Adaptive Assessment"}
                </button>
              ) : null}
              <details className="pre-execution-failure-details"><summary>Advanced details</summary><p>{providerFailureLabel(run)}: {run.result_summary.provider_failure?.code || run.termination_reason}</p></details>
            </>
          ) : (
            <details><summary>Technical details</summary><p>{run.failure_category || "CONTROLLED_FAILURE"}: {run.failure_message}</p></details>
          )}
        </div>
      ) : null}

      {run.execution_mode === "ADAPTIVE_AGENT" ? (
        <section className="agent-activity-section" aria-label="Adaptive agent activity">
          <div className="auditor-section-heading">
            <div><span className="eyebrow">Live activity</span><h3>Agent activity</h3></div>
            <span>{decisions.length} persisted decisions</span>
          </div>
          {decisions.length ? (
            <ol className="agent-activity-timeline">
              {decisions.map((decision) => {
              const hypothesis = hypotheses.find(
                (item) => item.id === decision.hypothesis,
              );
              const step = steps.find((item) => item.id === decision.run_step);
              return (
                <li key={decision.id} className="agent-activity-card">
                  <span className="agent-activity-sequence">{decision.sequence}</span>
                  <div className="agent-activity-content">
                    <div><span>Hypothesis</span><strong>{hypothesis?.title || hypothesisFamilyLabel(decision.hypothesis_identifier || "bounded_runtime")}</strong></div>
                    <div><span>AI decision</span><p>{decision.rationale_summary}</p></div>
                    {decision.tool_name ? (
                      <div><span>Action</span><p><strong>{humanActionLabel(decision.tool_name)}</strong><small className="mono">{decision.tool_name}</small></p></div>
                    ) : null}
                    <div><span>Observation</span><p>{observationSummary(step, decision)}</p></div>
                    {hypothesis?.oracle_result.safe_summary ? (
                      <div><span>Oracle result</span><p>{hypothesis.oracle_result.safe_summary}</p></div>
                    ) : null}
                  </div>
                  <span className={`agent-step-status state-${decision.execution_status.toLowerCase()}`}>
                    {decision.execution_status === "REJECTED" ? "REJECTED" : decision.decision_type === "TOOL_ACTION" ? decision.execution_status : decision.decision_type}
                  </span>
                </li>
              );
              })}
            </ol>
          ) : (
            <div className="agent-waiting-state"><span className="agent-pulse" aria-hidden="true" /><strong>Preparing the first bounded decision</strong><p>The agent is loading the approved state and capability envelope.</p></div>
          )}
        </section>
      ) : null}

      <section className="coverage-section" aria-labelledby="coverage-title">
        <div className="auditor-section-heading"><div><span className="eyebrow">Truthful backend state</span><h3 id="coverage-title">Security coverage</h3></div><span>{coveragePercent}% of assessable areas touched</span></div>
        <div className="coverage-grid">
          {coverageEntries.map(([area, status]) => (
            <div key={area} className={`coverage-item coverage-${coverageTone(status)}`}>
              <span>{coverageAreaLabel(area)}</span>
              <strong>{coverageStatusLabel(status)}</strong>
            </div>
          ))}
        </div>
      </section>

      <section id="assessment-evidence" className="live-evidence-section" aria-labelledby="evidence-title">
        <div className="auditor-section-heading"><div><span className="eyebrow">Persisted evidence</span><h3 id="evidence-title">Live evidence</h3></div><span>{evidence.length} records · {artifacts.length} artifacts</span></div>
        {screenshotArtifacts.length ? (
          <div className="live-screenshot-strip">
            {screenshotArtifacts.slice(-3).map((artifact) => (
              <a key={artifact.id} href={artifact.download_url} target="_blank" rel="noreferrer">
                <img src={artifact.download_url} alt={artifact.name} />
                <span>{artifact.name}</span>
              </a>
            ))}
          </div>
        ) : null}
        {evidence.length ? (
          <div className="evidence-group-grid">
            {Object.entries(evidenceGroups).map(([group, items]) => (
              <section key={group}>
                <h4>{group}</h4>
                {items.slice(-3).reverse().map((item) => (
                  <article key={item.id}>
                    <strong>{evidenceLabel(item.evidence_type)}</strong>
                    <p>{boundedPreview(item.snippet || "Structured evidence metadata recorded.")}</p>
                    <small>{formatDate(item.created_at)} · {item.redacted ? "Redacted" : "Bounded"}</small>
                  </article>
                ))}
              </section>
            ))}
          </div>
        ) : <div className="agent-waiting-state"><strong>No evidence yet</strong><p>Evidence appears here after permitted gateway actions complete.</p></div>}
        {(evidence.length > 3 || artifacts.length) ? (
          <details className="assessment-evidence-disclosure">
            <summary>View All Evidence</summary>
            <div className="assessment-evidence-grid">
              <section><h4>Evidence ({evidence.length})</h4><ul>{evidence.map((item) => <li key={item.id}><strong>{evidenceLabel(item.evidence_type)}</strong><span>{item.source}</span><small>{boundedPreview(item.snippet || "Structured evidence metadata recorded.")}</small></li>)}</ul></section>
              <section><h4>Artifacts ({artifacts.length})</h4><ul>{artifacts.map((artifact) => <li key={artifact.id}><strong>{artifact.name}</strong><span>{artifact.artifact_type} · {artifact.content_type}</span>{artifact.download_url ? <a href={artifact.download_url} target="_blank" rel="noreferrer">Open artifact</a> : <small>Metadata only</small>}</li>)}</ul></section>
            </div>
          </details>
        ) : null}
      </section>

      <section className="oracle-results-section" aria-labelledby="oracle-title">
        <div className="auditor-section-heading"><div><span className="eyebrow">Deterministic evaluation</span><h3 id="oracle-title">Security evaluation</h3></div><span>Not GPT conclusions</span></div>
        <div className="oracle-result-grid">
          {hypotheses.map((hypothesis) => (
            <article key={hypothesis.id}>
              <span>{hypothesis.title}</span>
              <strong className={`oracle-${hypothesis.status.toLowerCase()}`}>{hypothesis.status}</strong>
              <p>{hypothesis.oracle_result.safe_summary || "Awaiting sufficient deterministic evidence."}</p>
            </article>
          ))}
        </div>
      </section>

      {terminal ? (
        <section className="assessment-results-dashboard" aria-labelledby="results-title">
          <div className="auditor-section-heading"><div><span className="eyebrow">Final deterministic results</span><h3 id="results-title">Assessment results</h3></div><span>{summary?.run_finding_count || 0} related findings</span></div>
          <div className="results-metric-grid">
            <StatusFact label="Duration" value={formatRunElapsed(run)} />
            <StatusFact label="Decisions" value={String(run.decision_count)} />
            <StatusFact label="Actions" value={String(run.tool_call_count)} />
            <StatusFact label="Evidence" value={String(evidence.length)} />
            <StatusFact label="Findings" value={String(summary?.run_finding_count ?? 0)} />
            <StatusFact label="Risk" value={summary?.risk.score === null || summary?.risk.score === undefined ? "Unavailable" : `${summary.risk.score}/100`} detail={summary?.risk.severity} />
            <StatusFact label="MASVS" value={summary?.compliance.score === null || summary?.compliance.score === undefined ? "Unavailable" : `${summary.compliance.score}%`} />
          </div>
          {summary?.run_findings.length ? (
            <div className="result-finding-list">
              {summary.run_findings.map((finding) => (
                <article key={finding.id} className={`result-finding severity-${finding.severity.toLowerCase()}`}>
                  <span>{finding.severity}</span><h4>{finding.title}</h4><p>{finding.rule_id} · {finding.status} · {finding.confidence} confidence</p>
                </article>
              ))}
            </div>
          ) : <p className="muted">No deterministic runtime finding was supported by this bounded evidence set.</p>}
          <div className="results-action-row">
            <Link className="button button-secondary" to={`/findings?audit=${run.audit}`}>View Findings</Link>
            {summary?.report.status === "READY" ? <Link className="button button-primary" to={`/audits/${summary.audit_id}/report`}>View Assessment Report</Link> : <span className="report-state">Report: {summary?.report.status || "Generating"}</span>}
          </div>
          <div className="provenance-path" aria-label="Finding provenance">
            <span>AI experiment</span><b>→</b><span>Tool action</span><b>→</b><span>Observation</span><b>→</b><span>Evidence</span><b>→</b><span>Deterministic oracle</span><b>→</b><span>Finding</span>
          </div>
        </section>
      ) : null}

      <details className="technical-run-details">
        <summary>Technical Run Details</summary>
        <div className="technical-plan-facts">
          <StatusFact label="AgentRun" value={`#${run.id}`} />
          <StatusFact label="Mode" value={run.execution_mode} />
          <StatusFact label="Provider / model" value={run.decision_provider} detail={run.decision_model} />
          <StatusFact label="Provider calls" value={String(run.model_call_count)} />
          <StatusFact label="Envelope hash" value={`${run.capability_envelope_hash.slice(0, 16)}…`} />
          <StatusFact label="Termination" value={run.termination_reason || "In progress"} />
        </div>
        <ol className="agent-step-list planner-execution-timeline">
          {steps.map((step) => (
            <li key={step.id}><span className="agent-step-sequence">{step.sequence_number}</span><div><span className="eyebrow mono">{step.plan_step_identifier}</span><strong className="mono">{step.is_control_step ? "Plan observation" : step.tool_name}</strong><small>{step.duration_seconds === null ? "Not started" : formatDuration(step.duration_seconds)} · {evidence.filter((item) => item.agent_run_step === step.id).length} evidence records</small>{step.failure_message ? <small>{step.failure_message}</small> : null}</div><span className={`agent-step-status state-${step.status.toLowerCase()}`}>{step.status}</span></li>
          ))}
        </ol>
      </details>

      {summary?.run_findings.length ? (
        <div className="planner-scope-summary technical-authority-note">
          <div>
            <span>Findings authority</span>
            <p>Deterministic backend rules and oracles only.</p>
          </div>
          <div>
            <span>Execution boundary</span>
            <p>Every selected action passed schema, policy, envelope, budget, and Tool Gateway authorization.</p>
          </div>
        </div>
      ) : null}
    </section>
  );
}

function RuntimeInstrumentationResult({
  run,
  steps,
  artifacts,
}: {
  run: AgentRun;
  steps: AgentRunStep[];
  artifacts: AgentRunArtifact[];
}) {
  const summary = run.result_summary;
  const actionResult = summary.result || {};
  const beforeArtifact = artifacts.find(
    (artifact) => artifact.name === "frida-before-screenshot.png",
  );
  const afterArtifact = artifacts.find(
    (artifact) => artifact.name === "frida-after-screenshot.png",
  );
  const isAction = run.objective === "FRIDA_RUNTIME_ACTION";
  const clientVersion = isAction
    ? metadataString(actionResult.frida_client_version) ||
      metadataString((actionResult.after_state as Record<string, unknown> | undefined)?.frida_client_version)
    : summary.frida_client_version || "";
  const serverVersion = isAction
    ? metadataString(actionResult.frida_server_version) ||
      metadataString((actionResult.after_state as Record<string, unknown> | undefined)?.frida_server_version)
    : summary.frida_server_version || "";

  return (
    <div className="runtime-result" aria-label="Runtime instrumentation result">
      <div className="agent-run-heading">
        <div>
          <span className="eyebrow">Runtime instrumentation</span>
          <h3>{objectiveLabel(run.objective)} #{run.id}</h3>
        </div>
        <span className={`agent-run-state state-${run.status.toLowerCase()}`}>
          {run.status}
        </span>
      </div>

      <div className="dynamic-device-facts agent-result-facts">
        <StatusFact label="Target" value={summary.package_name || "Unavailable"} />
        <StatusFact label="PID" value={String(summary.pid ?? actionResult.pid ?? actionResult.target_pid ?? "Unavailable")} />
        <StatusFact label="Frida client" value={clientVersion || "Unavailable"} state={clientVersion ? "online" : "offline"} />
        <StatusFact label="Frida server" value={serverVersion || "Unavailable"} state={serverVersion ? "online" : "offline"} />
        <StatusFact label="Version agreement" value={yesNo(Boolean(actionResult.version_agreement || (actionResult.verification as Record<string, unknown> | undefined)?.version_agreement || (clientVersion && clientVersion === serverVersion)))} />
        <StatusFact label="Attach" value={summary.attach_succeeded || actionResult.attach_capability || actionResult.attach_event_received ? "Success" : "Not confirmed"} state={summary.attach_succeeded || actionResult.attach_capability || actionResult.attach_event_received ? "online" : "offline"} />
        {summary.operation === "ps" ? (
          <StatusFact label="Process count" value={String(actionResult.process_count ?? 0)} state={Number(actionResult.process_count || 0) > 0 ? "online" : "offline"} />
        ) : null}
        {!isAction ? (
          <>
            <StatusFact label="Script execution" value={summary.execution_succeeded ? "Success" : "Failed"} state={summary.execution_succeeded ? "online" : "offline"} />
            <StatusFact label="Frida event" value={summary.frida_event_received ? "UI modification confirmed" : `${summary.event_count ?? 0} bounded events`} state={summary.frida_event_received || (summary.event_count || 0) > 0 ? "online" : "warning"} />
            <StatusFact label="Visual state changed" value={yesNo(summary.visual_state_changed)} state={summary.visual_state_changed ? "online" : "offline"} />
            <StatusFact label="Cleanup" value={summary.cleanup_state || "Unavailable"} />
          </>
        ) : null}
      </div>

      {summary.frida_event_received ? (
        <p className="alert alert-success">Frida event: UI modification confirmed.</p>
      ) : null}
      {run.failure_message ? (
        <p className="agent-failure-message">{run.failure_category}: {run.failure_message}</p>
      ) : null}

      {!isAction ? (
        <>
          <div className="runtime-screenshot-comparison">
            <ScreenshotPreview label="Before screenshot" artifact={beforeArtifact} digest={summary.before_screenshot?.sha256} />
            <ScreenshotPreview label="After screenshot" artifact={afterArtifact} digest={summary.after_screenshot?.sha256} />
          </div>
          <div className="runtime-ui-comparison">
            <AgentUiEvidence summary={summary.before_ui} />
            <AgentUiEvidence summary={summary.after_ui} />
          </div>
          <AgentLogcatEvidence summary={summary.logcat} />
        </>
      ) : null}

      <section className="agent-step-card" aria-label="Runtime instrumentation steps">
        <div className="agent-subsection-heading">
          <h3>Evidence timeline</h3>
          <span>{steps.filter((step) => step.status === "SUCCEEDED").length} / {steps.length} succeeded</span>
        </div>
        <ol className="agent-step-list">
          {steps.map((step) => (
            <li key={step.id}>
              <span className="agent-step-sequence">{step.sequence_number}</span>
              <div>
                <strong className="mono">{step.tool_name}</strong>
                {step.failure_message ? <small>{step.failure_message}</small> : null}
              </div>
              <span className={`agent-step-status state-${step.status.toLowerCase()}`}>{step.status}</span>
            </li>
          ))}
        </ol>
      </section>

      <p className="agent-result-summary">
        {summary.interpretation || (isAction ? "The requested real Frida environment action completed." : "Runtime instrumentation evidence was captured.")}
      </p>
      <p className="muted agent-scope-note">
        {summary.limitations || summary.assessment_scope || "Runtime evidence only; no vulnerability verdict was produced."}
      </p>
    </div>
  );
}

function ScreenshotPreview({
  label,
  artifact,
  digest,
}: {
  label: string;
  artifact?: AgentRunArtifact;
  digest?: string;
}) {
  return (
    <section className="agent-evidence-card runtime-screenshot-card">
      <div className="agent-subsection-heading">
        <h3>{label}</h3>
        <span>{artifact?.content_type || "image/png"}</span>
      </div>
      {artifact?.download_url ? (
        <img src={artifact.download_url} alt={label} />
      ) : (
        <div className="screenshot-placeholder">Preview unavailable</div>
      )}
      <p className="mono runtime-digest">{digest || metadataString(artifact?.metadata.sha256) || "Digest unavailable"}</p>
    </section>
  );
}

function StatusFact({
  label,
  value,
  detail,
  state = "neutral",
}: {
  label: string;
  value: string;
  detail?: string;
  state?: "online" | "offline" | "warning" | "neutral";
}) {
  return (
    <div className={`dynamic-status-fact state-${state}`}>
      <span>{label}</span>
      <strong>{value}</strong>
      {detail ? <small>{detail}</small> : null}
    </div>
  );
}

function AgentEvidenceCard({ artifact }: { artifact?: AgentRunArtifact }) {
  if (!artifact) {
    return (
      <section className="agent-evidence-card" aria-label="Agent run evidence">
        <h3>Screenshot evidence</h3>
        <p className="muted">No screenshot metadata was produced for this run.</p>
      </section>
    );
  }

  const width = metadataNumber(artifact.metadata.width);
  const height = metadataNumber(artifact.metadata.height);
  const sizeBytes = metadataNumber(artifact.metadata.size_bytes);
  const digest = metadataString(artifact.metadata.sha256);
  const capturedAt = metadataString(artifact.metadata.captured_at);

  return (
    <section className="agent-evidence-card" aria-label="Agent run evidence">
      <div className="agent-subsection-heading">
        <h3>Screenshot evidence</h3>
        <span>{artifact.content_type}</span>
      </div>
      <dl>
        <div>
          <dt>Dimensions</dt>
          <dd>{width && height ? `${width} × ${height}` : "Not detected"}</dd>
        </div>
        <div>
          <dt>Size</dt>
          <dd>{sizeBytes === null ? "Unavailable" : formatBytes(sizeBytes)}</dd>
        </div>
        <div>
          <dt>Captured</dt>
          <dd>{formatDate(capturedAt || null)}</dd>
        </div>
        <div className="agent-evidence-digest">
          <dt>SHA-256</dt>
          <dd className="mono">{digest || "Unavailable"}</dd>
        </div>
      </dl>
      <p className="muted agent-scope-note">
        Validated metadata and the digest are retained; screenshot bytes are stored
        through the managed artifact service rather than inline in PostgreSQL.
      </p>
    </section>
  );
}

function AgentUiEvidence({
  summary,
}: {
  summary: AgentRun["result_summary"]["ui_dump"];
}) {
  return (
    <section className="agent-evidence-card" aria-label="UI hierarchy evidence">
      <div className="agent-subsection-heading">
        <h3>UI hierarchy summary</h3>
        <span>{summary?.node_count ?? 0} nodes</span>
      </div>
      <p className="agent-result-summary">
        Focused package: <span className="mono">{summary?.focused_package || "Unavailable"}</span>
      </p>
      <EvidenceValues label="Sample visible text" values={summary?.text_values} />
      <EvidenceValues label="Sample resource IDs" values={summary?.resource_ids} mono />
      <p className="muted agent-scope-note">
        Raw hierarchy XML is bounded and is not displayed by default. SHA-256: {summary?.xml_sha256 || "Unavailable"}
      </p>
    </section>
  );
}

function AgentLogcatEvidence({
  summary,
}: {
  summary?: {
    line_count?: number | null;
    lines?: string[];
    redaction_applied?: boolean;
  };
}) {
  return (
    <section className="agent-evidence-card agent-logcat-card" aria-label="Logcat evidence">
      <div className="agent-subsection-heading">
        <h3>Bounded logcat excerpt</h3>
        <span>{summary?.line_count ?? 0} lines</span>
      </div>
      <pre>{summary?.lines?.length ? summary.lines.join("\n") : "No bounded log lines were returned."}</pre>
      <p className="muted agent-scope-note">
        Redaction applied: {yesNo(summary?.redaction_applied)}. Output is capped at 100 lines.
      </p>
    </section>
  );
}

function EvidenceValues({
  label,
  values = [],
  mono = false,
}: {
  label: string;
  values?: string[];
  mono?: boolean;
}) {
  return (
    <div className="agent-evidence-values">
      <strong>{label}</strong>
      <p className={mono ? "mono" : undefined}>
        {values.length ? values.slice(0, 12).join(" · ") : "None reported"}
      </p>
    </div>
  );
}

function ServiceIndicator({
  label,
  component,
}: {
  label: string;
  component?: SystemComponent;
}) {
  const state =
    component?.status === "OPERATIONAL"
      ? "online"
      : component?.status === "DEGRADED"
        ? "warning"
        : component?.status === "DISABLED"
          ? "neutral"
          : "offline";
  return (
    <span className={`service-indicator state-${state}`} title={component?.message}>
      <i aria-hidden="true" />
      {label}: {component?.status === "OPERATIONAL" ? "Online" : component?.status || "Unavailable"}
    </span>
  );
}

function applicationDisplayName(packageName: string): string {
  if (packageName === "owasp.sat.agoat") return "OWASP AndroGoat";
  if (!packageName) return "Authorized Android application";
  const leaf = packageName.split(".").at(-1) || packageName;
  return leaf.charAt(0).toUpperCase() + leaf.slice(1);
}

function modelDisplayName(model: string): string {
  return {
    "gpt-5.6-luna": "GPT-5.6 Luna",
    "gpt-5.6-terra": "GPT-5.6 Terra",
    "gpt-5.5": "GPT-5.5",
  }[model] || model;
}

function hypothesisFamilyLabel(value: string): string {
  return {
    SENSITIVE_LOG_EXPOSURE: "Sensitive logging",
    APPLICATION_RUNTIME_STABILITY: "Runtime stability",
    UI_SENSITIVE_DATA_EXPOSURE: "Sensitive UI exposure",
    RUNTIME_TAMPERING_RESILIENCE: "Runtime tampering",
    sensitive_log_exposure: "Sensitive logging",
    application_runtime_stability: "Runtime stability",
    ui_sensitive_data_exposure: "Sensitive UI exposure",
    runtime_tampering_resilience: "Runtime tampering",
  }[value] || evidenceLabel(value);
}

function humanActionLabel(toolName: string): string {
  return {
    get_device_status: "Check device readiness",
    list_packages: "Confirm authorized applications",
    launch_package: "Launch AndroGoat",
    force_stop_package: "Close target application",
    take_screenshot: "Capture screenshot",
    start_logcat: "Start bounded log observation",
    stop_logcat: "Stop bounded log observation",
    get_logcat_excerpt: "Inspect runtime logs",
    dump_ui: "Inspect application interface",
    tap_coordinates: "Perform approved UI interaction",
    type_text: "Enter approved test input",
    frida_status: "Check runtime instrumentation",
    frida_ps: "Inspect target process state",
    frida_attach: "Attach approved instrumentation",
    frida_run_js: "Run controlled instrumentation proof",
  }[toolName] || evidenceLabel(toolName);
}

function observationSummary(
  step: AgentRunStep | undefined,
  decision: AgentActionDecision,
): string {
  if (!step) {
    if (decision.execution_status === "REJECTED") {
      return "No action or observation was produced because backend validation rejected the decision.";
    }
    if (decision.decision_type === "COMPLETE") {
      return "The agent determined that no further non-redundant permitted experiment was needed.";
    }
    if (decision.decision_type === "NEEDS_AUDITOR") {
      return "The assessment paused safely for auditor input.";
    }
    return decision.execution_status === "RUNNING"
      ? "Waiting for the permitted action to return a bounded observation."
      : "No persisted observation is available yet.";
  }
  const output = step.output_summary || {};
  if (step.status !== "SUCCEEDED") {
    return step.failure_message || "The permitted action did not produce a successful observation.";
  }
  if (step.tool_name === "get_device_status") {
    return `Android ${metadataString(output.android_version) || "emulator"} is ${output.ready ? "ready" : "not ready"}; target authorization remains bounded to this run.`;
  }
  if (step.tool_name === "launch_package") {
    return output.launched
      ? "The authorized target launched and is now available for the next experiment."
      : "The target launch result was persisted for follow-up evaluation.";
  }
  if (step.tool_name === "dump_ui") {
    return `${metadataNumber(output.node_count) ?? 0} bounded UI nodes were captured for the authorized target.`;
  }
  if (step.tool_name === "get_logcat_excerpt") {
    return `${metadataNumber(output.line_count) ?? 0} target-correlated log lines were captured with redaction applied.`;
  }
  if (step.tool_name === "start_logcat") {
    return "A run-scoped bounded log observation window was started.";
  }
  if (step.tool_name === "stop_logcat") {
    return "The run-scoped log observation window closed cleanly.";
  }
  if (step.tool_name === "frida_status") {
    return output.frida_server_reachable
      ? "Approved runtime instrumentation is reachable for the authorized target."
      : "Runtime instrumentation availability was recorded as unavailable.";
  }
  if (step.tool_name === "frida_run_js") {
    return `${metadataNumber(output.event_count) ?? 0} controlled runtime events were recorded with cleanup state preserved.`;
  }
  if (step.tool_name === "take_screenshot") {
    return "A managed screenshot artifact was captured and persisted.";
  }
  return "The permitted action completed and its bounded observation was persisted.";
}

function agentStatusLabel(status: AgentRun["status"]): string {
  return {
    QUEUED: "Starting",
    RUNNING: "Assessing",
    PAUSED: "Waiting",
    SUCCEEDED: "Completed",
    FAILED: "Failed",
    CANCELLED: "Cancelled",
    TIMEOUT: "Timed out",
  }[status];
}

function agentFailureMessage(run: AgentRun): string {
  if (run.pre_execution_failure) {
    return "AI assessment could not start. No Android actions were executed.";
  }
  if (run.termination_reason === "PROVIDER_FAILURE") {
    return "AI assessment reasoning could not continue.";
  }
  if (run.termination_reason === "DECISION_SECURITY_REJECTED") {
    return "The AI assessment decision did not pass the authorized security checks.";
  }
  if (run.termination_reason.includes("GATEWAY") || run.failure_category.includes("TOOL")) {
    return "A permitted assessment action failed.";
  }
  if (run.termination_reason.includes("RUNTIME")) {
    return "Android lab execution became unavailable.";
  }
  return "The assessment stopped safely before completion.";
}

function providerFailureLabel(run: AgentRun): string {
  const code = run.result_summary.provider_failure?.code || "";
  return code.includes("SCHEMA")
    ? "AI schema failure · rejected before execution"
    : "AI provider failure · rejected before execution";
}

function assessmentFailureMessage(
  error: unknown,
  stage: "planning" | "policy" | "approval" | "execution",
): string {
  const detail = errorMessage(error);
  const normalized = detail.toLowerCase();
  if (normalized.includes("policy") || normalized.includes("scope")) {
    return "The proposed plan exceeded the authorized assessment scope.";
  }
  if (normalized.includes("device") || normalized.includes("runtime unavailable")) {
    return "Android lab is unavailable.";
  }
  if (normalized.includes("gateway") || normalized.includes("tool execution")) {
    return "A permitted assessment action failed.";
  }
  if (normalized.includes("provider") || normalized.includes("openai")) {
    if (normalized.includes("schema") && normalized.includes("no request")) {
      return "AI schema is not compatible with the provider. No request was sent.";
    }
    return stage === "planning"
      ? "AI planning could not be completed."
      : "AI assessment reasoning could not continue.";
  }
  return {
    planning: "AI planning could not be completed.",
    policy: "The assessment could not pass the authorized security checks.",
    approval: "The assessment approval could not be recorded.",
    execution: "The security assessment could not be started.",
  }[stage];
}

function coverageAreaLabel(area: string): string {
  return {
    device_runtime_readiness: "Runtime readiness",
    application_interaction: "Application interaction",
    ui_exposure: "UI exposure",
    logging: "Logging",
    runtime_instrumentation: "Runtime instrumentation",
    runtime_stability: "Runtime stability",
    network_tls: "Network / TLS",
    local_storage: "Local storage",
    authentication_authorization: "Authentication / authorization",
  }[area] || evidenceLabel(area);
}

function coverageStatusLabel(status: string): string {
  return status === "NOT_ASSESSABLE_WITH_CURRENT_CAPABILITIES"
    ? "Not assessable"
    : evidenceLabel(status);
}

function coverageTone(status: string): string {
  if (status === "ASSESSED") return "assessed";
  if (status === "IN_PROGRESS") return "progress";
  if (status.startsWith("NOT_ASSESSABLE")) return "unavailable";
  if (["INCONCLUSIVE", "BLOCKED"].includes(status)) return "warning";
  return "pending";
}

function groupEvidence(evidence: Evidence[]): Record<string, Evidence[]> {
  const groups: Record<string, Evidence[]> = {};
  for (const item of evidence) {
    const type = item.evidence_type.toLowerCase();
    const group = type.includes("screenshot")
      ? "Screenshots"
      : type.includes("ui")
        ? "UI observations"
        : type.includes("log")
          ? "Logs"
          : type.includes("frida") || type.includes("runtime")
            ? "Runtime / Frida"
            : "Other";
    groups[group] = [...(groups[group] || []), item];
  }
  return groups;
}

function boundedPreview(value: string): string {
  return value.length > 220 ? `${value.slice(0, 217)}…` : value;
}

function componentById(
  components: SystemComponent[] | undefined,
  id: string,
): SystemComponent | undefined {
  return components?.find((component) => component.id === id);
}

function packageActionLabel(action: PackageAction): string {
  return {
    "launch-package": "Launch",
    "force-stop": "Force Stop",
    "clear-data": "Clear Data",
    uninstall: "Uninstall",
  }[action];
}

function yesNo(value: boolean | undefined): string {
  return value ? "Yes" : "No";
}

function evidenceLabel(value: string): string {
  return value
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function objectiveLabel(value: AgentObjective): string {
  return {
    DEVICE_READINESS_CHECK: "Device Readiness Check",
    BASIC_APP_INTERACTION_CHECK: "Basic App Interaction Check",
    FRIDA_RUNTIME_ACTION: "Frida Environment Action",
    FRIDA_RUNTIME_UI_MODIFICATION_PROOF: "Frida Runtime UI Modification Proof",
    FRIDA_CUSTOM_SCRIPT: "Custom Frida Script",
    ASSESSMENT_PLAN_EXECUTION: "Approved Assessment Plan",
  }[value];
}

function isFridaObjective(value: AgentObjective): boolean {
  return value === "FRIDA_RUNTIME_ACTION" ||
    value === "FRIDA_RUNTIME_UI_MODIFICATION_PROOF" ||
    value === "FRIDA_CUSTOM_SCRIPT";
}

function runtimeTypeLabel(
  value: AgentRuntimeType | null | undefined,
): string {
  return value === "CONTAINER_SANDBOX"
    ? "Container Sandbox"
    : value === "INTERNAL_CONTROLLER"
      ? "Internal Controller"
      : "Unavailable";
}

function isolationLabel(value: string | null | undefined): string {
  return {
    INTERNAL_ONLY: "Internal process",
    CONTAINER_PLANNED: "Container planned",
    CONTAINER_ISOLATED: "Ephemeral container",
  }[value || ""] || "Unavailable";
}

function deviceIdentity(run: AgentRun): string {
  const device = run.result_summary.device;
  if (!device) return "Unavailable";
  const values = [
    device.android_version || "Android unknown",
    device.api_level === null ? "API unknown" : `API ${device.api_level}`,
    device.abi || "ABI unknown",
  ];
  return values.join(" / ");
}

function formatDuration(value: number | null): string {
  return value === null ? "Unavailable" : `${value.toFixed(3)} s`;
}

function formatRunElapsed(run: AgentRun): string {
  if (run.duration_seconds !== null) return formatDuration(run.duration_seconds);
  if (!run.started_at) return "Not started";
  const elapsedSeconds = Math.max(0, (Date.now() - new Date(run.started_at).getTime()) / 1000);
  return `${elapsedSeconds.toFixed(1)} s`;
}

function formatRunElapsedCompact(run: AgentRun): string {
  const seconds = Math.max(
    0,
    Math.round(
      run.duration_seconds ??
        (run.started_at
          ? (Date.now() - new Date(run.started_at).getTime()) / 1000
          : 0),
    ),
  );
  const minutes = Math.floor(seconds / 60);
  return `${String(minutes).padStart(2, "0")}:${String(seconds % 60).padStart(2, "0")}`;
}

function metadataString(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function metadataNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function formatBytes(value: number): string {
  if (value < 1024) return `${value} B`;
  return `${(value / 1024).toFixed(1)} KiB`;
}
