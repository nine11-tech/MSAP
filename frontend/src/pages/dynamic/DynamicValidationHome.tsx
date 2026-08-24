import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import {
  approveFridaScriptProposal,
  approveFindingValidationMission,
  downloadPdfReport,
  generateFridaScriptProposal,
  getCorrelationCapabilityGaps,
  getDynamicHostAgentStatus,
  getFindingValidationMission,
  getFindingValidationTimeline,
  getOpenAIBudgetStatus,
  listFridaScriptProposals,
  listAgentRunArtifacts,
  listApkFiles,
  listAudits,
  listFindingValidationEvidence,
  listFindings,
  rejectFridaScriptProposal,
  resumeAdaptiveAgentRun,
  startCorrelationPlaybook,
  startCorrelationCandidatePoc,
  startFindingValidationMission,
  startStaticDynamicCorrelation,
} from "../../api/msap";
import type {
  AgentRunArtifact,
  Audit,
  CapabilityGapEntry,
  CapabilityGapReport,
  CorrelationCandidate,
  CorrelationClassification,
  Evidence,
  FridaScriptProposal,
  FindingValidationMission,
  FindingValidationTimeline,
  OpenAIBudgetStatus,
  StaticDynamicCorrelation,
} from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import {
  Card,
  ErrorMessage,
  LoadingState,
  PageHeader,
  errorMessage,
} from "../../components/Common";

type HomeStage = "target" | "correlating" | "correlated" | "review" | "live" | "conclusion";

type ResultTab = "RECOMMENDED" | "OPTIONAL" | "STATIC" | "NOT_TESTABLE" | "VALIDATED" | "BLOCKED";

const TERMINAL_MISSION_STATUSES = [
  "CONFIRMED",
  "NOT_REPRODUCED",
  "INCONCLUSIVE",
  "BLOCKED",
  "NOT_DYNAMICALLY_TESTABLE",
  "FAILED",
];

const CLASSIFICATION_TABS: {
  key: ResultTab;
  label: string;
  classifications: CorrelationClassification[];
  countField: keyof StaticDynamicCorrelation;
}[] = [
  {
    key: "RECOMMENDED",
    label: "Recommended",
    classifications: ["RECOMMENDED_DYNAMIC_VALIDATION"],
    countField: "recommended_count",
  },
  {
    key: "OPTIONAL",
    label: "Optional",
    classifications: ["OPTIONAL_DYNAMIC_VALIDATION"],
    countField: "optional_count",
  },
  {
    key: "STATIC",
    label: "Static evidence sufficient",
    classifications: ["STATIC_EVIDENCE_SUFFICIENT"],
    countField: "static_sufficient_count",
  },
  {
    key: "NOT_TESTABLE",
    label: "Not testable",
    classifications: ["NOT_TESTABLE_WITH_CURRENT_CAPABILITIES"],
    countField: "not_testable_count",
  },
  {
    key: "VALIDATED",
    label: "Already validated",
    classifications: ["ALREADY_VALIDATED"],
    countField: "already_validated_count",
  },
  {
    key: "BLOCKED",
    label: "Blocked by lab",
    classifications: ["BLOCKED_BY_LAB_CAPABILITY"],
    countField: "blocked_count",
  },
];

const CLASSIFICATION_LABEL: Record<CorrelationClassification, string> = {
  RECOMMENDED_DYNAMIC_VALIDATION: "Recommended dynamic validation",
  OPTIONAL_DYNAMIC_VALIDATION: "Optional dynamic validation",
  STATIC_EVIDENCE_SUFFICIENT: "Static evidence sufficient",
  NOT_TESTABLE_WITH_CURRENT_CAPABILITIES: "Not testable with current capabilities",
  ALREADY_VALIDATED: "Already validated",
  BLOCKED_BY_LAB_CAPABILITY: "Blocked by lab capability",
};

const STEP_STATUS_DISPLAY: Record<string, { icon: string; label: string }> = {
  PLANNED: { icon: "○", label: "Planned" },
  PENDING: { icon: "○", label: "Pending" },
  RUNNING: { icon: "→", label: "Running" },
  SUCCEEDED: { icon: "✓", label: "Succeeded" },
  FAILED: { icon: "✕", label: "Failed" },
  TIMEOUT: { icon: "✕", label: "Timed out" },
  SKIPPED: { icon: "—", label: "Skipped" },
  CANCELLED: { icon: "—", label: "Cancelled" },
};

function severityTone(severity: string): string {
  return severity.toLowerCase().replaceAll(" ", "-");
}

function classificationTone(classification: CorrelationClassification): string {
  return {
    RECOMMENDED_DYNAMIC_VALIDATION: "recommended",
    OPTIONAL_DYNAMIC_VALIDATION: "optional",
    STATIC_EVIDENCE_SUFFICIENT: "static",
    NOT_TESTABLE_WITH_CURRENT_CAPABILITIES: "not-testable",
    ALREADY_VALIDATED: "validated",
    BLOCKED_BY_LAB_CAPABILITY: "blocked",
  }[classification] || "neutral";
}

const TERMINAL_RUN_STATUSES = ["SUCCEEDED", "FAILED", "TIMEOUT", "CANCELLED"];

function titleCaseLabel(value: string): string {
  return value
    .split(/[_\-]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

const EVIDENCE_TYPE_LABELS: Record<string, string> = {
  tool_output: "Tool output",
  ui_hierarchy: "UI hierarchy",
  screenshot: "Screenshot",
  logcat: "Runtime logs",
  frida_events: "Frida events",
  provider_response: "Provider response",
  broadcast_result: "Broadcast result",
  activity_launch: "Activity launch result",
  dynamic_screenshot: "Screenshot",
  dynamic_ui_hierarchy: "UI hierarchy",
  dynamic_logcat_capture: "Runtime log capture",
  dynamic_logcat_excerpt: "Runtime log excerpt",
  dynamic_frida_status: "Frida status",
  dynamic_frida_processes: "Frida process list",
  dynamic_frida_attach: "Frida attach result",
  dynamic_frida_events: "Frida events",
  network_flow: "Network flow summary",
  dynamic_tool_observation: "Tool observation",
  assessment_plan_control_observation: "Plan control observation",
};

const AUDITOR_PLAYBOOKS = [
  {
    id: "ROOT_DETECTION_SCREEN_VALIDATION" as const,
    title: "Root detection manipulation",
    summary:
      "Show AndroGoat reporting a rooted device first, then use approved Frida instrumentation to make the same screen report that the device is not rooted.",
    evidence: [
      "Before screenshot showing Device is rooted",
      "After screenshot showing Device is not rooted",
      "Frida hook events and UI evidence",
    ],
  },
  {
    id: "TLS_PINNING_FRIDA_BYPASS" as const,
    title: "TLS pinning bypass",
    summary:
      "Show the pinned OkHttp request failing to produce a decrypted proxy flow before instrumentation, then bypass pinning with approved Frida hooks and capture the decrypted target-host flow.",
    evidence: [
      "Baseline bounded proxy capture",
      "Bypass bounded proxy flow summary",
      "Frida hook events and exercised UI evidence",
    ],
  },
];

function evidenceTypeLabel(value?: string | null): string {
  const raw = (value || "").trim();
  if (!raw) return "Evidence";
  return EVIDENCE_TYPE_LABELS[raw] || titleCaseLabel(raw);
}

function formatBytes(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return "";
  const size = Number(value);
  if (size < 1024) return `${Math.round(size)} bytes`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KiB`;
  return `${(size / (1024 * 1024)).toFixed(2)} MiB`;
}

function boundedSnippet(value: string | undefined | null): string {
  const text = (value || "").trim();
  if (!text) return "Recorded by the agent with metadata retained.";
  return text.length > 240 ? `${text.slice(0, 240)}…` : text;
}

type EvidenceObservation = {
  data?: Record<string, unknown>;
  tool_name?: string;
  redaction_applied?: boolean;
  truncated?: boolean;
  [key: string]: unknown;
};

function parseEvidenceJson(item: Evidence): EvidenceObservation | null {
  try {
    const parsed = JSON.parse(item.snippet || "");
    if (parsed && typeof parsed === "object") return parsed as EvidenceObservation;
  } catch {
    return null;
  }
  return null;
}

function screenshotMetadata(item: Evidence): Record<string, string> {
  const observation = parseEvidenceJson(item);
  const data =
    observation && observation.data && typeof observation.data === "object"
      ? observation.data
      : {};
  const valueOf = (key: string): string => {
    const value = data[key];
    if (value === null || value === undefined) return "";
    return String(value);
  };
  const rows: Record<string, string> = {};
  const objectReferenceId = valueOf("object_reference_id");
  if (objectReferenceId) rows["Object reference"] = objectReferenceId;
  const sha256 = valueOf("sha256") || item.sha256;
  if (sha256) rows["SHA-256"] = sha256;
  const contentType = valueOf("content_type");
  if (contentType) rows["Content type"] = contentType;
  const width = valueOf("width");
  const height = valueOf("height");
  if (width && height) rows["Dimensions"] = `${width} × ${height}`;
  const sizeBytes = valueOf("size_bytes");
  if (sizeBytes) rows["Size"] = formatBytes(Number(sizeBytes));
  const capturedAt = valueOf("captured_at");
  if (capturedAt) rows["Captured at"] = capturedAt;
  return rows;
}

function humanEvidenceSummary(item: Evidence): string {
  if (item.ai_explanation && item.ai_explanation.trim()) {
    return item.ai_explanation.trim();
  }
  const observation = parseEvidenceJson(item);
  if (!observation) return boundedSnippet(item.snippet);
  const data =
    observation.data && typeof observation.data === "object"
      ? observation.data
      : {};
  if (observation.tool_name === "take_screenshot" || item.evidence_type.includes("screenshot")) {
    const metadata = screenshotMetadata(item);
    if (metadata["Dimensions"] || metadata["Content type"]) {
      const parts = [metadata["Content type"], metadata["Dimensions"]].filter(Boolean);
      const suffix = metadata["SHA-256"]
        ? `SHA-256 ${metadata["SHA-256"].slice(0, 16)}…`
        : "";
      return `Persisted ${parts.join(" · ")} screenshot${suffix ? ` · ${suffix}` : ""}.`;
    }
    return "Persisted screenshot with metadata retained.";
  }
  if (typeof data.line_count === "number") {
    return `${data.line_count} bounded runtime log lines captured.`;
  }
  if (typeof data.event_count === "number") {
    return `${data.event_count} approved runtime events recorded.`;
  }
  if (typeof data.node_count === "number") {
    return `${data.node_count} UI nodes captured.`;
  }
  if (typeof data.launched === "boolean") {
    return data.launched
      ? "The target app was launched and is foregrounded."
      : "The app launch did not complete.";
  }
  if (typeof data.package_name === "string" && typeof data.focused_activity === "string") {
    return `Target state recorded: ${data.package_name} / ${data.focused_activity}.`;
  }
  if (typeof data.screenshot_created === "boolean") {
    return data.screenshot_created
      ? "Screenshot captured."
      : "No screenshot could be captured.";
  }
  return boundedSnippet(item.snippet);
}

function evidenceStatusFromProvenance(item: Evidence): string {
  const provenance =
    item.provenance && typeof item.provenance === "object"
      ? (item.provenance as Record<string, unknown>)
      : {};
  if (typeof provenance.tool === "string" && provenance.tool) {
    return friendlyToolLabel(provenance.tool);
  }
  return "";
}

function friendlyToolLabel(toolName: string): string {
  return {
    get_device_status: "Check device readiness",
    list_packages: "Confirm authorized applications",
    launch_package: "Launch target app",
    force_stop_package: "Close target application",
    take_screenshot: "Capture screenshot",
    start_logcat: "Start bounded log observation",
    stop_logcat: "Stop bounded log observation",
    get_logcat_excerpt: "Inspect runtime logs",
    dump_ui: "Inspect application interface",
    tap_coordinates: "Run approved UI interaction",
    type_text: "Enter approved test input",
    frida_status: "Check runtime instrumentation",
    frida_ps: "Inspect target process state",
    frida_attach: "Attach approved instrumentation",
    frida_run_js: "Run controlled instrumentation proof",
    reset_root_detection_demo: "Reset approved demo state",
    launch_exported_activity: "Launch exported activity",
    send_explicit_broadcast: "Send approved broadcast",
    query_exported_provider: "Query exported provider",
    prepare_root_detection_demo: "Prepare rooted baseline",
    start_proxy_capture: "Start bounded proxy capture",
    stop_proxy_capture: "Stop bounded proxy capture",
    get_proxy_flows: "Inspect bounded proxy flows",
  }[toolName] || toolName;
}

type EvidenceKind = "screenshot" | "ui" | "log" | "tool" | "runtime_event" | "other";

function evidenceKind(item: Evidence): EvidenceKind {
  const type = item.evidence_type || "";
  const tool = parseEvidenceJson(item)?.tool_name;
  if (type.includes("screenshot") || tool === "take_screenshot") return "screenshot";
  if (type.includes("ui_hierarchy")) return "ui";
  if (type.includes("logcat")) return "log";
  if (type.includes("frida")) return "runtime_event";
  if (
    type.includes("tool_output") ||
    type.includes("tool_observation") ||
    type.includes("provider_response") ||
    type.includes("broadcast_result") ||
    type.includes("activity_launch") ||
    type.includes("control_observation")
  ) {
    return "tool";
  }
  return "other";
}

const EVIDENCE_KIND_ORDER: EvidenceKind[] = [
  "screenshot",
  "ui",
  "log",
  "tool",
  "runtime_event",
  "other",
];

function evidenceKindLabel(kind: EvidenceKind, count: number): string {
  const labels: Record<EvidenceKind, [string, string]> = {
    screenshot: ["Screenshot", "Screenshots"],
    ui: ["UI hierarchy", "UI hierarchy"],
    log: ["Runtime log", "Runtime logs"],
    tool: ["Tool observation", "Tool observations"],
    runtime_event: ["Runtime event", "Runtime events"],
    other: ["Other evidence", "Other evidence"],
  };
  return labels[kind][count === 1 ? 0 : 1];
}

function evidenceSummaryCounts(evidence: Evidence[]): Map<EvidenceKind, number> {
  const counts = new Map<EvidenceKind, number>();
  for (const item of evidence) {
    const kind = evidenceKind(item);
    counts.set(kind, (counts.get(kind) || 0) + 1);
  }
  return counts;
}

function shortHash(value: string | null | undefined): string {
  const text = (value || "").trim();
  if (!text) return "";
  return text.length > 16 ? `${text.slice(0, 12)}…${text.slice(-6)}` : text;
}

function observationError(observation: EvidenceObservation | null): string {
  if (!observation) return "";
  const data =
    observation.data && typeof observation.data === "object"
      ? observation.data
      : {};
  for (const key of ["error", "error_message", "failure_message", "message"]) {
    const value = data[key];
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  if (typeof observation.error === "string" && observation.error.trim()) {
    return observation.error.trim();
  }
  return "";
}

function logExcerpt(observation: EvidenceObservation | null): string {
  if (!observation) return "";
  const data =
    observation.data && typeof observation.data === "object"
      ? observation.data
      : {};
  for (const key of ["excerpt", "result_excerpt", "summary", "preview"]) {
    const value = data[key];
    if (typeof value === "string" && value.trim()) {
      const text = value.trim();
      return text.length > 320 ? `${text.slice(0, 320)}…` : text;
    }
  }
  if (Array.isArray(data.lines)) {
    const joined = data.lines
      .slice(0, 12)
      .map(String)
      .join("\n");
    if (joined) return joined.length > 320 ? `${joined.slice(0, 320)}…` : joined;
  }
  return "";
}

function observationData(observation: EvidenceObservation | null): Record<string, unknown> {
  return observation && observation.data && typeof observation.data === "object"
    ? observation.data
    : {};
}

export function DynamicValidationHome() {
  const [audits, setAudits] = useState<Audit[]>([]);
  const [apkFiles, setApkFiles] = useState<{ audit: number; package_name: string }[]>([]);
  const [selectedAuditId, setSelectedAuditId] = useState<number | "">("");
  const [staticFindingCount, setStaticFindingCount] = useState<number | null>(null);
  const [labReady, setLabReady] = useState<boolean | null>(null);
  const [labDetail, setLabDetail] = useState<string>("");
  const [budget, setBudget] = useState<OpenAIBudgetStatus | null>(null);
  const [correlation, setCorrelation] = useState<StaticDynamicCorrelation | null>(null);
  const [gapReport, setGapReport] = useState<CapabilityGapReport | null>(null);
  const [correlating, setCorrelating] = useState(false);
  const [mission, setMission] = useState<FindingValidationMission | null>(null);
  const [nextStep, setNextStep] = useState("");
  const [timeline, setTimeline] = useState<FindingValidationTimeline | null>(null);
  const [evidence, setEvidence] = useState<Evidence[]>([]);
  const [fridaScriptProposals, setFridaScriptProposals] = useState<FridaScriptProposal[]>([]);
  const [activeTab, setActiveTab] = useState<ResultTab>("RECOMMENDED");
  const [loading, setLoading] = useState(true);
  const [working, setWorking] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [pdfUnavailable, setPdfUnavailable] = useState(false);
  const { hasRole } = useAuth();
  const canOperate = hasRole("ADMIN", "ANALYST");
  const pollingRef = useRef<number | null>(null);
  const finalizePollingRef = useRef(false);
  const evidencePanelRef = useRef<HTMLDivElement | null>(null);

  const selectedAudit = audits.find((audit) => audit.id === selectedAuditId);
  const selectedPackage = useMemo(() => {
    if (!selectedAuditId) return "";
    return (
      apkFiles.find((apk) => apk.audit === selectedAuditId)?.package_name || ""
    );
  }, [apkFiles, selectedAuditId]);

  const stage: HomeStage = useMemo(() => {
    if (mission) {
      if (TERMINAL_MISSION_STATUSES.includes(mission.status)) return "conclusion";
      if (mission.status === "RUNNING") return "live";
      return "review";
    }
    if (correlating) return "correlating";
    if (correlation) return "correlated";
    return "target";
  }, [mission, correlating, correlation]);

  const refreshBudget = useCallback(() => {
    getOpenAIBudgetStatus().then(setBudget).catch(() => null);
  }, []);

  const loadWorkspace = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [auditData, apkData, hostData] = await Promise.all([
        listAudits(),
        listApkFiles(),
        getDynamicHostAgentStatus().catch(() => null),
      ]);
      setAudits(auditData);
      setApkFiles(
        apkData.map((apk) => ({
          audit: apk.audit,
          package_name: apk.package_name,
        })),
      );
      setLabReady(Boolean(hostData?.connected && hostData.device?.state === "device"));
      const fridaReady = Boolean(
        hostData?.agent?.frida_client_available &&
          hostData.agent.frida_server_status === "REACHABLE",
      );
      setLabDetail(
        hostData?.connected
          ? hostData.device?.state === "device"
            ? `Emulator ready · ${hostData.device.android_version || "Android"}${fridaReady ? " · Frida ready" : ""}`
            : `Host agent online · emulator ${hostData.device?.state || "unavailable"}`
          : "Host agent offline",
      );
      setSelectedAuditId((current) => {
        if (current && auditData.some((audit) => audit.id === current)) {
          return current;
        }
        return "";
      });
    } catch (requestError) {
      setError(errorMessage(requestError));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadWorkspace();
  }, [loadWorkspace]);

  useEffect(() => {
    refreshBudget();
  }, [refreshBudget]);

  useEffect(() => {
    if (!selectedAuditId) {
      setStaticFindingCount(null);
      return;
    }
    let active = true;
    void listFindings(selectedAuditId)
      .then((findings) => {
        if (active) setStaticFindingCount(findings.length);
      })
      .catch(() => null);
    return () => {
      active = false;
    };
  }, [selectedAuditId]);

  const stopPolling = useCallback(() => {
    if (pollingRef.current !== null) {
      window.clearInterval(pollingRef.current);
      pollingRef.current = null;
    }
  }, []);

  useEffect(() => {
    return stopPolling;
  }, [stopPolling]);

  const refreshLiveState = useCallback(
    async (missionId: number) => {
      try {
        const [currentMission, currentTimeline, currentEvidence] =
          await Promise.all([
            getFindingValidationMission(missionId),
            getFindingValidationTimeline(missionId),
            listFindingValidationEvidence(missionId),
          ]);
        setMission(currentMission);
        setTimeline(currentTimeline);
        setEvidence(currentEvidence);
        if (currentMission.agent_run) {
          void listFridaScriptProposals(currentMission.agent_run)
            .then(setFridaScriptProposals)
            .catch(() => null);
        } else {
          setFridaScriptProposals([]);
        }
        const missionTerminal = TERMINAL_MISSION_STATUSES.includes(
          currentMission.status,
        );
        const runTerminal =
          Boolean(currentMission.agent_run_status) &&
          TERMINAL_RUN_STATUSES.includes(
            currentMission.agent_run_status || "",
          );
        if (missionTerminal || runTerminal) {
          const alreadyFinalized = finalizePollingRef.current;
          finalizePollingRef.current = true;
          stopPolling();
          if (!alreadyFinalized) {
            window.setTimeout(() => {
              void Promise.all([
                getFindingValidationMission(missionId),
                getFindingValidationTimeline(missionId),
                listFindingValidationEvidence(missionId),
              ])
                .then(([finalMission, finalTimeline, finalEvidence]) => {
                  setMission(finalMission);
                  setTimeline(finalTimeline);
                  setEvidence(finalEvidence);
                  if (finalMission.agent_run) {
                    void listFridaScriptProposals(finalMission.agent_run)
                      .then(setFridaScriptProposals)
                      .catch(() => null);
                  }
                })
                .catch(() => null);
            }, 1000);
          }
        }
      } catch (requestError) {
        setError(errorMessage(requestError));
      }
    },
    [stopPolling],
  );

  const startPolling = useCallback(
    (missionId: number) => {
      stopPolling();
      finalizePollingRef.current = false;
      void refreshLiveState(missionId);
      pollingRef.current = window.setInterval(() => {
        void refreshLiveState(missionId);
      }, 2500);
    },
    [refreshLiveState, stopPolling],
  );

  const applyMission = useCallback(
    (nextMission: FindingValidationMission, nextAction: string) => {
      setMission(nextMission);
      setNextStep(nextAction);
      setTimeline(null);
      setEvidence([]);
      setFridaScriptProposals([]);
      if (nextMission.status === "RUNNING") {
        startPolling(nextMission.id);
      } else if (TERMINAL_MISSION_STATUSES.includes(nextMission.status)) {
        finalizePollingRef.current = false;
        void refreshLiveState(nextMission.id);
      }
    },
    [refreshLiveState, startPolling],
  );

  const handleViewEvidence = useCallback(() => {
    if (mission) void refreshLiveState(mission.id);
    window.setTimeout(() => {
      evidencePanelRef.current?.scrollIntoView({
        behavior: "smooth",
        block: "start",
      });
    }, 80);
  }, [mission, refreshLiveState]);

  async function handleStartCorrelation() {
    if (!selectedAuditId || correlating) return;
    setCorrelating(true);
    setError("");
    setNotice("");
    setCorrelation(null);
    setMission(null);
    setFridaScriptProposals([]);
    setGapReport(null);
    setActiveTab("RECOMMENDED");
    try {
      const result = await startStaticDynamicCorrelation(selectedAuditId);
      setCorrelation(result);
      setNotice(
        `MSAP reviewed ${result.total_static_findings} static findings: ${result.recommended_count} recommended for dynamic validation, ${result.not_testable_count} not testable with current capabilities.`,
      );
      void getCorrelationCapabilityGaps(selectedAuditId)
        .then(setGapReport)
        .catch(() => null);
    } catch (requestError) {
      setError(errorMessage(requestError));
    } finally {
      setCorrelating(false);
      refreshBudget();
    }
  }

  async function handleReanalyze() {
    if (!selectedAuditId || correlating) return;
    setCorrelating(true);
    setError("");
    setNotice("");
    try {
      const result = await startStaticDynamicCorrelation(selectedAuditId);
      setCorrelation(result);
      setNotice("Correlation re-run completed with the latest findings and capability state.");
      void getCorrelationCapabilityGaps(selectedAuditId)
        .then(setGapReport)
        .catch(() => null);
    } catch (requestError) {
      setError(errorMessage(requestError));
    } finally {
      setCorrelating(false);
      refreshBudget();
    }
  }

  async function handleStartPoc(candidate: CorrelationCandidate) {
    if (!selectedAuditId || !canOperate) return;
    setWorking(`poc-${candidate.finding_id}`);
    setError("");
    setNotice("");
    try {
      const response = await startCorrelationCandidatePoc(
        selectedAuditId,
        candidate.finding_id,
      );
      applyMission(response.mission, response.next_step);
      if (response.next_step === "not-testable") {
        setNotice("MSAP determined this finding is not dynamically testable with current capabilities.");
      } else if (response.next_step === "approve") {
        setNotice("The PoC mission was generated from the AI plan. Review and approve to execute it.");
      } else if (response.next_step === "run") {
        setNotice("The PoC is approved. Run it to collect live evidence.");
      } else if (response.next_step === "monitor") {
        startPolling(response.mission.id);
      }
    } catch (requestError) {
      setError(errorMessage(requestError));
    } finally {
      setWorking("");
      refreshBudget();
    }
  }

  async function handleStartPlaybook(
    playbookId: "ROOT_DETECTION_SCREEN_VALIDATION" | "TLS_PINNING_FRIDA_BYPASS",
  ) {
    if (!selectedAuditId || !canOperate) return;
    setWorking(`playbook-${playbookId}`);
    setError("");
    setNotice("");
    try {
      const response = await startCorrelationPlaybook(selectedAuditId, playbookId);
      applyMission(response.mission, response.next_step);
      setNotice(
        "The bounded assessment playbook was prepared. Review and approve it before execution.",
      );
    } catch (requestError) {
      setError(errorMessage(requestError));
    } finally {
      setWorking("");
    }
  }

  async function handleViewCandidateEvidence(candidate: CorrelationCandidate) {
    if (!selectedAuditId || !canOperate) return;
    setWorking(`evidence-${candidate.finding_id}`);
    setError("");
    setNotice("");
    try {
      const response = await startCorrelationCandidatePoc(
        selectedAuditId,
        candidate.finding_id,
      );
      applyMission(response.mission, response.next_step);
      await refreshLiveState(response.mission.id);
      handleViewEvidence();
    } catch (requestError) {
      setError(errorMessage(requestError));
    } finally {
      setWorking("");
    }
  }

  async function handleApprovePoc() {
    if (!mission) return;
    setWorking("approve");
    setError("");
    setNotice("");
    try {
      const approved = await approveFindingValidationMission(mission.id);
      setMission(approved);
      setNextStep("run");
      setNotice("PoC approved. Execution remains a separate auditor action.");
    } catch (requestError) {
      setError(errorMessage(requestError));
    } finally {
      setWorking("");
      refreshBudget();
    }
  }

  async function handleRunPoc() {
    if (!mission) return;
    setWorking("run");
    setError("");
    setNotice("");
    try {
      const response = await startFindingValidationMission(mission.id);
      const started = await getFindingValidationMission(response.mission.id);
      setMission(started);
      setNextStep("monitor");
      setNotice("The agent is executing the approved PoC. Evidence appears live.");
      if (started.agent_run) {
        void listFridaScriptProposals(started.agent_run)
          .then(setFridaScriptProposals)
          .catch(() => null);
      }
      startPolling(started.id);
    } catch (requestError) {
      setError(errorMessage(requestError));
    } finally {
      setWorking("");
      refreshBudget();
    }
  }

  async function handleGenerateFridaScriptProposal() {
    if (!mission?.agent_run) return;
    setWorking("frida-generate");
    setError("");
    setNotice("");
    try {
      const proposal = await generateFridaScriptProposal(mission.agent_run);
      setFridaScriptProposals((items) => [
        proposal,
        ...items.filter((item) => item.id !== proposal.id),
      ]);
      setNotice("Frida script proposal generated. Review and approve it before hook execution.");
    } catch (requestError) {
      setError(errorMessage(requestError));
    } finally {
      setWorking("");
      refreshBudget();
    }
  }

  async function handleApproveFridaScriptProposal(proposalId: number) {
    if (!mission?.agent_run) return;
    setWorking(`frida-approve-${proposalId}`);
    setError("");
    setNotice("");
    try {
      const proposal = await approveFridaScriptProposal(mission.agent_run, proposalId);
      setFridaScriptProposals((items) => [
        proposal,
        ...items.filter((item) => item.id !== proposal.id),
      ]);
      setNotice("Frida script approved. Resume the agent when you are ready.");
    } catch (requestError) {
      setError(errorMessage(requestError));
    } finally {
      setWorking("");
    }
  }

  async function handleRejectFridaScriptProposal(proposalId: number) {
    if (!mission?.agent_run) return;
    setWorking(`frida-reject-${proposalId}`);
    setError("");
    setNotice("");
    try {
      const proposal = await rejectFridaScriptProposal(mission.agent_run, proposalId);
      setFridaScriptProposals((items) => [
        proposal,
        ...items.filter((item) => item.id !== proposal.id),
      ]);
      setNotice("Frida script rejected. Generate a revised proposal if instrumentation is still needed.");
    } catch (requestError) {
      setError(errorMessage(requestError));
    } finally {
      setWorking("");
    }
  }

  async function handleResumeAdaptiveRun() {
    if (!mission?.agent_run) return;
    setWorking("frida-resume");
    setError("");
    setNotice("");
    try {
      await resumeAdaptiveAgentRun(mission.agent_run);
      const refreshed = await getFindingValidationMission(mission.id);
      setMission(refreshed);
      setNextStep("monitor");
      setNotice("Agent resumed with the approved assessment boundary.");
      startPolling(mission.id);
    } catch (requestError) {
      setError(errorMessage(requestError));
    } finally {
      setWorking("");
    }
  }

  async function handleDownloadReport() {
    if (!selectedAuditId) return;
    setWorking("report");
    setPdfUnavailable(false);
    setError("");
    try {
      const { blob, filename } = await downloadPdfReport(selectedAuditId);
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = filename || `MSAP_Audit_${selectedAuditId}_Security_Report.pdf`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 5000);
      setNotice("Validation report downloaded.");
    } catch (requestError) {
      setPdfUnavailable(true);
      setNotice("Report is ready as JSON. PDF export is not available yet.");
    } finally {
      setWorking("");
    }
  }

  function handleBackToCandidates() {
    stopPolling();
    finalizePollingRef.current = false;
    setMission(null);
    setTimeline(null);
    setEvidence([]);
    setNextStep("");
  }

  if (loading && !audits.length) {
    return <LoadingState label="Loading Dynamic Validation..." />;
  }

  const timelineItems = timeline?.items || [];
  const completedSteps = timelineItems.filter((item) =>
    ["SUCCEEDED", "FAILED", "TIMEOUT", "SKIPPED", "CANCELLED"].includes(item.status),
  ).length;
  const currentStepIndex = timelineItems.findIndex((item) => item.status === "RUNNING");
  const currentStep = currentStepIndex >= 0 ? timelineItems[currentStepIndex] : null;
  const totalSteps = Math.max(timelineItems.length, 1);

  return (
    <div className="dynamic-home-page">
      <PageHeader
        eyebrow="MSAP · Dynamic validation"
        title="MSAP Dynamic Validation"
        description="Turn static findings into evidence-backed dynamic PoCs."
      />

      {error ? <ErrorMessage message={error} /> : null}
      {notice ? (
        <div className="alert alert-success" role="status">
          {notice}
        </div>
      ) : null}

      <div className="dynamic-home-status-strip" aria-label="Dynamic lab status">
        <span className={`status-pill ${labReady ? "is-online" : "is-offline"}`}>
          <i aria-hidden="true" />Lab {labReady === null ? "checking…" : labReady ? "ready" : "needs attention"}
        </span>
        {selectedAudit ? (
          <span className="status-pill is-neutral">App: {selectedPackage || "Not installed"}</span>
        ) : null}
        {staticFindingCount !== null ? (
          <span className="status-pill is-neutral">
            Audit findings: {staticFindingCount}
          </span>
        ) : null}
        {correlation ? (
          <span className="status-pill is-online">
            Dynamic candidates: {correlation.recommended_count + correlation.optional_count}
          </span>
        ) : null}
        {budget ? (
          <span className="dynamic-home-budget-text" title="Hard backend-enforced AI call budget">
            AI budget {budget.remaining_total_calls}/{budget.max_total_openai_calls}
          </span>
        ) : null}
      </div>

      <Card className="dynamic-home-target-card" title="Step 1 · Audit findings">
        <div className="dynamic-home-target-layout">
          <div className="dynamic-home-target-facts">
            <label className="field-label" htmlFor="demo-audit-select">Audit</label>
            <select
              id="demo-audit-select"
              className="form-select"
              value={selectedAuditId}
              onChange={(event) => setSelectedAuditId(Number(event.target.value) || "")}
              disabled={correlating}
            >
              {!selectedAuditId ? <option value="">Select an audit</option> : null}
              {audits.map((audit) => (
                <option key={audit.id} value={audit.id}>{audit.name}</option>
              ))}
            </select>
            <dl className="dynamic-home-facts">
              <div><dt>Audit</dt><dd>{selectedAudit?.name || "Not selected"}</dd></div>
              <div><dt>App / package</dt><dd className="mono">{selectedPackage || "Not installed"}</dd></div>
              <div>
                <dt>Audit findings</dt>
                <dd>
                  {staticFindingCount ?? "—"}
                  {staticFindingCount !== null ? (
                    <small className="muted"> · total persisted audit findings</small>
                  ) : null}
                </dd>
              </div>
              <div>
                <dt>Lab readiness</dt>
                <dd className={labReady ? "state-text-ready" : "state-text-failed"}>
                  {labReady === null ? "Checking…" : labReady ? "Ready" : "Needs attention"}
                  {labDetail ? <small> · {labDetail}</small> : null}
                </dd>
              </div>
            </dl>
          </div>
          <div className="dynamic-home-target-action">
            <button
              className="button button-primary button-prominent dynamic-home-cta"
              onClick={() => void handleStartCorrelation()}
              disabled={!selectedAuditId || correlating}
            >
              {correlating
                ? "Analyzing static findings…"
                : "Start Static → Dynamic Correlation"}
            </button>
            <p className="muted">
              The correlation agent reviews every static finding of the audit and
              classifies which runtime validations are worth executing with the
              current lab capabilities.
            </p>
          </div>
        </div>
      </Card>

      {stage === "correlating" ? (
        <Card className="dynamic-home-correlating-card" title="Step 2 · AI correlation in progress">
          <div className="agent-waiting-state">
            <strong>Correlating static findings…</strong>
            <p>
              The agent reviews the audit's static findings in bounded batches,
              builds the capability manifest, and classifies every finding. The
              result appears here when the review completes.
            </p>
          </div>
        </Card>
      ) : null}

      {stage === "correlated" && correlation ? (
        <CorrelationResults
          correlation={correlation}
          gapReport={gapReport}
          selectedPackage={selectedPackage}
          activeTab={activeTab}
          onTabChange={setActiveTab}
          canOperate={canOperate}
          working={working}
          correlating={correlating}
          staticFindingCount={staticFindingCount}
          onStartPoc={(candidate) => void handleStartPoc(candidate)}
          onStartPlaybook={(playbookId) => void handleStartPlaybook(playbookId)}
          onViewCandidateEvidence={(candidate) =>
            void handleViewCandidateEvidence(candidate)
          }
          onReanalyze={() => void handleReanalyze()}
        />
      ) : null}

      {stage === "review" && mission ? (
        <PocMissionReview
          mission={mission}
          nextStep={nextStep}
          canOperate={canOperate}
          working={working}
          onApprove={() => void handleApprovePoc()}
          onRun={() => void handleRunPoc()}
          onBack={handleBackToCandidates}
        />
      ) : null}

      {mission?.agent_run && mission.allowed_capabilities.includes("frida_run_js") ? (
        <PocFridaApprovalPanel
          mission={mission}
          proposals={fridaScriptProposals}
          canOperate={canOperate}
          working={working}
          onGenerate={() => void handleGenerateFridaScriptProposal()}
          onApprove={(proposalId) => void handleApproveFridaScriptProposal(proposalId)}
          onReject={(proposalId) => void handleRejectFridaScriptProposal(proposalId)}
          onResume={() => void handleResumeAdaptiveRun()}
        />
      ) : null}

      {stage === "live" && mission ? (
        <PocLiveExecution
          mission={mission}
          evidence={evidence}
          timelineItems={timelineItems}
          currentStep={currentStep}
          completedSteps={completedSteps}
          totalSteps={totalSteps}
          labDetail={labDetail}
        />
      ) : null}

      {stage === "conclusion" && mission ? (
        <PocConclusionCard
          mission={mission}
          evidenceCount={evidence.length}
          onViewEvidence={handleViewEvidence}
          onAnotherFinding={handleBackToCandidates}
        />
      ) : null}

      {stage !== "target" && stage !== "correlated" && stage !== "correlating" ? (
        <div id="dynamic-evidence-panel" ref={evidencePanelRef}>
          <PocEvidencePanel evidence={evidence} mission={mission} />
        </div>
      ) : null}

      {stage === "correlated" || stage === "conclusion" || stage === "review" ? (
        <ReportDownloadCard
          auditId={selectedAuditId}
          working={working === "report"}
          pdfUnavailable={pdfUnavailable}
          onDownload={() => void handleDownloadReport()}
        />
      ) : null}

      <footer className="dynamic-home-footer">
        <Link className="button button-secondary" to="/dynamic/advanced">
          Advanced Operator Console
        </Link>
        <span className="muted">
          Internal lab, budget, and mission details live in the Advanced Operator
          Console.
        </span>
      </footer>
    </div>
  );
}

function CorrelationResults({
  correlation,
  gapReport,
  selectedPackage,
  activeTab,
  onTabChange,
  canOperate,
  working,
  correlating,
  staticFindingCount,
  onStartPoc,
  onStartPlaybook,
  onViewCandidateEvidence,
  onReanalyze,
}: {
  correlation: StaticDynamicCorrelation;
  gapReport: CapabilityGapReport | null;
  selectedPackage: string;
  activeTab: ResultTab;
  onTabChange: (tab: ResultTab) => void;
  canOperate: boolean;
  working: string;
  correlating: boolean;
  staticFindingCount: number | null;
  onStartPoc: (candidate: CorrelationCandidate) => void;
  onStartPlaybook: (
    playbookId: "ROOT_DETECTION_SCREEN_VALIDATION" | "TLS_PINNING_FRIDA_BYPASS",
  ) => void;
  onViewCandidateEvidence: (candidate: CorrelationCandidate) => void;
  onReanalyze: () => void;
}) {
  const activeTabConfig = CLASSIFICATION_TABS.find((tab) => tab.key === activeTab)!;
  const visibleCandidates = correlation.candidates.filter((candidate) =>
    activeTabConfig.classifications.includes(candidate.classification),
  );
  const correlatedCount = correlation.total_static_findings;
  const eligibleCount =
    correlation.recommended_count + correlation.optional_count;

  return (
    <section className="dynamic-home-candidates" aria-label="Correlation results">
      <div className="auditor-section-heading">
        <div>
          <span className="eyebrow">Step 2 · AI correlation results</span>
          <h2>Correlation results</h2>
        </div>
        <span className="correlation-summary-meta">
          {correlatedCount} correlated static findings · {correlation.correlation_mode === "AI_AGENT" ? "AI agent" : "deterministic fallback"} · {correlation.model}
        </span>
      </div>

      <p className="muted">
        {staticFindingCount !== null
          ? `Of the ${staticFindingCount} persisted audit findings, ${correlatedCount} were reviewed for static→dynamic correlation; ${eligibleCount} are eligible candidates for runtime validation.`
          : `${eligibleCount} findings are eligible candidates for static→dynamic correlation.`}
      </p>

      <div className="correlation-count-grid">
        {CLASSIFICATION_TABS.map((tab) => (
          <button
            key={tab.key}
            className={`correlation-count-chip ${tab.key === activeTab ? "is-active" : ""}`}
            onClick={() => onTabChange(tab.key)}
          >
            <strong>{Number(correlation[tab.countField]) || 0}</strong>
            <span>{tab.label}</span>
          </button>
        ))}
      </div>

      <div className="auditor-section-actions">
        <button
          className="button button-secondary"
          onClick={onReanalyze}
          disabled={correlating}
        >
          {correlating ? "Re-analyzing…" : "Re-analyze findings"}
        </button>
        <span className="muted">
          Re-analyze recomputes the correlation when findings or lab capabilities changed.
        </span>
      </div>

      {visibleCandidates.length ? (
        <div className="dynamic-candidate-grid">
          {[...visibleCandidates]
            .sort((a, b) => a.priority - b.priority)
            .map((candidate) => (
              <CorrelationCandidateCard
                key={candidate.finding_id}
                candidate={candidate}
                canOperate={canOperate}
                working={working === `poc-${candidate.finding_id}`}
                workingEvidence={working === `evidence-${candidate.finding_id}`}
                onStartPoc={() => onStartPoc(candidate)}
                onViewCandidateEvidence={() =>
                  onViewCandidateEvidence(candidate)
                }
              />
            ))}
        </div>
      ) : (
        <div className="agent-waiting-state">
          <strong>No findings in this classification</strong>
          <p>No static finding of this audit was classified into this bucket.</p>
        </div>
      )}

      {correlation.capability_gaps.length || (gapReport && gapReport.highest_value_missing_capabilities.length) ? (
        <CapabilityGapsPanel
          gaps={correlation.capability_gaps}
          gapReport={gapReport}
        />
      ) : null}

      <AuditorPlaybooksPanel
        selectedPackage={selectedPackage}
        canOperate={canOperate}
        working={working}
        onStartPlaybook={onStartPlaybook}
      />
    </section>
  );
}

function CapabilityGapsPanel({
  gaps,
  gapReport,
}: {
  gaps: CapabilityGapEntry[];
  gapReport: CapabilityGapReport | null;
}) {
  const ranked = gaps.length ? gaps : (gapReport?.highest_value_missing_capabilities || []);
  return (
    <Card className="dynamic-home-gaps-card" title="Capability gaps">
      <p className="muted">
        Findings that cannot be validated dynamically yet. New capabilities close
        these gaps in future sprints.
      </p>
      <ul className="capability-gap-list">
        {ranked.slice(0, 10).map((gap) => (
          <li key={gap.missing_capability}>
            <strong>{gap.missing_capability}</strong>
            <span>
              {gap.affected_finding_count} affected finding{gap.affected_finding_count === 1 ? "" : "s"}
            </span>
          </li>
        ))}
      </ul>
      {gapReport ? (
        <div className="planner-chip-list">
          {gapReport.available_capabilities.slice(0, 12).map((capability) => (
            <span key={capability} className="planner-tool-chip">{friendlyToolLabel(capability)}</span>
          ))}
          {gapReport.available_capabilities.length > 12 ? (
            <span className="muted">+{gapReport.available_capabilities.length - 12} more</span>
          ) : null}
        </div>
      ) : null}
    </Card>
  );
}

function AuditorPlaybooksPanel({
  selectedPackage,
  canOperate,
  working,
  onStartPlaybook,
}: {
  selectedPackage: string;
  canOperate: boolean;
  working: string;
  onStartPlaybook: (
    playbookId: "ROOT_DETECTION_SCREEN_VALIDATION" | "TLS_PINNING_FRIDA_BYPASS",
  ) => void;
}) {
  const supported = selectedPackage === "owasp.sat.agoat";
  return (
    <Card className="dynamic-home-gaps-card" title="Live assessment playbooks">
      <p className="muted">
        Auditor-selectable live assessments that exercise Frida-backed runtime manipulation with bounded evidence collection.
      </p>
      {!supported ? (
        <div className="agent-waiting-state">
          <strong>AndroGoat demo package required</strong>
          <p>These two playbooks are currently restricted to the authorized AndroGoat demo application.</p>
        </div>
      ) : null}
      <div className="dynamic-candidate-grid">
        {AUDITOR_PLAYBOOKS.map((playbook) => (
          <article className="dynamic-candidate-card" key={playbook.id}>
            <header>
              <span className="classification-chip classification-optional">
                Live playbook
              </span>
              <strong>{playbook.title}</strong>
              <small>{playbook.id}</small>
            </header>
            <div className="candidate-detail">
              <span className="eyebrow">What the agent proves</span>
              <p>{playbook.summary}</p>
            </div>
            <div className="candidate-detail">
              <span className="eyebrow">Expected evidence</span>
              <div className="planner-chip-list">
                {playbook.evidence.map((item) => (
                  <span key={item} className="planner-evidence-chip">
                    {item}
                  </span>
                ))}
              </div>
            </div>
            <div className="candidate-actions">
              <button
                className="button button-primary"
                onClick={() => onStartPlaybook(playbook.id)}
                disabled={!supported || !canOperate || Boolean(working)}
              >
                {working === `playbook-${playbook.id}`
                  ? "Preparing assessment…"
                  : "Start assessment"}
              </button>
            </div>
          </article>
        ))}
      </div>
    </Card>
  );
}

function CorrelationCandidateCard({
  candidate,
  canOperate,
  working,
  workingEvidence,
  onStartPoc,
  onViewCandidateEvidence,
}: {
  candidate: CorrelationCandidate;
  canOperate: boolean;
  working: boolean;
  workingEvidence: boolean;
  onStartPoc: () => void;
  onViewCandidateEvidence: () => void;
}) {
  const severity = candidate.severity || "Info";
  const startable = candidate.start_poc_available;
  const alreadyConfirmed = candidate.current_validation_status === "CONFIRMED";
  return (
    <article className={`dynamic-candidate-card severity-${severityTone(severity)}`}>
      <header>
        <span className={`badge severity-${severityTone(severity)}`}>{severity}</span>
        <strong>{candidate.finding_title}</strong>
        <small>{candidate.rule_id} · {candidate.category}</small>
      </header>

      <div className="candidate-classification-row">
        <span className={`classification-chip classification-${classificationTone(candidate.classification)}`}>
          {CLASSIFICATION_LABEL[candidate.classification]}
        </span>
        <span className="muted">Priority {candidate.priority}/9 · {candidate.estimated_complexity} complexity</span>
      </div>

      {candidate.security_hypothesis ? (
        <div className="candidate-detail">
          <span className="eyebrow">Security hypothesis</span>
          <p>{candidate.security_hypothesis}</p>
        </div>
      ) : null}

      {candidate.dynamic_validation_value ? (
        <div className="candidate-detail">
          <span className="eyebrow">Dynamic validation value</span>
          <p>{candidate.dynamic_validation_value}</p>
        </div>
      ) : null}

      {candidate.recommended_poc_summary ? (
        <div className="candidate-detail">
          <span className="eyebrow">Recommended PoC</span>
          <p>{candidate.recommended_poc_summary}</p>
        </div>
      ) : null}

      {candidate.likely_capabilities.length ? (
        <div className="candidate-detail">
          <span className="eyebrow">Likely capabilities</span>
          <div className="planner-chip-list">
            {candidate.likely_capabilities.map((capability) => (
              <span key={capability} className="planner-tool-chip">
                {friendlyToolLabel(capability)}
              </span>
            ))}
          </div>
        </div>
      ) : null}

      {candidate.expected_evidence.length ? (
        <div className="candidate-detail">
          <span className="eyebrow">Expected evidence</span>
          <div className="planner-chip-list">
            {candidate.expected_evidence.map((item) => (
              <span key={item} className="planner-evidence-chip">{evidenceTypeLabel(item)}</span>
            ))}
          </div>
        </div>
      ) : null}

      {candidate.prerequisites ? (
        <div className="candidate-detail">
          <span className="eyebrow">Prerequisites</span>
          <p className="muted">{candidate.prerequisites}</p>
        </div>
      ) : null}

      {candidate.limitations ? (
        <div className="candidate-detail">
          <span className="eyebrow">Limitations</span>
          <p className="muted">{candidate.limitations}</p>
        </div>
      ) : null}

      {candidate.missing_capabilities.length ? (
        <div className="candidate-detail">
          <span className="eyebrow">Missing capabilities</span>
          <div className="planner-chip-list">
            {candidate.missing_capabilities.map((capability) => (
              <span key={capability} className="planner-evidence-chip">{capability}</span>
            ))}
          </div>
        </div>
      ) : null}

      {candidate.current_validation_status ? (
        <div className="candidate-meta">
          <span>Status: {candidate.current_validation_status}</span>
        </div>
      ) : null}

      <div className="candidate-actions">
        {startable ? (
          <button
            className="button button-primary"
            onClick={onStartPoc}
            disabled={!canOperate || working || workingEvidence}
          >
            {working ? "Preparing PoC…" : "Start PoC"}
          </button>
        ) : alreadyConfirmed ? (
          <div className="already-confirmed-note">
            <strong>Already dynamically confirmed</strong>
            <span>Runtime validation already produced sufficient evidence.</span>
            <button
              className="button button-secondary"
              onClick={onViewCandidateEvidence}
              disabled={!canOperate || working || workingEvidence}
            >
              {workingEvidence ? "Loading evidence…" : "View evidence"}
            </button>
          </div>
        ) : (
          <span className="not-testable-note">
            <strong>No PoC available</strong>
            <span>
              {candidate.classification === "NOT_TESTABLE_WITH_CURRENT_CAPABILITIES"
                ? "The current lab capabilities cannot validate this finding."
                : candidate.classification === "ALREADY_VALIDATED"
                  ? "This finding was already validated dynamically."
                  : candidate.classification === "BLOCKED_BY_LAB_CAPABILITY"
                    ? "The lab currently cannot provide the required capability."
                    : "Runtime validation would not add meaningful evidence."}
            </span>
          </span>
        )}
      </div>
    </article>
  );
}

function PocMissionReview({
  mission,
  nextStep,
  canOperate,
  working,
  onApprove,
  onRun,
  onBack,
}: {
  mission: FindingValidationMission;
  nextStep: string;
  canOperate: boolean;
  working: string;
  onApprove: () => void;
  onRun: () => void;
  onBack: () => void;
}) {
  const contract = mission.scenario_contract || {};
  const steps = Array.isArray(contract.steps) ? (contract.steps as Array<Record<string, unknown>>) : [];
  const tools = Array.isArray(mission.allowed_capabilities) ? mission.allowed_capabilities : [];
  const evidenceTypes = Array.isArray(contract.required_evidence_types)
    ? (contract.required_evidence_types as string[])
    : [];
  const missionTitle =
    mission.playbook_id === "ROOT_DETECTION_SCREEN_VALIDATION"
      ? "Root detection manipulation"
      : mission.playbook_id === "TLS_PINNING_FRIDA_BYPASS"
        ? "TLS pinning bypass"
        : mission.finding_title;
  return (
    <Card className="dynamic-home-review-card" title="Step 3 · Review the PoC">
      <div className="mission-review-card">
        <span className={`validation-status-badge status-${mission.status.toLowerCase()}`}>
          {mission.result_label || mission.status}
        </span>
        <h3>{missionTitle}</h3>
        <p>{mission.hypothesis || "The PoC planning agent prepared a bounded validation plan for this finding."}</p>
        <dl className="dynamic-home-facts">
          <div><dt>Finding</dt><dd>{mission.finding_rule_id} · {mission.finding_severity}</dd></div>
          <div><dt>Target</dt><dd className="mono">{mission.target_package}</dd></div>
          <div><dt>Plan steps</dt><dd>{steps.length || "—"}</dd></div>
          <div><dt>Provider</dt><dd>{mission.provider} · {mission.model}</dd></div>
          {mission.result_explanation ? (
            <div><dt>Next</dt><dd>{mission.result_explanation}</dd></div>
          ) : null}
        </dl>
      </div>

      <div className="mission-review-grid">
        <section>
          <h4>PoC plan</h4>
          <ol className="poc-plan-list">
            {steps.length ? steps.map((step, index) => (
              <li key={`${index}-${String(step.step_id || index)}`}>
                <strong>{String(step.objective || `Step ${index + 1}`)}</strong>
                <span>{String(step.expected_observation || "Bounded observation")}</span>
              </li>
            )) : <li>No Android action will be executed.</li>}
          </ol>
        </section>
        <section>
          <h4>Approved tools</h4>
          <div className="planner-chip-list">
            {tools.length ? tools.map((tool) => (
              <span key={tool} className="planner-tool-chip">
                {friendlyToolLabel(tool)}
              </span>
            )) : <span className="muted">None</span>}
          </div>
          <h4>Evidence to collect</h4>
          <div className="planner-chip-list">
            {evidenceTypes.length ? evidenceTypes.map((item) => (
              <span key={item} className="planner-evidence-chip">
                {evidenceTypeLabel(item)}
              </span>
            )) : <span className="muted">Tool output</span>}
          </div>
        </section>
      </div>

      <div className="auditor-stage-actions">
        {nextStep === "approve" || mission.status === "VALIDATED" ? (
          <button
            className="button button-primary button-prominent"
            onClick={onApprove}
            disabled={!canOperate || Boolean(working)}
          >
            {working === "approve" ? "Approving…" : "Approve PoC"}
          </button>
        ) : null}
        {nextStep === "run" || mission.status === "APPROVED" ? (
          <button
            className="button button-primary button-prominent"
            onClick={onRun}
            disabled={!canOperate || Boolean(working)}
          >
            {working === "run" ? "Starting agent…" : "Run PoC"}
          </button>
        ) : null}
        {mission.status === "NOT_DYNAMICALLY_TESTABLE" ? (
          <span className="not-testable-note">
            {mission.limitations || "Current MSAP capabilities cannot validate this finding dynamically."}
          </span>
        ) : null}
        <button className="button button-secondary" onClick={onBack}>
          Back to candidates
        </button>
      </div>
    </Card>
  );
}

function PocFridaApprovalPanel({
  mission,
  proposals,
  canOperate,
  working,
  onGenerate,
  onApprove,
  onReject,
  onResume,
}: {
  mission: FindingValidationMission;
  proposals: FridaScriptProposal[];
  canOperate: boolean;
  working: string;
  onGenerate: () => void;
  onApprove: (proposalId: number) => void;
  onReject: (proposalId: number) => void;
  onResume: () => void;
}) {
  const latest = proposals[0] || null;
  const approved = proposals.find((proposal) => proposal.status === "APPROVED");
  const failed = proposals.find((proposal) => proposal.status === "FAILED");
  const pausedForReview = mission.agent_run_status === "PAUSED";
  return (
    <Card className="dynamic-home-review-card frida-approval-card" title="Frida instrumentation approval">
      <div className="mission-review-card">
        <span className={`validation-status-badge status-${(latest?.status || "generated").toLowerCase()}`}>
          {latest ? titleCaseLabel(latest.status) : "No script proposal"}
        </span>
        <h3>Auditor-approved Frida hook required for generated scripts</h3>
        <p>
          The agent may propose Frida JavaScript, but MSAP will not run generated
          hooks until an auditor approves the exact script hash.
        </p>
        <dl className="dynamic-home-facts">
          <div><dt>Target</dt><dd className="mono">{mission.target_package}</dd></div>
          <div><dt>Run</dt><dd>{mission.agent_run ? `#${mission.agent_run}` : "Not started"}</dd></div>
          <div><dt>Approved script</dt><dd>{approved ? approved.source_sha256.slice(0, 16) + "…" : "None"}</dd></div>
          <div><dt>Run state</dt><dd>{mission.agent_run_status || mission.status}</dd></div>
        </dl>
      </div>

      {failed ? (
        <div className="alert alert-warning" role="status">
          <strong>Generated Frida script failed during execution.</strong>
          <span>{failed.last_error || "The gateway recorded a bounded Frida execution failure."}</span>
          <span>{failed.suggested_fix || "Generate a narrower script and approve the revised hook."}</span>
        </div>
      ) : null}

      {latest ? (
        <div className="mission-review-grid">
          <section>
            <h4>{latest.title}</h4>
            <p>{latest.rationale}</p>
            <dl className="dynamic-home-facts">
              <div><dt>Provider</dt><dd>{latest.generator_provider} {latest.generator_model ? `· ${latest.generator_model}` : ""}</dd></div>
              <div><dt>Hash</dt><dd className="mono">{latest.source_sha256.slice(0, 24)}…</dd></div>
              <div><dt>Size</dt><dd>{latest.source_size_bytes} bytes</dd></div>
              <div><dt>Status</dt><dd>{titleCaseLabel(latest.status)}</dd></div>
            </dl>
          </section>
          <section>
            <h4>Expected evidence</h4>
            <ul className="poc-plan-list">
              {(latest.expected_evidence || []).length
                ? latest.expected_evidence.map((item) => <li key={item}>{item}</li>)
                : <li>Bounded Frida event and script hash.</li>}
            </ul>
            {latest.validation_warnings.length ? (
              <>
                <h4>Warnings</h4>
                <ul className="poc-plan-list">
                  {latest.validation_warnings.map((item) => <li key={item}>{item}</li>)}
                </ul>
              </>
            ) : null}
          </section>
        </div>
      ) : (
        <div className="agent-waiting-state">
          <strong>No generated Frida script proposal yet</strong>
          <p>Generate a proposal when the running assessment needs custom instrumentation.</p>
        </div>
      )}

      {latest ? (
        <details className="plan-details-disclosure">
          <summary>Review script before approval</summary>
          <pre>{latest.source_code}</pre>
        </details>
      ) : null}

      <div className="auditor-stage-actions">
        <button
          className="button button-secondary"
          onClick={onGenerate}
          disabled={!canOperate || Boolean(working) || !mission.agent_run}
        >
          {working === "frida-generate" ? "Generating…" : latest ? "Generate Revised Script" : "Generate Frida Script"}
        </button>
        {latest?.status === "GENERATED" ? (
          <>
            <button
              className="button button-primary button-prominent"
              onClick={() => onApprove(latest.id)}
              disabled={!canOperate || Boolean(working)}
            >
              {working === `frida-approve-${latest.id}` ? "Approving…" : "Approve Script Hook"}
            </button>
            <button
              className="button button-secondary"
              onClick={() => onReject(latest.id)}
              disabled={!canOperate || Boolean(working)}
            >
              {working === `frida-reject-${latest.id}` ? "Rejecting…" : "Reject Script"}
            </button>
          </>
        ) : null}
        {pausedForReview && approved ? (
          <button
            className="button button-primary button-prominent"
            onClick={onResume}
            disabled={!canOperate || Boolean(working)}
          >
            {working === "frida-resume" ? "Resuming…" : "Resume Agent"}
          </button>
        ) : null}
      </div>
    </Card>
  );
}

function PocLiveExecution({
  mission,
  evidence,
  timelineItems,
  currentStep,
  completedSteps,
  totalSteps,
  labDetail,
}: {
  mission: FindingValidationMission;
  evidence: Evidence[];
  timelineItems: FindingValidationTimeline["items"];
  currentStep: FindingValidationTimeline["items"][number] | null;
  completedSteps: number;
  totalSteps: number;
  labDetail: string;
}) {
  return (
    <Card className="dynamic-home-live-card" title="Step 4 · Live PoC execution">
      <div className="mission-live-progress" role="status">
        <strong>Validating: {mission.finding_title}</strong>
        <span>
          {currentStep
            ? `Step ${currentStep.sequence} of ${totalSteps} · ${currentStep.scenario_title}`
            : `Step ${Math.min(completedSteps + 1, totalSteps)} of ${totalSteps} · preparing…`}
        </span>
        <div className="mission-progress-chips">
          <span>{completedSteps} steps completed</span>
          <span>{evidence.length} evidence records</span>
          <span>{labDetail}</span>
        </div>
      </div>

      <ol className="agent-activity-timeline mission-timeline">
        {timelineItems.length ? timelineItems.map((item) => {
          const display = STEP_STATUS_DISPLAY[item.status] || {
            icon: "○",
            label: item.status || "Planned",
          };
          return (
            <li key={`${item.sequence}-${item.scenario_step_id}`} className="agent-activity-card">
              <span className="agent-activity-sequence">{display.icon}</span>
              <div className="agent-activity-content">
                <div><span>Step {item.sequence}</span><strong>{item.scenario_title}</strong></div>
                <div><span>Status</span><p>{item.observation_summary || item.expected_observation || display.label}</p></div>
                {item.troubleshooting ? (
                  <div><span>Troubleshooting</span><p>Bounded retry/recovery was recorded for this step.</p></div>
                ) : null}
              </div>
              <span className={`agent-step-status state-${item.status.toLowerCase()}`}>
                {display.label}
              </span>
            </li>
          );
        }) : (
          <li className="agent-activity-card">
            <span className="agent-activity-sequence">1</span>
            <div className="agent-activity-content">
              <div><span>Status</span><strong>Starting the agent…</strong></div>
              <div><span>Observation</span><p>Live steps appear as the PoC executes.</p></div>
            </div>
          </li>
        )}
      </ol>
    </Card>
  );
}

function PocEvidencePanel({
  evidence,
  mission,
}: {
  evidence: Evidence[];
  mission: FindingValidationMission | null;
}) {
  const [artifacts, setArtifacts] = useState<AgentRunArtifact[]>([]);
  const artifactById = useMemo(() => {
    const map = new Map<number, AgentRunArtifact>();
    for (const artifact of artifacts) map.set(artifact.id, artifact);
    return map;
  }, [artifacts]);

  useEffect(() => {
    let active = true;
    setArtifacts([]);
    const runId = mission?.agent_run;
    if (!runId) return;
    listAgentRunArtifacts(runId)
      .then((records) => {
        if (active) setArtifacts(records);
      })
      .catch(() => null);
    return () => {
      active = false;
    };
  }, [mission?.agent_run]);

  const groups = useMemo(() => {
    const grouped = new Map<EvidenceKind, Evidence[]>();
    for (const item of evidence) {
      const kind = evidenceKind(item);
      const items = grouped.get(kind) || [];
      items.push(item);
      grouped.set(kind, items);
    }
    return EVIDENCE_KIND_ORDER.filter((kind) => grouped.has(kind)).map((kind) => {
      const items = grouped.get(kind) || [];
      return {
        kind,
        label: evidenceKindLabel(kind, items.length),
        items: [...items].reverse(),
      };
    });
  }, [evidence]);

  if (!evidence.length) return null;

  const counts = evidenceSummaryCounts(evidence);
  const chips = EVIDENCE_KIND_ORDER.filter((kind) => counts.has(kind)).map((kind) => {
    const count = counts.get(kind) || 0;
    return { kind, count, label: evidenceKindLabel(kind, count) };
  });

  return (
    <Card className="dynamic-home-evidence-card" title="Evidence collected">
      <div className="evidence-panel">
        <div className="evidence-summary-chips" aria-label="Evidence summary">
          <span className="evidence-chip evidence-chip-total">
            <strong>{evidence.length}</strong>{" "}
            {evidence.length === 1 ? "record" : "records"}
          </span>
          {chips.map((chip) => (
            <span className="evidence-chip" key={chip.kind}>
              <strong>{chip.count}</strong> {chip.label.toLowerCase()}
            </span>
          ))}
        </div>
        <div className="evidence-groups">
          {groups.map(({ kind, label, items }) => (
            <section className="evidence-group" key={kind}>
              <h4 className="evidence-group-title">
                {label} <span>({items.length})</span>
              </h4>
              {items.map((item) => (
                <EvidenceCard
                  key={item.id}
                  item={item}
                  artifact={
                    item.agent_run_artifact !== null
                      ? artifactById.get(item.agent_run_artifact)
                      : undefined
                  }
                />
              ))}
            </section>
          ))}
        </div>
      </div>
    </Card>
  );
}

function EvidenceCard({
  item,
  artifact,
}: {
  item: Evidence;
  artifact: AgentRunArtifact | undefined;
}) {
  const observation = parseEvidenceJson(item);
  const kind = evidenceKind(item);
  const toolName = evidenceStatusFromProvenance(item);
  const data = observationData(observation);
  const metadata = kind === "screenshot" ? screenshotMetadata(item) : {};
  const downloadUrl = artifact?.download_url || "";
  const previewUrl =
    kind === "screenshot" &&
    downloadUrl &&
    (artifact?.content_type || "").startsWith("image/")
      ? downloadUrl
      : "";
  const sha = item.sha256 || metadata["SHA-256"] || artifact?.sha256 || "";
  const error = observationError(observation);
  const excerpt = kind === "log" ? logExcerpt(observation) : "";
  const [previewFailed, setPreviewFailed] = useState(false);

  const nodeCount = typeof data.node_count === "number" ? data.node_count : null;
  const lineCount = typeof data.line_count === "number" ? data.line_count : null;
  const eventCount = typeof data.event_count === "number" ? data.event_count : null;
  const collectorId = typeof data.collector_id === "string" ? data.collector_id : "";
  const focusedPackage =
    typeof data.focused_package === "string" ? data.focused_package : "";
  const focusedActivity =
    typeof data.focused_activity === "string" ? data.focused_activity : "";

  const genericRows: Array<[string, string]> = [];
  if (nodeCount !== null) genericRows.push(["UI nodes", String(nodeCount)]);
  if (lineCount !== null) genericRows.push(["Log lines", String(lineCount)]);
  if (eventCount !== null) genericRows.push(["Events", String(eventCount)]);
  if (collectorId) genericRows.push(["Collector", collectorId]);
  if (focusedPackage) genericRows.push(["Focused package", focusedPackage]);
  if (focusedActivity) genericRows.push(["Focused activity", focusedActivity]);
  if (sha && kind !== "screenshot") genericRows.push(["SHA-256", sha]);

  const title = item.evidence_title || evidenceTypeLabel(item.evidence_type);
  const aiConclusion = (item.ai_conclusion || "").trim();
  const aiImpact = (item.ai_security_impact || "").trim();
  const aiStrength = (item.ai_evidence_strength || "").trim();
  const aiStatus = (item.ai_explanation_status || "").trim();
  const aiProvider = (item.ai_explanation_provider || "").trim();

  return (
    <article className="evidence-card">
      <header className="evidence-card-header">
        <h5 className="evidence-card-title">{title}</h5>
        <time className="evidence-card-time">
          {new Date(item.created_at).toLocaleString()}
        </time>
      </header>

      {kind === "screenshot" ? (
        previewUrl && !previewFailed ? (
          <div className="evidence-screenshot-preview">
            <img
              src={previewUrl}
              alt="Stored screenshot preview"
              onError={() => setPreviewFailed(true)}
            />
          </div>
        ) : (
          <div
            className="evidence-screenshot-placeholder"
            role="img"
            aria-label="Screenshot stored"
          >
            <span className="evidence-screenshot-placeholder-title">
              Screenshot stored
            </span>
            <span className="evidence-screenshot-placeholder-meta">
              {[
                metadata["Content type"],
                metadata["Dimensions"],
                metadata["Size"],
              ]
                .filter(Boolean)
                .join(" · ") || "Persisted with metadata retained"}
            </span>
          </div>
        )
      ) : null}

      <p className="evidence-summary">{humanEvidenceSummary(item)}</p>
      {aiConclusion ? (
        <p className="evidence-ai-conclusion">
          <strong>Conclusion:</strong> {aiConclusion}
        </p>
      ) : null}
      {aiImpact ? (
        <p className="evidence-ai-impact">
          <strong>Why it matters:</strong> {aiImpact}
        </p>
      ) : null}
      {aiStatus ? (
        <p className="muted evidence-ai-meta">
          AI explanation: {aiStatus.toLowerCase()}
          {aiProvider ? ` · ${aiProvider}` : ""}
          {aiStrength ? ` · ${titleCaseLabel(aiStrength.toLowerCase())}` : ""}
        </p>
      ) : null}
      {toolName ? (
        <p className="muted evidence-tool">Related tool: {toolName}</p>
      ) : null}
      {error ? (
        <p className="evidence-warning" role="alert">
          Tool reported: {error.length > 160 ? `${error.slice(0, 160)}…` : error}
        </p>
      ) : null}

      {kind === "screenshot" && Object.keys(metadata).length ? (
        <dl className="evidence-metadata-grid">
          {Object.entries(metadata).map(([label, value]) => (
            <div key={label}>
              <dt>{label}</dt>
              <dd className="mono">
                {label === "SHA-256" ? (
                  <span className="evidence-hash" title={value}>
                    {shortHash(value)}
                  </span>
                ) : (
                  value
                )}
              </dd>
            </div>
          ))}
        </dl>
      ) : genericRows.length ? (
        <dl className="evidence-metadata-grid">
          {genericRows.map(([label, value]) => (
            <div key={label}>
              <dt>{label}</dt>
              <dd className="mono">
                {label === "SHA-256" ? (
                  <span className="evidence-hash" title={value}>
                    {shortHash(value)}
                  </span>
                ) : (
                  value
                )}
              </dd>
            </div>
          ))}
        </dl>
      ) : null}

      {excerpt ? <pre className="evidence-excerpt">{excerpt}</pre> : null}

      {kind === "screenshot" && downloadUrl ? (
        <a
          className="button button-primary evidence-download"
          href={downloadUrl}
          target="_blank"
          rel="noopener noreferrer"
        >
          Download screenshot
        </a>
      ) : kind === "screenshot" && artifact ? (
        <p className="muted evidence-artifact-note">
          Artifact: {artifact.name} · {artifact.content_type} ·{" "}
          {formatBytes(artifact.size_bytes)}
        </p>
      ) : null}

      {observation ? (
        <details className="evidence-raw-json">
          <summary>Raw evidence JSON</summary>
          <pre>{JSON.stringify(observation, null, 2)}</pre>
        </details>
      ) : null}
    </article>
  );
}

function PocConclusionCard({
  mission,
  evidenceCount,
  onViewEvidence,
  onAnotherFinding,
}: {
  mission: FindingValidationMission;
  evidenceCount: number;
  onViewEvidence: () => void;
  onAnotherFinding: () => void;
}) {
  return (
    <Card className="dynamic-home-conclusion-card" title="Dynamic validation result">
      <span className={`validation-status-badge status-${mission.status.toLowerCase()}`}>
        {mission.result_label || mission.status}
      </span>
      <h3>{mission.finding_title}</h3>
      <p>{mission.result_explanation || mission.final_conclusion}</p>
      {mission.final_conclusion ? <p className="muted">{mission.final_conclusion}</p> : null}
      <p className="muted">Evidence collected: {evidenceCount} records</p>
      <div className="results-action-row">
        <button className="button button-primary" onClick={onViewEvidence}>
          View Evidence
        </button>
        <button className="button button-secondary" onClick={onAnotherFinding}>
          Validate another finding
        </button>
      </div>
    </Card>
  );
}

function ReportDownloadCard({
  auditId,
  working,
  pdfUnavailable,
  onDownload,
}: {
  auditId: number | "";
  working: boolean;
  pdfUnavailable: boolean;
  onDownload: () => void;
}) {
  if (!auditId) return null;
  return (
    <Card className="dynamic-home-report-card" title="Report">
      <p className="muted">
        {pdfUnavailable
          ? "Report ready as JSON · PDF export not available yet"
          : "Download the audit validation report with findings, missions, evidence, and conclusions."}
      </p>
      <div className="results-action-row">
        <button
          className="button button-primary"
          onClick={onDownload}
          disabled={working}
        >
          {working ? "Preparing report…" : "Download Validation Report"}
        </button>
        <Link className="button button-secondary" to={`/audits/${auditId}/report`}>
          View Report
        </Link>
      </div>
    </Card>
  );
}
