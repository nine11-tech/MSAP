import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import {
  approveAssessmentPlan,
  captureDynamicHostAgentScreenshot,
  createAgentRun,
  createAssessmentPlan,
  getDynamicHostAgentStatus,
  installDynamicAuditApk,
  listAgentRunArtifacts,
  listAgentRuns,
  listAgentRunSteps,
  listAgentRuntimes,
  listAssessmentPlans,
  listApkFiles,
  listAudits,
  listDynamicHostAgentPackages,
  runDynamicHostAgentPackageAction,
  syncDynamicHostAgent,
  validateAssessmentPlan,
} from "../api/msap";
import type {
  AgentRun,
  AgentRunArtifact,
  AgentRuntime,
  AgentRunStep,
  AgentObjective,
  AssessmentPlan,
  ApkFile,
  Audit,
  DynamicHostAgentInstallResult,
  DynamicHostAgentStatus,
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
  | "sync"
  | "screenshot"
  | "packages"
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
  | "planner-approve";

type PackageAction =
  | "launch-package"
  | "force-stop"
  | "clear-data"
  | "uninstall";

type AgentRuntimeType = "INTERNAL_CONTROLLER" | "CONTAINER_SANDBOX";
type AgentTargetType = "VERIFIED_APK" | "INSTALLED_PACKAGE";

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
  const [plannerPackageName, setPlannerPackageName] = useState("");
  const [plannerProvider, setPlannerProvider] = useState<
    "" | "DETERMINISTIC" | "OPENAI"
  >("");
  const [plannerObjective, setPlannerObjective] = useState(
    "Assess authorized runtime behavior with bounded evidence.",
  );
  const [plannerScope, setPlannerScope] = useState(
    "Capture a baseline, inspect runtime instrumentation readiness, and plan before/after evidence collection without asserting a vulnerability verdict.",
  );
  const [screenshotUrl, setScreenshotUrl] = useState("");
  const screenshotUrlRef = useRef("");
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
        const [stepData, artifactData] = await Promise.all([
          listAgentRunSteps(latestRun.id),
          listAgentRunArtifacts(latestRun.id),
        ]);
        setAgentSteps(stepData);
        setAgentArtifacts(artifactData);
      } else {
        setAgentSteps([]);
        setAgentArtifacts([]);
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

  async function handleSync() {
    setWorking("sync");
    setError("");
    setNotice("");
    try {
      const result = await syncDynamicHostAgent();
      setAgentStatus(result);
      setNotice("Device inventory synchronized.");
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

  async function handleRefreshPackages() {
    setWorking("packages");
    setError("");
    setNotice("");
    try {
      await refreshPackages();
    } catch (requestError) {
      setError(errorMessage(requestError));
    } finally {
      setWorking("");
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
        ...(plannerProvider ? { planner_provider: plannerProvider } : {}),
      });
      setAssessmentPlan(plan);
      setNotice(`Assessment plan #${plan.id} generated. No tools were executed.`);
    } catch (requestError) {
      setError(errorMessage(requestError));
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
      setNotice(`Assessment plan #${plan.id} validated. No tools were executed.`);
    } catch (requestError) {
      setError(errorMessage(requestError));
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
      setNotice(`Assessment plan #${plan.id} approved. Approval did not start execution.`);
    } catch (requestError) {
      setError(errorMessage(requestError));
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
        eyebrow="Managed Android runtime"
        title="Dynamic Lab"
        description="Reliable emulator and APK controls for the accepted MVP."
      />

      {error ? <ErrorMessage message={error} /> : null}
      {notice ? (
        <div className="alert alert-success" role="status">
          {notice}
        </div>
      ) : null}

      <Card className="dynamic-mvp-section">
        <SectionHeader
          title="Device"
          actions={
            <div className="dynamic-mvp-actions">
              <button
                className="button button-secondary"
                onClick={() => void handleRefresh()}
                disabled={Boolean(working)}
              >
                {working === "refresh" ? "Refreshing..." : "Refresh"}
              </button>
              <button
                className="button button-primary"
                onClick={() => void handleSync()}
                disabled={!canOperate || Boolean(working)}
              >
                {working === "sync" ? "Syncing..." : "Sync Device"}
              </button>
              <button
                className="button button-secondary"
                onClick={() => void handleScreenshot()}
                disabled={!agentStatus?.connected || !emulatorOnline || Boolean(working)}
              >
                {working === "screenshot" ? "Capturing..." : "Screenshot"}
              </button>
            </div>
          }
        />

        <div className="dynamic-device-facts">
          <StatusFact
            label="Host agent"
            value={agentStatus?.connected ? "Online" : "Offline"}
            detail={agentStatus?.agent?.version ? `v${agentStatus.agent.version}` : undefined}
            state={agentStatus?.connected ? "online" : "offline"}
          />
          <StatusFact
            label="Emulator"
            value={emulatorOnline ? "Online" : "Offline"}
            detail={device?.state || "Unavailable"}
            state={emulatorOnline ? "online" : "offline"}
          />
          <StatusFact label="Serial" value={device?.serial || "Unavailable"} />
          <StatusFact
            label="Android"
            value={device?.android_version || "Unavailable"}
          />
          <StatusFact
            label="API"
            value={device?.api_level === null || device?.api_level === undefined
              ? "Unavailable"
              : String(device.api_level)}
          />
          <StatusFact label="ABI" value={device?.abi || "Unavailable"} />
          <StatusFact
            label="Root"
            value={
              device?.root_uid === null || device?.root_uid === undefined
                ? "Unavailable"
                : `UID ${device.root_uid}`
            }
            state={device?.root_uid === 0 ? "online" : "neutral"}
          />
          <StatusFact
            label="SELinux"
            value={device?.selinux || "Unavailable"}
            state={
              device?.selinux?.toLowerCase() === "enforcing"
                ? "online"
                : "neutral"
            }
          />
          <StatusFact
            label="Last sync"
            value={formatDate(agentStatus?.last_sync_at)}
          />
          {device?.proxy ? (
            <StatusFact label="Proxy" value={device.proxy} />
          ) : null}
          {device?.focused_app ? (
            <StatusFact label="Focused app" value={device.focused_app} />
          ) : null}
          <ServiceFact label="MinIO" component={minio} />
          <ServiceFact label="Celery" component={celery} />
        </div>
      </Card>

      <Card className="dynamic-mvp-section">
        <SectionHeader title="APK" />
        <div className="dynamic-apk-controls">
          <label>
            Audit
            <select
              value={selectedAuditId}
              onChange={(event) =>
                setSelectedAuditId(
                  event.target.value ? Number(event.target.value) : "",
                )
              }
            >
              <option value="">Select audit</option>
              {audits.map((audit) => (
                <option key={audit.id} value={audit.id}>
                  {audit.name}
                </option>
              ))}
            </select>
          </label>

          <label>
            Verified APK
            <select
              value={selectedApkId}
              onChange={(event) =>
                setSelectedApkId(
                  event.target.value ? Number(event.target.value) : "",
                )
              }
              disabled={!selectedAuditId}
            >
              <option value="">Select verified APK</option>
              {verifiedApks.map((apk) => (
                <option key={apk.id} value={apk.id}>
                  #{apk.id} {apk.package_name || apk.sha256.slice(0, 12)}
                  {apk.version_name ? ` (${apk.version_name})` : ""}
                </option>
              ))}
            </select>
          </label>

          <label>
            Installed package
            <input
              value={packageName}
              onChange={(event) => setPackageName(event.target.value)}
              list="dynamic-installed-packages"
              placeholder="com.example.app"
              autoComplete="off"
            />
            <datalist id="dynamic-installed-packages">
              {packages.map((item) => (
                <option key={item} value={item} />
              ))}
            </datalist>
          </label>
        </div>

        <div className="dynamic-apk-actions">
          <button
            className="button button-primary"
            onClick={() => void handleInstall()}
            disabled={
              !canOperate ||
              !selectedAuditId ||
              !selectedApkId ||
              !emulatorOnline ||
              Boolean(working)
            }
          >
            {working === "install" ? "Installing..." : "Install APK"}
          </button>
          <button
            className="button button-secondary"
            onClick={() => void handlePackageAction("launch-package")}
            disabled={!canOperate || !packageName.trim() || !emulatorOnline || Boolean(working)}
          >
            {working === "launch-package" ? "Launching..." : "Launch"}
          </button>
          <button
            className="button button-secondary"
            onClick={() => void handlePackageAction("force-stop")}
            disabled={!canOperate || !packageName.trim() || !emulatorOnline || Boolean(working)}
          >
            {working === "force-stop" ? "Stopping..." : "Force Stop"}
          </button>
          <button
            className="button button-secondary"
            onClick={() => void handlePackageAction("clear-data")}
            disabled={!canOperate || !packageName.trim() || !emulatorOnline || Boolean(working)}
          >
            {working === "clear-data" ? "Clearing..." : "Clear Data"}
          </button>
          <button
            className="button button-danger"
            onClick={() => void handlePackageAction("uninstall")}
            disabled={!canOperate || !packageName.trim() || !emulatorOnline || Boolean(working)}
          >
            {working === "uninstall" ? "Uninstalling..." : "Uninstall"}
          </button>
          <button
            className="button button-secondary"
            onClick={() => void handleRefreshPackages()}
            disabled={!agentStatus?.connected || !emulatorOnline || Boolean(working)}
          >
            {working === "packages" ? "Refreshing..." : "Refresh Packages"}
          </button>
        </div>

        {!canOperate ? (
          <p className="muted dynamic-role-note">Viewer access is read-only.</p>
        ) : null}
        {selectedAuditId && !verifiedApks.length ? (
          <p className="muted dynamic-role-note">
            No verified APK is available for the selected audit.
          </p>
        ) : null}

        {installResult?.success ? (
          <section className="installed-package-metadata" aria-label="Installed package metadata">
            <h3>Installed package metadata</h3>
            <dl>
              <div>
                <dt>Package</dt>
                <dd>{installResult.package_metadata.package_name || "Unavailable"}</dd>
              </div>
              <div>
                <dt>Version</dt>
                <dd>
                  {installResult.package_metadata.version_name || "Unavailable"}
                  {installResult.package_metadata.version_code
                    ? ` (${installResult.package_metadata.version_code})`
                    : ""}
                </dd>
              </div>
              <div>
                <dt>Launch activity</dt>
                <dd>{installResult.package_metadata.launchable_activity || "Unavailable"}</dd>
              </div>
              <div>
                <dt>Installed path</dt>
                <dd>{installResult.package_metadata.installed_apk_path || "Unavailable"}</dd>
              </div>
              <div>
                <dt>Permissions</dt>
                <dd>
                  {installResult.package_metadata.granted_permission_count} granted /{" "}
                  {installResult.package_metadata.requested_permission_count} requested
                </dd>
              </div>
              <div>
                <dt>SHA-256</dt>
                <dd className="mono">{installResult.sha256}</dd>
              </div>
            </dl>
          </section>
        ) : null}
      </Card>

      <Card className="dynamic-mvp-section dynamic-screenshot-section">
        <SectionHeader title="Emulator Screenshot" />
        <div className={`dynamic-screenshot-panel${screenshotUrl ? " has-capture" : ""}`}>
          {screenshotUrl ? (
            <img src={screenshotUrl} alt="Latest Android emulator screenshot" />
          ) : (
            <span>No capture</span>
          )}
        </div>
      </Card>

      <Card className="dynamic-mvp-section assessment-planner-card">
        <SectionHeader
          title="AI Assessment Planner"
          actions={<span className="planner-only-badge">PLAN ONLY</span>}
        />
        <p className="muted planner-intro">
          Generate a structured assessment plan from audit context and the existing
          restricted tool manifest. The planner cannot call tools, and approval does
          not start an agent run.
        </p>

        <div className="planner-controls">
          <label>
            <span>Audit</span>
            <select
              value={selectedAuditId}
              onChange={(event) =>
                setSelectedAuditId(Number(event.target.value) || "")
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
            <span>Authorized target</span>
            <select
              value={plannerPackageName}
              onChange={(event) => setPlannerPackageName(event.target.value)}
              disabled={!selectedAuditId || Boolean(working)}
            >
              <option value="">Select verified audit package</option>
              {authorizedPlannerPackages.map((target) => (
                <option key={target} value={target}>{target}</option>
              ))}
            </select>
          </label>
          <label>
            <span>Planner provider</span>
            <select
              value={plannerProvider}
              onChange={(event) =>
                setPlannerProvider(
                  event.target.value as "" | "DETERMINISTIC" | "OPENAI",
                )
              }
              disabled={Boolean(working)}
            >
              <option value="">Server default</option>
              <option value="OPENAI">OpenAI · GPT-5.5</option>
              <option value="DETERMINISTIC">Deterministic reference</option>
            </select>
          </label>
          <label className="planner-objective-field">
            <span>Assessment objective</span>
            <input
              value={plannerObjective}
              onChange={(event) => setPlannerObjective(event.target.value)}
              maxLength={500}
              disabled={Boolean(working)}
            />
          </label>
          <label className="planner-scope-field">
            <span>Scope</span>
            <textarea
              value={plannerScope}
              onChange={(event) => setPlannerScope(event.target.value)}
              maxLength={2000}
              rows={4}
              disabled={Boolean(working)}
            />
          </label>
        </div>

        <div className="planner-actions">
          <button
            className="button button-primary"
            onClick={() => void handleGenerateAssessmentPlan()}
            disabled={
              !canOperate ||
              !selectedAuditId ||
              !plannerPackageName ||
              !plannerObjective.trim() ||
              !plannerScope.trim() ||
              Boolean(working)
            }
          >
            {working === "planner-generate" ? "Generating..." : "Generate Plan"}
          </button>
          <button
            className="button button-secondary"
            onClick={() => void handleValidateAssessmentPlan()}
            disabled={
              !canOperate ||
              !assessmentPlan ||
              assessmentPlan.status !== "GENERATED" ||
              Boolean(working)
            }
          >
            {working === "planner-validate" ? "Validating..." : "Validate Plan"}
          </button>
          <button
            className="button button-secondary"
            onClick={() => void handleApproveAssessmentPlan()}
            disabled={
              !canOperate ||
              !assessmentPlan ||
              assessmentPlan.status !== "VALIDATED" ||
              Boolean(working)
            }
          >
            {working === "planner-approve" ? "Approving..." : "Approve Plan"}
          </button>
        </div>

        {!canOperate ? (
          <p className="muted dynamic-role-note">
            Viewer access is read-only; plan generation, validation, and approval
            require Analyst or Admin.
          </p>
        ) : null}
        {selectedAuditId && authorizedPlannerPackages.length === 0 ? (
          <p className="muted dynamic-role-note">
            The selected audit has no verified package with an authorized package name.
          </p>
        ) : null}

        {assessmentPlan ? (
          <AssessmentPlanResult plan={assessmentPlan} />
        ) : (
          <div className="planner-empty-result">
            No assessment plan has been generated yet.
          </div>
        )}
      </Card>

      <Card className="dynamic-mvp-section agent-foundation-card">
        <SectionHeader
          title="Agentic Dynamic Assessment"
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
            Sprint C2 keeps both run modes deterministic while adding bounded
            package, screenshot, UI hierarchy, logcat, tap, and text tools.
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

        {agentRun && !isFridaObjective(agentRun.objective) ? (
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
        <SectionHeader title="Runtime Instrumentation" />
        <p className="muted">
          Real Frida checks and scripts execute through the run-scoped Django tool
          gateway against one audit-authorized Android package.
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
  );
}

function AssessmentPlanResult({ plan }: { plan: AssessmentPlan }) {
  const toolCount = plan.steps.reduce(
    (count, step) => count + step.required_tools.length,
    0,
  );
  return (
    <section className="planner-result" aria-label="Latest AI assessment plan">
      <div className="planner-result-heading">
        <div>
          <span className="eyebrow">Structured assessment plan</span>
          <h3>Plan #{plan.id} · {plan.target_package}</h3>
        </div>
        <span className={`planner-state planner-state-${plan.status.toLowerCase()}`}>
          {plan.status}
        </span>
      </div>

      <div className="planner-summary-facts">
        <StatusFact label="Provider" value={plan.planner_provider} detail={plan.planner_model} />
        <StatusFact label="Validation" value={plan.validation_status} state={plan.validation_status === "PASSED" ? "online" : "warning"} />
        <StatusFact label="Policy" value={plan.policy_status} state={plan.policy_status === "PASSED" ? "online" : "warning"} />
        <StatusFact label="Steps" value={String(plan.steps.length)} />
        <StatusFact label="Bounded tool references" value={String(toolCount)} />
        <StatusFact label="Created" value={formatDate(plan.created_at)} />
        <StatusFact label="Plan hash" value={plan.plan_hash ? `${plan.plan_hash.slice(0, 16)}…` : "Unavailable"} />
        <StatusFact
          label="Planner latency"
          value={
            plan.provider_metadata.latency_ms === undefined
              ? "Unavailable"
              : `${plan.provider_metadata.latency_ms} ms`
          }
          detail={
            plan.provider_metadata.retry_count === undefined
              ? undefined
              : `${plan.provider_metadata.retry_count} retries`
          }
        />
      </div>

      <div className="planner-scope-summary">
        <div>
          <span>Objective</span>
          <p>{plan.objective}</p>
        </div>
        <div>
          <span>Scope</span>
          <p>{plan.scope}</p>
        </div>
      </div>

      <div className="planner-no-execution-note">
        <strong>Plan only.</strong> Approval records auditor authorization for a
        future execution agent. It does not contact the gateway, host agent, or
        emulator.
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
                <dt>Allowed tools</dt>
                <dd className="planner-chip-list">
                  {step.required_tools.length ? step.required_tools.map((tool) => (
                    <span key={tool} className="planner-tool-chip mono">{tool}</span>
                  )) : <span className="muted">Reasoning-only step</span>}
                </dd>
              </div>
              <div>
                <dt>Expected observation</dt>
                <dd>{step.expected_observation}</dd>
              </div>
              <div>
                <dt>Success condition</dt>
                <dd>{step.success_condition}</dd>
              </div>
              <div>
                <dt>Evidence</dt>
                <dd className="planner-chip-list">
                  {step.evidence_requirements.map((evidence) => (
                    <span key={evidence} className="planner-evidence-chip">{evidenceLabel(evidence)}</span>
                  ))}
                </dd>
              </div>
              <div>
                <dt>Dependencies</dt>
                <dd>{step.dependencies.length ? step.dependencies.join(", ") : "None"}</dd>
              </div>
            </dl>
            {step.required_tools.length ? (
              <details className="planner-tool-arguments">
                <summary>Bounded tool arguments</summary>
                <pre>{JSON.stringify(step.tool_arguments, null, 2)}</pre>
              </details>
            ) : null}
          </li>
        ))}
      </ol>
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
        Sprint C retains validated metadata and the digest; screenshot bytes are
        not stored in PostgreSQL.
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

function ServiceFact({
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
    <StatusFact
      label={label}
      value={component?.status === "OPERATIONAL" ? "Online" : "Offline"}
      detail={component?.message}
      state={state}
    />
  );
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
