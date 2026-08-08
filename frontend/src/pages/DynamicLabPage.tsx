import {
  type FormEvent,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { Link } from "react-router-dom";
import { ApiError } from "../api/client";
import {
  captureDynamicHostAgentScreenshot,
  cancelDynamicJob,
  createDynamicJob,
  getDynamicHostAgentStatus,
  getDynamicRunnerReadiness,
  getSystemStatus,
  installDynamicAuditApk,
  listApkFiles,
  listAudits,
  listDynamicDeviceCapabilities,
  listDynamicDevicePools,
  listDynamicDevices,
  listDynamicEmulatorSnapshots,
  listDynamicJobs,
  listDynamicHostAgentPackages,
  listDynamicSessions,
  runDynamicHostAgentAction,
  runDynamicHostAgentPackageAction,
  runDynamicMvpJob,
  syncDynamicHostAgent,
} from "../api/msap";
import type {
  ApkFile,
  Audit,
  DynamicAnalysisJob,
  DynamicDevice,
  DynamicDeviceCapability,
  DynamicDevicePool,
  DynamicEmulatorSnapshot,
  DynamicHostAgentActionResult,
  DynamicHostAgentInstallResult,
  DynamicHostAgentStatus,
  DynamicJobCreateRequest,
  DynamicRunnerReadiness,
  DynamicSession,
  SystemStatus,
} from "../api/types";
import { useAuth } from "../auth/AuthContext";
import {
  Card,
  EmptyState,
  ErrorMessage,
  LoadingState,
  MetricCard,
  PageHeader,
  SectionHeader,
  StatusBadge,
  errorMessage,
  formatDate,
  formatEnum,
} from "../components/Common";

const REQUIRED_CAPABILITIES = [
  "ADB",
  "ROOT",
  "FRIDA",
  "MITMPROXY_ROUTE",
  "RUNTIME_CA",
  "SNAPSHOT",
  "NETWORK_CAPTURE",
];

const TERMINAL_SESSION_STATES = new Set([
  "COMPLETED",
  "FAILED",
  "CANCELLED",
  "QUARANTINED",
]);

const RUNNABLE_JOB_STATUSES = new Set(["QUEUED"]);

const TOOL_PROFILE_OPTIONS: DynamicJobCreateRequest["requested_tool_profile"][] = [
  "FULL",
  "FRIDA_EXTENDED",
  "FRIDA_BASIC",
  "NETWORK_CAPTURE",
  "ADB_ONLY",
];

const INTERACTION_MODE_OPTIONS: DynamicJobCreateRequest["requested_interaction_mode"][] = [
  "PASSIVE",
  "BASIC_AUTOMATION",
  "SCRIPTED_SCENARIO",
  "AUTHORIZED_LOGIN_SCENARIO",
];

export function DynamicLabPage() {
  const [audits, setAudits] = useState<Audit[]>([]);
  const [apkFiles, setApkFiles] = useState<ApkFile[]>([]);
  const [pools, setPools] = useState<DynamicDevicePool[]>([]);
  const [devices, setDevices] = useState<DynamicDevice[]>([]);
  const [capabilities, setCapabilities] = useState<DynamicDeviceCapability[]>([]);
  const [snapshots, setSnapshots] = useState<DynamicEmulatorSnapshot[]>([]);
  const [jobs, setJobs] = useState<DynamicAnalysisJob[]>([]);
  const [sessions, setSessions] = useState<DynamicSession[]>([]);
  const [selectedAuditId, setSelectedAuditId] = useState<number | "">("");
  const [selectedApkId, setSelectedApkId] = useState<number | "">("");
  const [selectedPoolId, setSelectedPoolId] = useState<number | "">("");
  const [selectedJobId, setSelectedJobId] = useState<number | "">("");
  const [toolProfile, setToolProfile] =
    useState<DynamicJobCreateRequest["requested_tool_profile"]>("FULL");
  const [interactionMode, setInteractionMode] =
    useState<DynamicJobCreateRequest["requested_interaction_mode"]>("PASSIVE");
  const [includePlatformTlsProbe, setIncludePlatformTlsProbe] = useState(false);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [working, setWorking] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [agentStatus, setAgentStatus] = useState<DynamicHostAgentStatus | null>(
    null,
  );
  const [runnerReadiness, setRunnerReadiness] =
    useState<DynamicRunnerReadiness | null>(null);
  const [systemStatus, setSystemStatus] = useState<SystemStatus | null>(null);
  const [agentWorking, setAgentWorking] = useState("");
  const [agentError, setAgentError] = useState("");
  const [packageName, setPackageName] = useState("");
  const [knownPackages, setKnownPackages] = useState<string[]>([]);
  const [installResult, setInstallResult] =
    useState<DynamicHostAgentInstallResult | null>(null);
  const [latestEvidence, setLatestEvidence] = useState<{
    action: string;
    evidence: Record<string, unknown>;
  } | null>(null);
  const [screenshotUrl, setScreenshotUrl] = useState("");
  const [screenshotFilename, setScreenshotFilename] = useState(
    "MSAP_emulator_capture.png",
  );
  const screenshotUrlRef = useRef("");
  const [agentActivity, setAgentActivity] = useState<
    Array<{ action: string; status: string; duration?: number; at: string }>
  >([]);
  const { hasRole } = useAuth();
  const canOperate = hasRole("ADMIN", "ANALYST");

  const loadWorkspace = useCallback(async (showLoading = true) => {
    if (showLoading) setLoading(true);
    setRefreshing(!showLoading);
    setError("");
    try {
      const [
        auditData,
        apkData,
        poolData,
        deviceData,
        capabilityData,
        snapshotData,
        jobData,
        sessionData,
        hostAgentData,
        runnerReadinessData,
        systemStatusData,
      ] = await Promise.all([
        listAudits(),
        listApkFiles(),
        listDynamicDevicePools(),
        listDynamicDevices(),
        listDynamicDeviceCapabilities(),
        listDynamicEmulatorSnapshots(),
        listDynamicJobs(),
        listDynamicSessions(),
        getDynamicHostAgentStatus(),
        getDynamicRunnerReadiness(),
        getSystemStatus(),
      ]);
      setAudits(auditData);
      setApkFiles(apkData);
      setPools(poolData);
      setDevices(deviceData);
      setCapabilities(capabilityData);
      setSnapshots(snapshotData);
      setJobs(jobData);
      setSessions(sessionData);
      setAgentStatus(hostAgentData);
      setRunnerReadiness(runnerReadinessData);
      setSystemStatus(systemStatusData);
      setSelectedAuditId((current) => current || auditData[0]?.id || "");
      setSelectedPoolId((current) => current || poolData[0]?.id || "");
      setSelectedJobId((current) => current || jobData[0]?.id || "");
    } catch (requestError) {
      setError(errorMessage(requestError));
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

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

  const capabilitiesByDevice = useMemo(() => {
    const grouped = new Map<number, DynamicDeviceCapability[]>();
    capabilities.forEach((capability) => {
      grouped.set(capability.device, [
        ...(grouped.get(capability.device) || []),
        capability,
      ]);
    });
    return grouped;
  }, [capabilities]);

  const snapshotsByDevice = useMemo(() => {
    const grouped = new Map<number, DynamicEmulatorSnapshot[]>();
    snapshots.forEach((snapshot) => {
      grouped.set(snapshot.device, [...(grouped.get(snapshot.device) || []), snapshot]);
    });
    return grouped;
  }, [snapshots]);

  const auditNames = useMemo(
    () => new Map(audits.map((audit) => [audit.id, audit.name])),
    [audits],
  );
  const deviceNames = useMemo(
    () => new Map(devices.map((device) => [device.id, device.name])),
    [devices],
  );
  const selectedJob = jobs.find((job) => job.id === selectedJobId) || jobs[0];
  const auditApkFiles = apkFiles.filter((apk) => apk.audit === selectedAuditId);
  const selectedApk =
    auditApkFiles.find((apk) => apk.id === selectedApkId) || auditApkFiles[0];
  const latestJob = jobs[0];
  const availableDevices = devices.filter((device) => device.status === "AVAILABLE");
  const activeSessions = sessions.filter(
    (session) => !TERMINAL_SESSION_STATES.has(session.state),
  );
  const minioStatus = systemStatus?.components.find(
    (component) => component.id === "minio",
  );

  useEffect(() => {
    setSelectedApkId((current) =>
      auditApkFiles.some((apk) => apk.id === current)
        ? current
        : auditApkFiles[0]?.id || "",
    );
  }, [selectedAuditId, apkFiles]);

  async function handleCreateJob(event: FormEvent) {
    event.preventDefault();
    if (selectedAuditId === "") return;

    setWorking(true);
    setError("");
    setNotice("");
    try {
      const request: DynamicJobCreateRequest = {
        audit: selectedAuditId,
        mode: "COMBINED",
        requested_tool_profile: toolProfile,
        requested_interaction_mode: interactionMode,
      };
      if (selectedPoolId !== "") {
        request.requested_device_pool = selectedPoolId;
      }
      const job = await createDynamicJob(request);
      setJobs((current) => [job, ...current.filter((item) => item.id !== job.id)]);
      setSelectedJobId(job.id);
      setNotice(`Dynamic MVP job #${job.id} was created for audit #${job.audit}.`);
    } catch (requestError) {
      setError(dynamicErrorMessage(requestError));
    } finally {
      setWorking(false);
    }
  }

  async function handleRunJob(jobId?: number) {
    const runJobId = jobId || selectedJob?.id;
    if (!runJobId) return;

    setWorking(true);
    setError("");
    setNotice("");
    try {
      const response = await runDynamicMvpJob(runJobId, {
        include_platform_tls_probe: includePlatformTlsProbe,
      });
      setJobs((current) =>
        current.map((job) => (job.id === response.job.id ? response.job : job)),
      );
      setSelectedJobId(response.job.id);
      setNotice(response.execution_mode === "synchronous"
        ? `Dynamic MVP job #${response.job.id} finished synchronous demo execution with ${response.job.status}.`
        : `Dynamic MVP job #${response.job.id} was queued as task ${response.task_id}. Refresh to follow session evidence.`
      );
      await loadWorkspace(false);
    } catch (requestError) {
      setError(dynamicErrorMessage(requestError));
    } finally {
      setWorking(false);
    }
  }

  async function handleCancelJob(jobId: number) {
    setWorking(true);
    setError("");
    setNotice("");
    try {
      const cancelled = await cancelDynamicJob(jobId);
      setJobs((current) =>
        current.map((job) => (job.id === cancelled.id ? cancelled : job)),
      );
      setNotice(`Dynamic job #${jobId} was cancelled before execution.`);
      await loadWorkspace(false);
    } catch (requestError) {
      setError(dynamicErrorMessage(requestError));
    } finally {
      setWorking(false);
    }
  }

  function addAgentActivity(result: DynamicHostAgentActionResult) {
    setAgentActivity((current) => [
      {
        action: result.action,
        status: result.status,
        duration: result.duration_seconds,
        at: new Date().toISOString(),
      },
      ...current,
    ].slice(0, 6));
  }

  async function handleRefreshAgentStatus() {
    setAgentWorking("status");
    setAgentError("");
    try {
      const result = await getDynamicHostAgentStatus();
      setAgentStatus(result);
      if (!result.connected) setAgentError(result.detail);
    } catch (requestError) {
      setAgentError(hostAgentErrorMessage(requestError));
    } finally {
      setAgentWorking("");
    }
  }

  async function handleSyncAgent() {
    setAgentWorking("sync");
    setAgentError("");
    try {
      const result = await syncDynamicHostAgent();
      setAgentStatus(result);
      setNotice("Emulator metadata synchronized into the dynamic device inventory.");
      await loadWorkspace(false);
    } catch (requestError) {
      setAgentError(hostAgentErrorMessage(requestError));
    } finally {
      setAgentWorking("");
    }
  }

  async function handleAgentAction(
    action:
      | "preflight"
      | "restore-instrumented-snapshot"
      | "frida-smoke"
      | "mitmproxy-smoke"
      | "platform-tls-probe"
      | "verify-trust-state"
      | "apply-lab-proxy"
      | "clear-lab-proxy"
      | "cleanup",
  ) {
    if (
      action === "platform-tls-probe" &&
      !window.confirm(
        "The platform TLS probe is slow and disrupts temporary emulator network state. Continue?",
      )
    ) {
      return;
    }
    setAgentWorking(action);
    setAgentError("");
    try {
      const result = await runDynamicHostAgentAction(action);
      addAgentActivity(result);
      if (result.evidence) {
        setLatestEvidence({ action: result.action, evidence: result.evidence });
      }
      setNotice(`${formatEnum(result.action)} finished with ${result.status}.`);
      if (action === "frida-smoke" || action === "mitmproxy-smoke") {
        await handleRefreshAgentStatus();
      }
    } catch (requestError) {
      setAgentError(hostAgentErrorMessage(requestError));
    } finally {
      setAgentWorking("");
    }
  }

  async function handleScreenshot() {
    setAgentWorking("screenshot");
    setAgentError("");
    try {
      const blob = await captureDynamicHostAgentScreenshot();
      if (screenshotUrlRef.current) {
        URL.revokeObjectURL(screenshotUrlRef.current);
      }
      const objectUrl = URL.createObjectURL(blob);
      screenshotUrlRef.current = objectUrl;
      setScreenshotUrl(objectUrl);
      setScreenshotFilename(
        `MSAP_${(agentStatus?.device?.serial || "emulator").replace(/[^a-zA-Z0-9_-]/g, "-")}_${new Date().toISOString().replace(/[:.]/g, "-")}.png`,
      );
      addAgentActivity({
        action: "screenshot",
        success: true,
        status: "PASS",
      });
    } catch (requestError) {
      setAgentError(hostAgentErrorMessage(requestError));
    } finally {
      setAgentWorking("");
    }
  }

  async function handleListPackages() {
    setAgentWorking("packages");
    setAgentError("");
    try {
      const result = await listDynamicHostAgentPackages();
      setKnownPackages(result.packages);
      setNotice(`${result.count} bounded package names read from the emulator.`);
    } catch (requestError) {
      setAgentError(hostAgentErrorMessage(requestError));
    } finally {
      setAgentWorking("");
    }
  }

  async function handleInstallApk() {
    if (selectedAuditId === "" || !selectedApk) return;
    setAgentWorking("install-apk");
    setAgentError("");
    setInstallResult(null);
    try {
      const result = await installDynamicAuditApk(
        selectedAuditId,
        selectedApk.id,
      );
      setInstallResult(result);
      if (result.package_name) setPackageName(result.package_name);
      addAgentActivity(result);
      setNotice(
        `Uploaded APK #${result.apk_file} install finished with ${result.install_status}.`,
      );
    } catch (requestError) {
      setAgentError(hostAgentErrorMessage(requestError));
    } finally {
      setAgentWorking("");
    }
  }

  async function handlePackageAction(
    action: "launch-package" | "force-stop" | "clear-data" | "uninstall",
  ) {
    if (!packageName.trim()) return;
    if (
      (action === "clear-data" || action === "uninstall") &&
      !window.confirm(
        action === "clear-data"
          ? `Clear all application data for ${packageName.trim()}?`
          : `Uninstall ${packageName.trim()} from the managed emulator?`,
      )
    ) {
      return;
    }
    setAgentWorking(action);
    setAgentError("");
    try {
      const result = await runDynamicHostAgentPackageAction(
        action,
        packageName.trim(),
      );
      addAgentActivity(result);
      setNotice(
        action === "launch-package" && result.focused_activity
          ? `Launched ${packageName.trim()}; focused activity is ${result.focused_activity}.`
          : `${formatEnum(action)} finished with ${result.status}.`,
      );
      await Promise.all([handleRefreshAgentStatus(), handleListPackages()]);
    } catch (requestError) {
      setAgentError(hostAgentErrorMessage(requestError));
    } finally {
      setAgentWorking("");
    }
  }

  if (loading) return <LoadingState label="Loading dynamic lab workspace..." />;

  return (
    <>
      <PageHeader
        eyebrow="Dynamic MVP"
        title="Dynamic Lab"
        description="Validated Android runtime lab for Frida, mitmproxy, snapshots, and platform TLS proof."
        actions={
          <button
            className="button button-secondary"
            onClick={() => void loadWorkspace(false)}
            disabled={refreshing || working}
          >
            {refreshing ? "Refreshing..." : "Refresh"}
          </button>
        }
      />
      {error ? <ErrorMessage message={error} /> : null}
      {notice ? <div className="alert alert-success">{notice}</div> : null}

      <div className="dynamic-dependency-strip" aria-label="Dynamic dependencies">
        <DependencyChip
          label="Host agent"
          value={agentStatus?.connected ? "ONLINE" : "OFFLINE"}
        />
        <DependencyChip
          label="Emulator"
          value={agentStatus?.device?.state === "device" ? "ONLINE" : "OFFLINE"}
        />
        <DependencyChip
          label="MinIO"
          value={minioStatus?.status === "OPERATIONAL" ? "ONLINE" : minioStatus ? "OFFLINE" : "UNKNOWN"}
        />
        <DependencyChip
          label="Celery"
          value={runnerReadiness?.worker_status || "UNKNOWN"}
        />
        <DependencyChip
          label="Dynamic runner"
          value={runnerReadiness?.ready ? "READY" : "OFFLINE"}
        />
      </div>

      <div className="metric-grid dynamic-metrics">
        <MetricCard
          label="Registered devices"
          value={devices.length}
          detail={`${availableDevices.length} available`}
          accent
        />
        <MetricCard
          label="Runtime capabilities"
          value={capabilities.filter((capability) => capability.is_available).length}
          detail="ADB, root, Frida, mitmproxy, CA, snapshots"
        />
        <MetricCard
          label="Active sessions"
          value={activeSessions.length}
          detail={`${sessions.length} total sessions`}
        />
        <MetricCard
          label="Latest job"
          value={latestJob ? formatEnum(latestJob.status) : "None"}
          detail={latestJob ? `Job #${latestJob.id}` : "Create a dynamic MVP job"}
        />
      </div>

      <Card className="emulator-control-panel">
        <SectionHeader
          title="Emulator Control"
          description="Authenticated controls for the managed Android emulator."
          actions={
            <div className="emulator-header-actions">
              <StatusBadge
                value={agentStatus?.connected ? "CONNECTED" : "DISCONNECTED"}
              />
              <button
                className="button button-secondary"
                type="button"
                onClick={() => void handleRefreshAgentStatus()}
                disabled={Boolean(agentWorking)}
              >
                {agentWorking === "status" ? "Checking..." : "Refresh Agent Status"}
              </button>
              <button
                className="button button-primary"
                type="button"
                onClick={() => void handleSyncAgent()}
                disabled={
                  !canOperate || !agentStatus?.connected || Boolean(agentWorking)
                }
              >
                {agentWorking === "sync" ? "Syncing..." : "Sync Device"}
              </button>
            </div>
          }
        />

        {agentError ? <div className="alert alert-error">{agentError}</div> : null}
        {!agentStatus?.connected ? (
          <div className="agent-connection-help">
            <strong>
              {agentStatus?.detail ||
                "Start the local dynamic host agent on WSL to control the emulator."}
            </strong>
            <span>Check the configured host-agent URL and local agent process.</span>
          </div>
        ) : null}

        <div className="emulator-status-grid">
          <AgentStat label="Serial" value={agentStatus?.device?.serial || "—"} mono />
          <AgentStat label="State" value={agentStatus?.device?.state || "unknown"} />
          <AgentStat
            label="Android"
            value={
              agentStatus?.device
                ? `${agentStatus.device.android_version || "?"} / API ${agentStatus.device.api_level || "?"}`
                : "—"
            }
          />
          <AgentStat label="ABI" value={agentStatus?.device?.abi || "—"} mono />
          <AgentStat label="SELinux" value={agentStatus?.device?.selinux || "—"} />
          <AgentStat
            label="Root"
            value={agentStatus?.device?.root_uid === 0 ? "uid 0" : "not confirmed"}
          />
          <AgentStat label="Proxy" value={agentStatus?.device?.proxy || "—"} mono />
          <AgentStat
            label="Frida"
            value={
              agentStatus?.device?.frida_smoke === true
                ? "smoke passed"
                : agentStatus?.device?.frida_server_running
                  ? "server running"
                  : "not confirmed"
            }
          />
          <AgentStat label="Last sync" value={formatDate(agentStatus?.last_sync_at)} />
        </div>

        <div className="emulator-control-grid">
          <section className="emulator-actions-pane">
            <div className="agent-section-heading">
              <div>
                <strong>Allowlisted lab actions</strong>
                <span>Fixed scripts only; output is bounded and redacted.</span>
              </div>
            </div>
            <div className="agent-action-grid">
              <AgentActionButton
                label="Screenshot"
                action="screenshot"
                working={agentWorking}
                disabled={!agentStatus?.connected}
                onClick={handleScreenshot}
              />
              <AgentActionButton
                label="Run Preflight"
                action="preflight"
                working={agentWorking}
                disabled={!canOperate || !agentStatus?.connected}
                onClick={() => handleAgentAction("preflight")}
              />
              <AgentActionButton
                label="Restore Instrumented Snapshot"
                action="restore-instrumented-snapshot"
                working={agentWorking}
                disabled={!canOperate || !agentStatus?.connected}
                onClick={() => handleAgentAction("restore-instrumented-snapshot")}
              />
              <AgentActionButton
                label="Verify Trust State"
                action="verify-trust-state"
                working={agentWorking}
                disabled={!canOperate || !agentStatus?.connected}
                onClick={() => handleAgentAction("verify-trust-state")}
              />
              <AgentActionButton
                label="Apply Configured Lab Proxy"
                action="apply-lab-proxy"
                working={agentWorking}
                disabled={!canOperate || !agentStatus?.connected}
                onClick={() => handleAgentAction("apply-lab-proxy")}
              />
              <AgentActionButton
                label="Clear Lab Proxy"
                action="clear-lab-proxy"
                working={agentWorking}
                disabled={!canOperate || !agentStatus?.connected}
                onClick={() => handleAgentAction("clear-lab-proxy")}
              />
              <AgentActionButton
                label="Frida Smoke"
                action="frida-smoke"
                working={agentWorking}
                disabled={!canOperate || !agentStatus?.connected}
                onClick={() => handleAgentAction("frida-smoke")}
              />
              <AgentActionButton
                label="mitmproxy Smoke"
                action="mitmproxy-smoke"
                working={agentWorking}
                disabled={!canOperate || !agentStatus?.connected}
                onClick={() => handleAgentAction("mitmproxy-smoke")}
              />
              <AgentActionButton
                label="Platform TLS Probe"
                detail="slow / disruptive"
                action="platform-tls-probe"
                working={agentWorking}
                disabled={!canOperate || !agentStatus?.connected}
                onClick={() => handleAgentAction("platform-tls-probe")}
              />
              <AgentActionButton
                label="Cleanup Runtime"
                action="cleanup"
                working={agentWorking}
                disabled={!canOperate || !agentStatus?.connected}
                onClick={() => handleAgentAction("cleanup")}
              />
            </div>

            <div className="agent-apk-controls">
              <div className="agent-section-heading">
                <div>
                  <strong>Install an uploaded audit APK</strong>
                  <span>Only APK bytes already tracked by MSAP storage are accepted.</span>
                </div>
              </div>
              <div className="agent-install-row">
                <label>
                  Audit
                  <select
                    value={selectedAuditId}
                    onChange={(event) =>
                      setSelectedAuditId(
                        event.target.value ? Number(event.target.value) : "",
                      )
                    }
                    disabled={!canOperate || Boolean(agentWorking)}
                  >
                    <option value="">Select audit</option>
                    {audits.map((audit) => (
                      <option value={audit.id} key={audit.id}>
                        #{audit.id} {audit.name}
                      </option>
                    ))}
                  </select>
                </label>
                <label>
                  Uploaded APK
                  <select
                    value={selectedApk?.id || ""}
                    onChange={(event) =>
                      setSelectedApkId(
                        event.target.value ? Number(event.target.value) : "",
                      )
                    }
                    disabled={!canOperate || Boolean(agentWorking)}
                  >
                    <option value="">Select APK</option>
                    {auditApkFiles.map((apk) => (
                      <option value={apk.id} key={apk.id}>
                        #{apk.id} {apk.package_name || apk.sha256.slice(0, 12) || "uploaded APK"}
                      </option>
                    ))}
                  </select>
                </label>
                <button
                  className="button button-primary"
                  type="button"
                  onClick={() => void handleInstallApk()}
                  disabled={
                    !canOperate ||
                    !agentStatus?.connected ||
                    !selectedApk ||
                    selectedApk.storage_status !== "VERIFIED" ||
                    Boolean(agentWorking)
                  }
                >
                  {agentWorking === "install-apk"
                    ? "Installing..."
                    : "Install Uploaded APK"}
                </button>
              </div>
              {selectedApk && selectedApk.storage_status !== "VERIFIED" ? (
                <p className="dependency-note">
                  Install is disabled until MinIO confirms this APK as VERIFIED.
                </p>
              ) : null}
              {installResult ? (
                <div className="installed-package-card">
                  <div className="agent-install-result">
                    <StatusBadge value={installResult.install_status} />
                    <span>APK #{installResult.apk_file}</span>
                    <code>{installResult.sha256.slice(0, 16)}…</code>
                    <span>{installResult.duration_seconds?.toFixed(1)}s</span>
                  </div>
                  <dl>
                    <div><dt>Package</dt><dd>{installResult.package_metadata.package_name || "Not resolved"}</dd></div>
                    <div><dt>Version</dt><dd>{installResult.package_metadata.version_name || "—"} ({installResult.package_metadata.version_code || "—"})</dd></div>
                    <div><dt>Activity</dt><dd>{installResult.package_metadata.launchable_activity || "Not launchable"}</dd></div>
                    <div><dt>APK path</dt><dd>{installResult.package_metadata.installed_apk_path || "—"}</dd></div>
                    <div><dt>Permissions</dt><dd>{installResult.package_metadata.granted_permission_count} granted / {installResult.package_metadata.requested_permission_count} requested</dd></div>
                  </dl>
                </div>
              ) : null}
            </div>

            <div className="agent-package-controls">
              <label>
                Package control
                <input
                  value={packageName}
                  onChange={(event) => setPackageName(event.target.value)}
                  placeholder="com.example.app"
                  list="emulator-package-names"
                  disabled={!canOperate || Boolean(agentWorking)}
                />
                <datalist id="emulator-package-names">
                  {knownPackages.map((item) => (
                    <option value={item} key={item} />
                  ))}
                </datalist>
              </label>
              <button
                className="button button-secondary"
                type="button"
                onClick={() => void handleListPackages()}
                disabled={!agentStatus?.connected || Boolean(agentWorking)}
              >
                {agentWorking === "packages" ? "Reading..." : "List Packages"}
              </button>
              {(["launch-package", "force-stop", "clear-data", "uninstall"] as const).map(
                (action) => (
                  <button
                    className="button button-secondary"
                    type="button"
                    key={action}
                    onClick={() => void handlePackageAction(action)}
                    disabled={
                      !canOperate ||
                      !agentStatus?.connected ||
                      !packageName.trim() ||
                      Boolean(agentWorking)
                    }
                  >
                    {agentWorking === action
                      ? "Working..."
                      : formatEnum(action)}
                  </button>
                ),
              )}
            </div>
            {!canOperate ? (
              <p className="notice">
                Viewer access can inspect status, packages, and screenshots. Emulator
                mutations require an analyst or administrator role.
              </p>
            ) : null}
          </section>

          <aside className="emulator-evidence-pane">
            <div className="agent-section-heading">
              <div>
                <strong>Live emulator evidence</strong>
                <span>The prior browser object URL is released on every capture.</span>
              </div>
              {screenshotUrl ? (
                <a
                  className="screenshot-download"
                  href={screenshotUrl}
                  download={screenshotFilename}
                >
                  Download PNG
                </a>
              ) : null}
            </div>
            <div
              className={`emulator-screen-frame${screenshotUrl ? " has-capture" : ""}`}
            >
              {screenshotUrl ? (
                <img src={screenshotUrl} alt="Latest Android emulator screenshot" />
              ) : (
                <div><span>No capture</span></div>
              )}
            </div>
            <div className="agent-activity-list">
              {agentActivity.length ? (
                agentActivity.map((item, index) => (
                  <div key={`${item.at}-${item.action}-${index}`}>
                    <span className={`agent-event-dot ${item.status.toLowerCase()}`} />
                    <strong>{formatEnum(item.action)}</strong>
                    <StatusBadge value={item.status} />
                    <small>
                      {item.duration === undefined
                        ? formatDate(item.at)
                        : `${item.duration.toFixed(1)}s`}
                    </small>
                  </div>
                ))
              ) : (
                <p className="notice">Action stages and results will appear here.</p>
              )}
            </div>
            {latestEvidence ? (
              <StructuredEvidencePanel
                action={latestEvidence.action}
                evidence={latestEvidence.evidence}
              />
            ) : null}
          </aside>
        </div>
      </Card>

      <div className="content-grid dynamic-workspace-grid">
        <Card className="dynamic-hero-panel">
          <SectionHeader
            title="Runtime Orchestration"
            description="This workspace proves local lab readiness and stores stage evidence for the MVP runner."
            actions={
              <label className="toggle-field">
                <input
                  type="checkbox"
                  checked={includePlatformTlsProbe}
                  onChange={(event) => setIncludePlatformTlsProbe(event.target.checked)}
                />
                <span>Platform TLS probe</span>
              </label>
            }
          />
          <form className="form-grid dynamic-job-form" onSubmit={handleCreateJob}>
            <label>
              Audit
              <select
                value={selectedAuditId}
                onChange={(event) =>
                  setSelectedAuditId(event.target.value ? Number(event.target.value) : "")
                }
                disabled={!canOperate || working}
                required
              >
                <option value="">Select audit</option>
                {audits.map((audit) => (
                  <option value={audit.id} key={audit.id}>
                    #{audit.id} {audit.name}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Device pool
              <select
                value={selectedPoolId}
                onChange={(event) =>
                  setSelectedPoolId(event.target.value ? Number(event.target.value) : "")
                }
                disabled={!canOperate || working}
              >
                <option value="">Auto select</option>
                {pools.map((pool) => (
                  <option value={pool.id} key={pool.id}>
                    {pool.name}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Tool profile
              <select
                value={toolProfile}
                onChange={(event) =>
                  setToolProfile(
                    event.target
                      .value as DynamicJobCreateRequest["requested_tool_profile"],
                  )
                }
                disabled={!canOperate || working}
              >
                {TOOL_PROFILE_OPTIONS.map((profile) => (
                  <option value={profile} key={profile}>
                    {formatEnum(profile)}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Interaction mode
              <select
                value={interactionMode}
                onChange={(event) =>
                  setInteractionMode(
                    event.target
                      .value as DynamicJobCreateRequest["requested_interaction_mode"],
                  )
                }
                disabled={!canOperate || working}
              >
                {INTERACTION_MODE_OPTIONS.map((mode) => (
                  <option value={mode} key={mode}>
                    {formatEnum(mode)}
                  </option>
                ))}
              </select>
            </label>
            <button
              className="button button-primary"
              disabled={
                !canOperate ||
                working ||
                selectedAuditId === "" ||
                !runnerReadiness?.ready
              }
            >
              Create Dynamic MVP Job
            </button>
            <button
              className="button button-secondary"
              type="button"
              onClick={() => void handleRunJob()}
              disabled={
                !canOperate ||
                working ||
                !runnerReadiness?.ready ||
                !selectedJob ||
                !RUNNABLE_JOB_STATUSES.has(selectedJob.status)
              }
            >
              Run MVP
            </button>
          </form>
          {!runnerReadiness?.ready ? (
            <p className="dependency-note">
              {runnerReadiness?.detail || "Dynamic runner readiness is unknown."}
            </p>
          ) : runnerReadiness.sync_demo_enabled ? (
            <p className="dependency-note">
              Synchronous demo mode is active. The browser request can remain open for several minutes.
            </p>
          ) : null}
          {!canOperate ? (
            <p className="notice">
              Viewer access is read-only. An analyst or administrator can create
              and run dynamic MVP jobs.
            </p>
          ) : null}
        </Card>

        <Card className="limitations-card" title="Honest MVP Limits">
          <ul className="limitations-list">
            <li>
              Current dynamic MVP proves lab orchestration and platform TLS
              capability only.
            </li>
            <li>APK install is controlled; app exercise and verdicts remain analyst-led.</li>
            <li>No malware verdict or behavioral vulnerability confirmation is produced.</li>
            <li>
              TLS interception is not guaranteed for apps with pinning or custom
              trust stores.
            </li>
          </ul>
        </Card>
      </div>

      <Card title="Device inventory">
        {devices.length ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Serial</th>
                  <th>Status</th>
                  <th>Runtime</th>
                  <th>Capabilities</th>
                  <th>Snapshot</th>
                  <th>Health check</th>
                </tr>
              </thead>
              <tbody>
                {devices.map((device) => {
                  const deviceCapabilities = capabilitiesByDevice.get(device.id) || [];
                  const deviceSnapshots = snapshotsByDevice.get(device.id) || [];
                  return (
                    <tr key={device.id}>
                      <td>
                        <strong>{device.name}</strong>
                        <small>{device.pool_name || "No pool"}</small>
                      </td>
                      <td className="mono">{device.serial}</td>
                      <td>
                        <StatusBadge value={device.status} />
                      </td>
                      <td>
                        API {device.api_level}
                        <small>
                          {device.abi} {device.android_version || ""}
                        </small>
                      </td>
                      <td>
                        <CapabilityStrip capabilities={deviceCapabilities} />
                      </td>
                      <td>
                        {device.current_snapshot || deviceSnapshots[0]?.name || "-"}
                        <small>
                          {device.has_frida ? "Frida ready" : "Frida missing"} /
                          {device.has_mitm_ready ? " mitm ready" : " mitm missing"}
                        </small>
                      </td>
                      <td>{formatDate(device.last_health_check_at)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState message="No dynamic devices yet. Seed the local lab and run the MVP runner." />
        )}
      </Card>

      <div className="content-grid two-column dynamic-lists-grid">
        <Card title="Dynamic jobs">
          {jobs.length ? (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Job</th>
                    <th>Audit</th>
                    <th>Profile</th>
                    <th>Status</th>
                    <th>Queued</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {jobs.slice(0, 8).map((job) => (
                    <tr key={job.id}>
                      <td>
                        <strong>#{job.id}</strong>
                        <small>{formatEnum(job.requested_interaction_mode)}</small>
                      </td>
                      <td>{auditNames.get(job.audit) || `#${job.audit}`}</td>
                      <td>{formatEnum(job.requested_tool_profile)}</td>
                      <td>
                        <StatusBadge value={job.status} />
                      </td>
                      <td>{formatDate(job.queued_at)}</td>
                      <td className="align-right">
                        <button
                          className="text-button"
                          onClick={() => void handleRunJob(job.id)}
                          disabled={
                            !canOperate ||
                            working ||
                            !RUNNABLE_JOB_STATUSES.has(job.status)
                          }
                        >
                          run MVP
                        </button>
                        {job.status === "QUEUED" ? (
                          <button
                            className="text-button danger"
                            onClick={() => void handleCancelJob(job.id)}
                            disabled={!canOperate || working}
                          >
                            cancel
                          </button>
                        ) : null}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState message="No dynamic jobs yet. Create one from an audit with an uploaded APK." />
          )}
        </Card>

        <Card title="Latest sessions">
          {sessions.length ? (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Job</th>
                    <th>Device</th>
                    <th>State</th>
                    <th>Cleanup</th>
                    <th>Started</th>
                    <th>Finished</th>
                  </tr>
                </thead>
                <tbody>
                  {sessions.slice(0, 8).map((session) => (
                    <tr key={session.id}>
                      <td>
                        <Link to={`/dynamic/sessions/${session.id}`}>
                          Session #{session.id}
                        </Link>
                      </td>
                      <td>#{session.job}</td>
                      <td>{deviceNames.get(session.device) || session.device_serial}</td>
                      <td>
                        <StatusBadge value={session.state} />
                      </td>
                      <td>
                        <StatusBadge value={session.cleanup_status} />
                      </td>
                      <td>{formatDate(session.started_at)}</td>
                      <td>{formatDate(session.finished_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState message="No dynamic sessions yet. Seed the local lab and run the MVP runner." />
          )}
        </Card>
      </div>
    </>
  );
}

function AgentStat({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="agent-stat">
      <span>{label}</span>
      <strong className={mono ? "mono" : undefined}>{value}</strong>
    </div>
  );
}

function DependencyChip({ label, value }: { label: string; value: string }) {
  const normalized = value.toLowerCase();
  return (
    <div className={`dependency-chip dependency-${normalized}`}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function StructuredEvidencePanel({
  action,
  evidence,
}: {
  action: string;
  evidence: Record<string, unknown>;
}) {
  const sections = action === "frida-smoke"
    ? [
        ["Connection", ["emulator_serial", "remote_endpoint", "connection_established"]],
        ["Version agreement", ["client_version", "server_version", "version_match"]],
        ["Instrumentation event", ["injected_script_event_received"]],
        ["Process evidence", ["test_package_process", "spawned_or_attached_pid", "process_architecture", "process_count"]],
        ["Cleanup", ["cleanup_result", "final_status", "duration_seconds"]],
        ["Interpretation", ["interpretation"]],
        ["Limitations", ["limitations"]],
      ]
    : action === "mitmproxy-smoke"
      ? [
          ["Proxy configuration", ["mitmproxy_version", "proxy_bind_host", "proxy_bind_port", "emulator_proxy_state"]],
          ["Probe request", ["probe_target_host", "request_method", "response_status"]],
          ["Captured flow", ["captured_flow_count", "matching_flow_token_found"]],
          ["TLS / trust result", ["tls_interception_result", "certificate_trust_mode"]],
          ["Cleanup", ["cleanup_result", "final_status", "duration_seconds"]],
          ["Interpretation", ["interpretation"]],
          ["Limitations", ["limitations"]],
        ]
      : [["Controlled lab state", Object.keys(evidence)]];

  function downloadEvidence() {
    const blob = new Blob([JSON.stringify({ action, evidence }, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `msap-${action}-evidence.json`;
    link.click();
    URL.revokeObjectURL(url);
  }

  return (
    <section className="structured-evidence">
      <div className="agent-section-heading">
        <div>
          <strong>{formatEnum(action)} evidence</strong>
          <span>Bounded, redacted auditor summary</span>
        </div>
        <button className="text-button" type="button" onClick={downloadEvidence}>
          download JSON
        </button>
      </div>
      {sections.map(([title, keys]) => (
        <div className="evidence-section" key={String(title)}>
          <strong>{String(title)}</strong>
          <dl>
            {(keys as string[]).map((key) => (
              key in evidence ? (
                <div key={key}>
                  <dt>{formatEnum(key)}</dt>
                  <dd>{formatEvidenceValue(evidence[key])}</dd>
                </div>
              ) : null
            ))}
          </dl>
        </div>
      ))}
    </section>
  );
}

function formatEvidenceValue(value: unknown): string {
  if (value === null || value === undefined || value === "") return "—";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function AgentActionButton({
  label,
  detail,
  action,
  working,
  disabled,
  onClick,
}: {
  label: string;
  detail?: string;
  action: string;
  working: string;
  disabled: boolean;
  onClick: () => void | Promise<void>;
}) {
  return (
    <button
      className="agent-action-button"
      type="button"
      onClick={() => void onClick()}
      disabled={disabled || Boolean(working)}
    >
      <span>{working === action ? "Running..." : label}</span>
      {detail ? <small>{detail}</small> : null}
    </button>
  );
}

function CapabilityStrip({
  capabilities,
}: {
  capabilities: DynamicDeviceCapability[];
}) {
  return (
    <div className="capability-strip">
      {REQUIRED_CAPABILITIES.map((capabilityType) => {
        const capability = capabilities.find(
          (item) => item.capability_type === capabilityType,
        );
        return (
          <span
            className={`capability-chip ${capability?.is_available ? "available" : ""}`}
            key={capabilityType}
            title={capability?.name || formatEnum(capabilityType)}
          >
            {capabilityType.replace("MITMPROXY_ROUTE", "MITM")}
          </span>
        );
      })}
    </div>
  );
}

function dynamicErrorMessage(requestError: unknown): string {
  const message = errorMessage(requestError);
  if (
    requestError instanceof ApiError &&
    requestError.status === 409 &&
    message.toLowerCase().includes("disabled")
  ) {
    return `${message} Enable MSAP_DYNAMIC_RUNNER_ENABLED=true for local demo execution.`;
  }
  return message;
}

function hostAgentErrorMessage(requestError: unknown): string {
  if (requestError instanceof ApiError) {
    if (requestError.status === 403) {
      return "Your MSAP role does not permit this emulator action.";
    }
    if (requestError.code === "HOST_AGENT_DISABLED") {
      return "Start the local dynamic host agent on WSL to control the emulator.";
    }
    if (requestError.code === "HOST_AGENT_UNREACHABLE") {
      return "Backend cannot reach host-agent. Check MSAP_DYNAMIC_HOST_AGENT_URL and agent process.";
    }
  }
  return errorMessage(requestError);
}
