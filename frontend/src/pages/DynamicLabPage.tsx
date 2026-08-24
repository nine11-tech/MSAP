import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import {
  captureDynamicHostAgentScreenshot,
  getDynamicHostAgentStatus,
  getOpenAIBudgetStatus,
  installDynamicAuditApk,
  listApkFiles,
  listAudits,
  listDynamicHostAgentPackages,
  resetOpenAIBudget,
  runDynamicHostAgentPackageAction,
} from "../api/msap";
import type {
  ApkFile,
  Audit,
  DynamicHostAgentInstallResult,
  DynamicHostAgentStatus,
  OpenAIBudgetStatus,
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

type WorkingAction =
  | ""
  | "refresh"
  | "budget-reset"
  | "install"
  | "launch-package"
  | "force-stop"
  | "uninstall"
  | "screenshot";

type PackageAction = "launch-package" | "force-stop" | "uninstall";

export function DynamicLabPage() {
  const [audits, setAudits] = useState<Audit[]>([]);
  const [apkFiles, setApkFiles] = useState<ApkFile[]>([]);
  const [selectedAuditId, setSelectedAuditId] = useState<number | "">("");
  const [selectedApkId, setSelectedApkId] = useState<number | "">("");
  const [packages, setPackages] = useState<string[]>([]);
  const [packageName, setPackageName] = useState("");
  const [agentStatus, setAgentStatus] = useState<DynamicHostAgentStatus | null>(
    null,
  );
  const [openAiBudget, setOpenAiBudget] = useState<OpenAIBudgetStatus | null>(
    null,
  );
  const [installResult, setInstallResult] =
    useState<DynamicHostAgentInstallResult | null>(null);
  const [screenshotUrl, setScreenshotUrl] = useState("");
  const screenshotUrlRef = useRef("");
  const [loading, setLoading] = useState(true);
  const [working, setWorking] = useState<WorkingAction>("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const { hasRole } = useAuth();
  const canOperate = hasRole("ADMIN", "ANALYST");

  const loadConsole = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [auditData, apkData, hostData, packageData, budgetData] =
        await Promise.all([
          listAudits(),
          listApkFiles(),
          getDynamicHostAgentStatus().catch(() => null),
          listDynamicHostAgentPackages().catch(() => ({
            packages: [],
            count: 0,
            truncated: false,
          })),
          getOpenAIBudgetStatus().catch(() => null),
        ]);
      setAudits(auditData);
      setApkFiles(apkData);
      setAgentStatus(hostData);
      setPackages(packageData.packages);
      setOpenAiBudget(budgetData);
      setSelectedAuditId((current) =>
        current && auditData.some((audit) => audit.id === current)
          ? current
          : auditData[0]?.id || "",
      );
    } catch (requestError) {
      setError(errorMessage(requestError));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadConsole();
  }, [loadConsole]);

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

  useEffect(() => {
    setSelectedApkId((current) =>
      current && verifiedApks.some((apk) => apk.id === current)
        ? current
        : verifiedApks[0]?.id || "",
    );
    setInstallResult(null);
  }, [verifiedApks]);

  const selectedAudit = audits.find((audit) => audit.id === selectedAuditId);
  const selectedApk = verifiedApks.find((apk) => apk.id === selectedApkId);
  const emulatorOnline = agentStatus?.device?.state === "device";
  const targetInstalled = Boolean(
    packageName.trim() && packages.includes(packageName.trim()),
  );

  useEffect(() => {
    if (selectedApk?.package_name) {
      setPackageName(selectedApk.package_name);
    }
  }, [selectedApk]);

  async function refreshPackages() {
    const result = await listDynamicHostAgentPackages();
    setPackages(result.packages);
  }

  async function handleRefresh() {
    setWorking("refresh");
    setError("");
    setNotice("");
    try {
      const [hostData, packageData, budgetData] = await Promise.all([
        getDynamicHostAgentStatus(),
        listDynamicHostAgentPackages().catch(() => ({
          packages: [],
          count: 0,
          truncated: false,
        })),
        getOpenAIBudgetStatus().catch(() => null),
      ]);
      setAgentStatus(hostData);
      setPackages(packageData.packages);
      setOpenAiBudget(budgetData);
      setNotice("Lab readiness refreshed.");
    } catch (requestError) {
      setError(errorMessage(requestError));
    } finally {
      setWorking("");
    }
  }

  async function handleResetBudget() {
    setWorking("budget-reset");
    setError("");
    setNotice("");
    try {
      setOpenAiBudget(await resetOpenAIBudget());
      setNotice("OpenAI call budget reset.");
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
      const result = await installDynamicAuditApk(selectedAuditId, selectedApkId);
      setInstallResult(result);
      if (!result.success) {
        throw new Error(result.detail || "APK installation failed.");
      }
      if (result.package_name) {
        setPackageName(result.package_name);
      }
      await refreshPackages();
      setAgentStatus(await getDynamicHostAgentStatus());
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
      await refreshPackages();
      setAgentStatus(await getDynamicHostAgentStatus());
      setNotice(
        action === "launch-package" && result.focused_activity
          ? `${packageActionLabel(action)} completed. Focused activity: ${result.focused_activity}.`
          : `${packageActionLabel(action)} completed.`,
      );
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

  if (loading) {
    return <LoadingState label="Loading Advanced Operator Console..." />;
  }

  return (
    <div className="dynamic-mvp-page advanced-console-page">
      <PageHeader
        eyebrow="MSAP · Operator tools"
        title="Advanced Operator Console"
        description="Reduced operator surface for demo use: budget control, lab readiness, package actions, and screenshot capture only."
        actions={
          <Link className="button button-secondary" to="/dynamic">
            Back to Dynamic Lab
          </Link>
        }
      />

      {error ? <ErrorMessage message={error} /> : null}
      {notice ? (
        <div className="alert alert-success" role="status">
          {notice}
        </div>
      ) : null}

      <section className="advanced-console-hero" aria-label="Advanced console summary">
        <div className="advanced-console-hero-copy">
          <span className="eyebrow">Operator scope</span>
          <h2>Minimal live controls for the managed Android demo lab</h2>
          <p>
            This page is intentionally limited to readiness checks, budget reset,
            bounded package actions, and screenshot capture.
          </p>
        </div>
        <div className="advanced-console-overview">
          <OverviewChip
            label="Host agent"
            value={agentStatus?.connected ? "Online" : "Offline"}
            tone={agentStatus?.connected ? "online" : "offline"}
          />
          <OverviewChip
            label="Emulator"
            value={emulatorOnline ? "Ready" : "Offline"}
            tone={emulatorOnline ? "online" : "offline"}
          />
          <OverviewChip
            label="AI budget"
            value={
              openAiBudget
                ? `${openAiBudget.remaining_total_calls}/${openAiBudget.max_total_openai_calls}`
                : "Unknown"
            }
            tone={
              openAiBudget?.exhausted
                ? "offline"
                : openAiBudget && openAiBudget.remaining_total_calls <= 2
                  ? "warning"
                  : "online"
            }
          />
          <OverviewChip
            label="Selected package"
            value={packageName || "None"}
            tone={packageName ? "neutral" : "warning"}
          />
        </div>
      </section>

      <Card className="dynamic-mvp-section advanced-console-card">
        <SectionHeader
          title="Lab Readiness"
          description="Current host-agent and emulator status for the managed Android lab."
          actions={
            <button
              className="button button-secondary"
              onClick={() => void handleRefresh()}
              disabled={Boolean(working)}
            >
              {working === "refresh" ? "Refreshing..." : "Refresh readiness"}
            </button>
          }
        />

        <div className="dynamic-status-strip" aria-label="Dynamic lab status">
          <span
            className={`status-pill ${agentStatus?.connected ? "is-online" : "is-offline"}`}
          >
            <i aria-hidden="true" />
            Host agent {agentStatus?.connected ? "online" : "offline"}
          </span>
          <span
            className={`status-pill ${emulatorOnline ? "is-online" : "is-offline"}`}
          >
            <i aria-hidden="true" />
            Emulator {emulatorOnline ? "ready" : "offline"}
          </span>
          <span
            className={`status-pill ${
              openAiBudget
                ? openAiBudget.exhausted
                  ? "is-offline"
                  : openAiBudget.remaining_total_calls <= 2
                    ? "is-warning"
                    : "is-online"
                : "is-unknown"
            }`}
          >
            <i aria-hidden="true" />
            AI call budget{" "}
            {openAiBudget
              ? `${openAiBudget.remaining_total_calls}/${openAiBudget.max_total_openai_calls}`
              : "unknown"}
          </span>
        </div>

        <div className="dynamic-device-facts agent-result-facts advanced-console-facts">
          <StatusFact
            label="Audit"
            value={selectedAudit?.name || "Not selected"}
            detail={selectedAudit ? `Audit #${selectedAudit.id}` : undefined}
          />
          <StatusFact
            label="Device serial"
            value={agentStatus?.device?.serial || "Unavailable"}
          />
          <StatusFact
            label="Android / API"
            value={
              agentStatus?.device
                ? `${agentStatus.device.android_version || "Unknown"} / API ${agentStatus.device.api_level || "?"}`
                : "Unavailable"
            }
          />
          <StatusFact
            label="Focused app"
            value={agentStatus?.device?.focused_app || "Unavailable"}
          />
          <StatusFact
            label="Last checked"
            value={
              agentStatus?.last_checked_at
                ? formatDate(agentStatus.last_checked_at)
                : "Unavailable"
            }
          />
        </div>
      </Card>

      <Card className="dynamic-mvp-section advanced-console-card">
        <SectionHeader
          title="Budget Reset"
          description="Reset the current OpenAI budget counters for the demo environment."
          actions={
            <button
              className="button button-secondary"
              onClick={() => void handleResetBudget()}
              disabled={!canOperate || Boolean(working)}
            >
              {working === "budget-reset" ? "Resetting..." : "Reset budget"}
            </button>
          }
        />

        <div className="dynamic-device-facts agent-result-facts advanced-console-facts">
          <StatusFact
            label="Remaining calls"
            value={String(openAiBudget?.remaining_total_calls ?? "Unavailable")}
          />
          <StatusFact
            label="Max calls"
            value={String(openAiBudget?.max_total_openai_calls ?? "Unavailable")}
          />
          <StatusFact
            label="Exhausted"
            value={yesNo(openAiBudget?.exhausted)}
            state={openAiBudget?.exhausted ? "warning" : "online"}
          />
        </div>
      </Card>

      <Card className="dynamic-mvp-section advanced-console-card">
        <SectionHeader
          title="ADB Package Controls"
          description="Install the selected verified APK, then launch, force stop, uninstall, or capture a screenshot from the managed emulator."
        />

        <div className="advanced-console-target-layout">
          <div className="agent-runtime-controls advanced-console-form">
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
                  <option key={audit.id} value={audit.id}>
                    {audit.name}
                  </option>
                ))}
              </select>
            </label>
            <label>
              <span>Verified APK</span>
              <select
                value={selectedApkId}
                onChange={(event) =>
                  setSelectedApkId(event.target.value ? Number(event.target.value) : "")
                }
                disabled={!selectedAuditId || Boolean(working)}
              >
                <option value="">Select verified APK</option>
                {verifiedApks.map((apk) => (
                  <option key={apk.id} value={apk.id}>
                    {apk.package_name || `APK #${apk.id}`} · {apk.version_name || "unknown version"}
                  </option>
                ))}
              </select>
            </label>
            <label>
              <span>Package name</span>
              <input
                type="text"
                value={packageName}
                onChange={(event) => setPackageName(event.target.value)}
                disabled={Boolean(working)}
                autoComplete="off"
              />
            </label>
          </div>

          <section className="advanced-console-target-card" aria-label="Target summary">
            <span className="eyebrow">Target summary</span>
            <h3>{packageName || "No package selected"}</h3>
            <div className="advanced-console-target-meta">
              <StatusFact
                label="Installed"
                value={yesNo(targetInstalled)}
                state={targetInstalled ? "online" : "offline"}
              />
              <StatusFact
                label="Version"
                value={
                  installResult?.package_metadata.version_name ||
                  selectedApk?.version_name ||
                  "Unavailable"
                }
              />
              <StatusFact
                label="Audit"
                value={selectedAudit?.name || "Unavailable"}
              />
            </div>
          </section>
        </div>

        <div className="advanced-console-actions">
          <div className="advanced-console-actions-header">
            <div>
              <span className="eyebrow">Actions</span>
              <h3>Managed package operations</h3>
            </div>
            <span className="advanced-console-actions-note">
              Only bounded host-agent actions are exposed here.
            </span>
          </div>

          <div className="manual-control-toolbar advanced-console-toolbar">
            <button
              className="button button-secondary"
              onClick={() => void handleInstall()}
              disabled={!canOperate || !selectedAuditId || !selectedApkId || !emulatorOnline || Boolean(working)}
            >
              {working === "install" ? "Installing..." : "Install package"}
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
              {working === "force-stop" ? "Stopping..." : "Force stop"}
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
              onClick={() => void handleScreenshot()}
              disabled={!canOperate || !agentStatus?.connected || !emulatorOnline || Boolean(working)}
            >
              {working === "screenshot" ? "Capturing..." : "Screenshot"}
            </button>
          </div>
        </div>

        <section className="target-screenshot advanced-console-screenshot" aria-label="Latest emulator screenshot">
          <div className="target-screenshot-heading">
            <div>
              <span className="eyebrow">Capture</span>
              <h3>Latest emulator screenshot</h3>
            </div>
            <span className="advanced-console-screenshot-state">
              {screenshotUrl ? "Live preview available" : "Waiting for capture"}
            </span>
          </div>
          {screenshotUrl ? (
            <div className="dynamic-screenshot-panel has-capture">
              <img src={screenshotUrl} alt="Latest managed emulator screenshot" />
            </div>
          ) : (
            <div className="screenshot-empty-state">
              <strong>No screenshot captured</strong>
              <span>Use the Screenshot action to display the current emulator screen here.</span>
            </div>
          )}
        </section>

        {!canOperate ? (
          <p className="muted dynamic-role-note">
            Viewer access is read-only.
          </p>
        ) : null}
      </Card>
    </div>
  );
}

function OverviewChip({
  label,
  value,
  tone,
}: {
  label: string;
  value: string;
  tone: "online" | "offline" | "warning" | "neutral";
}) {
  return (
    <div className={`advanced-console-chip state-${tone}`}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function packageActionLabel(action: PackageAction): string {
  switch (action) {
    case "launch-package":
      return "Launch";
    case "force-stop":
      return "Force stop";
    case "uninstall":
      return "Uninstall";
  }
}

function yesNo(value: boolean | null | undefined): string {
  return value ? "Yes" : "No";
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
    <div className={`status-fact state-${state}`}>
      <dt>{label}</dt>
      <dd>{value}</dd>
      {detail ? <small>{detail}</small> : null}
    </div>
  );
}
