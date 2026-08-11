import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import {
  captureDynamicHostAgentScreenshot,
  getDynamicHostAgentStatus,
  installDynamicAuditApk,
  listApkFiles,
  listAudits,
  listDynamicHostAgentPackages,
  runDynamicHostAgentPackageAction,
  syncDynamicHostAgent,
} from "../api/msap";
import type {
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
  | "uninstall";

type PackageAction =
  | "launch-package"
  | "force-stop"
  | "clear-data"
  | "uninstall";

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
      const [auditData, apkData, hostData] = await Promise.all([
        listAudits(),
        listApkFiles(),
        getDynamicHostAgentStatus(),
      ]);
      setAudits(auditData);
      setApkFiles(apkData);
      setAgentStatus(hostData);
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

  useEffect(() => {
    setSelectedApkId((current) => {
      if (current && verifiedApks.some((apk) => apk.id === current)) {
        return current;
      }
      return verifiedApks[0]?.id || "";
    });
    setInstallResult(null);
  }, [selectedAuditId, verifiedApks]);

  const device = agentStatus?.device;
  const emulatorOnline = device?.state === "device";
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

      <Card className="dynamic-next-card">
        <p className="eyebrow">Coming Next</p>
        <h2>Agentic Dynamic Assessment</h2>
        <strong>Coming in Sprint B.</strong>
        <p>
          The next dynamic engine will run controlled mobile security playbooks
          inside an isolated agent runtime.
        </p>
      </Card>
    </div>
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
