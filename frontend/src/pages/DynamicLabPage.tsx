import { type FormEvent, useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { ApiError } from "../api/client";
import {
  createDynamicJob,
  listAudits,
  listDynamicDeviceCapabilities,
  listDynamicDevicePools,
  listDynamicDevices,
  listDynamicEmulatorSnapshots,
  listDynamicJobs,
  listDynamicSessions,
  runDynamicMvpJob,
} from "../api/msap";
import type {
  Audit,
  DynamicAnalysisJob,
  DynamicDevice,
  DynamicDeviceCapability,
  DynamicDevicePool,
  DynamicEmulatorSnapshot,
  DynamicJobCreateRequest,
  DynamicSession,
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

const RUNNABLE_JOB_STATUSES = new Set(["QUEUED", "RUNNING"]);

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
  const [pools, setPools] = useState<DynamicDevicePool[]>([]);
  const [devices, setDevices] = useState<DynamicDevice[]>([]);
  const [capabilities, setCapabilities] = useState<DynamicDeviceCapability[]>([]);
  const [snapshots, setSnapshots] = useState<DynamicEmulatorSnapshot[]>([]);
  const [jobs, setJobs] = useState<DynamicAnalysisJob[]>([]);
  const [sessions, setSessions] = useState<DynamicSession[]>([]);
  const [selectedAuditId, setSelectedAuditId] = useState<number | "">("");
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
  const { hasRole } = useAuth();
  const canOperate = hasRole("ADMIN", "ANALYST");

  const loadWorkspace = useCallback(async (showLoading = true) => {
    if (showLoading) setLoading(true);
    setRefreshing(!showLoading);
    setError("");
    try {
      const [
        auditData,
        poolData,
        deviceData,
        capabilityData,
        snapshotData,
        jobData,
        sessionData,
      ] = await Promise.all([
        listAudits(),
        listDynamicDevicePools(),
        listDynamicDevices(),
        listDynamicDeviceCapabilities(),
        listDynamicEmulatorSnapshots(),
        listDynamicJobs(),
        listDynamicSessions(),
      ]);
      setAudits(auditData);
      setPools(poolData);
      setDevices(deviceData);
      setCapabilities(capabilityData);
      setSnapshots(snapshotData);
      setJobs(jobData);
      setSessions(sessionData);
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
  const latestJob = jobs[0];
  const availableDevices = devices.filter((device) => device.status === "AVAILABLE");
  const activeSessions = sessions.filter(
    (session) => !TERMINAL_SESSION_STATES.has(session.state),
  );

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
      setNotice(
        `Dynamic MVP job #${response.job.id} was queued as task ${response.task_id}. Refresh to follow session evidence.`,
      );
      await loadWorkspace(false);
    } catch (requestError) {
      setError(dynamicErrorMessage(requestError));
    } finally {
      setWorking(false);
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
              disabled={!canOperate || working || selectedAuditId === ""}
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
                !selectedJob ||
                !RUNNABLE_JOB_STATUSES.has(selectedJob.status)
              }
            >
              Run MVP
            </button>
          </form>
          <div className="demo-hint-panel">
            <strong>Local demo setup</strong>
            <code>python manage.py seed_dynamic_lab</code>
            <code>
              MSAP_DYNAMIC_RUNNER_ENABLED=true python manage.py run_dynamic_mvp
              --audit-id &lt;id&gt;
            </code>
          </div>
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
            <li>It does not yet install or exercise the uploaded target APK.</li>
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
