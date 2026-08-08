# MSAP Final MVP Demo Runbook

The local MVP proves that an authenticated MSAP analyst can upload an authorized
APK, control `emulator-5554` from the browser, and retain bounded dynamic evidence.
Browser requests never contain shell commands, host paths, proxy addresses, or CA
files.

## Recommended topology

- Docker Compose: PostgreSQL, Redis, MinIO, and `minio-init`.
- WSL host: Django, one Celery worker, Vite, and the dynamic host agent.
- Windows: the already-running Android emulator.
- Browser: `http://127.0.0.1:5173`.

The host agent is the only component that loads `~/.local/bin/msap-dynamic-env`
or invokes Windows ADB. Django and Celery use localhost infrastructure endpoints.

## One-command startup

Keep the emulator running, then execute from the repository root:

```bash
scripts/demo/start-local-mvp-demo.sh up
```

The helper:

1. Stops only competing Compose `backend`, `worker`, and `frontend` containers.
2. Starts PostgreSQL, Redis, MinIO, and bucket initialization.
3. creates a permission-restricted, temporary 64-character agent token under the
   ignored `.runtime/msap-demo/` directory.
4. applies migrations, then starts the loopback host agent, local Django with
   `--noreload`, a local Celery worker, and Vite.
5. waits for MinIO, host-agent, Django, Celery, and frontend readiness.

It does not change a user password, install an APK, restore a snapshot, alter
emulator proxy state, or run any TLS probe. Service logs are capped at 2 MiB each.

Operational commands:

```bash
scripts/demo/start-local-mvp-demo.sh status
scripts/demo/start-local-mvp-demo.sh logs
scripts/demo/start-local-mvp-demo.sh down
```

`down` stops only processes whose PID and process-start identity were recorded by
the helper, removes runtime PID/token files, and stops the three infrastructure
containers without deleting volumes.

## Object-storage contract

Django uses `MINIO_ENDPOINT=http://127.0.0.1:9000` for server-side HEAD/download
operations in the WSL topology. Browser presigned URLs are signed using the
separate `MINIO_PUBLIC_ENDPOINT=http://127.0.0.1:9000`. In full Compose mode,
the internal endpoint is `http://minio:9000`, while the public signing endpoint
remains browser-reachable.

The Compose MinIO service permits only the two local Vite origins through
`MINIO_API_CORS_ALLOW_ORIGIN`. The recorded bucket policy permits PUT, GET, and
HEAD where an S3-compatible deployment supports per-bucket CORS. Buckets remain
private and every browser PUT remains signature-authorized.

The browser calculates SHA-256 before initiating an upload. Its signed PUT sends
the fixed content type and SHA-256 object metadata. Confirmation performs a
server-side HEAD and requires object size, content type, and checksum metadata to
match before changing storage status to `VERIFIED`.

## Browser acceptance sequence

1. Open `http://127.0.0.1:5173`, log in, and open **Dynamic Lab**.
2. Confirm the Host agent, Emulator, MinIO, Celery, and Dynamic runner chips.
3. Refresh/sync the device. Expected inventory is Android 15, API 35, x86_64,
   root UID 0, and SELinux Enforcing.
4. Click **Screenshot** and confirm the emulator PNG renders inline.
5. From the audit page, select the authorized APK and complete upload. Confirm its
   storage status becomes `VERIFIED`.
6. Return to Dynamic Lab, select the audit/APK, and click **Install Uploaded APK**.
   Review package name, version, installed path, launcher activity, permission
   counts, duration, and SHA-256.
7. Click **Launch App**, take a new screenshot, then click **Force Stop**.
8. Run **Frida Smoke** and inspect Connection, Version agreement,
   Instrumentation event, Process evidence, Cleanup, Interpretation, and
   Limitations. Download the bounded JSON if useful.
9. Run **mitmproxy Smoke** and inspect Proxy configuration, Probe request,
   Captured flow, TLS/trust result, Cleanup, Interpretation, and Limitations.
10. Create/run a Dynamic MVP job. With the worker offline, the API returns HTTP
    503 before creating another queued job. With the worker online, the task is
    queued normally.

Clear Data and Uninstall require explicit browser confirmation. Do not use them
during normal acceptance. Snapshot restoration and Platform TLS Probe are also
operator-triggered only.

## Queued-job recovery

Eligible queued rows can be cancelled from Dynamic Lab. Recover abandoned work
older than a bounded age with:

```bash
cd /home/anass/projects/MSAP/backend
./.venv/bin/python manage.py recover_dynamic_jobs --older-than-minutes 5
```

Queued jobs become `CANCELLED`; evidence is retained. A running job is recovered
only after both the requested stale age and its own timeout have elapsed. If its
runtime cleanup cannot be proven, its session and leased device are quarantined
instead of being falsely marked clean.

## Trust and proxy controls

- **Restore Instrumented Snapshot** invokes only the fixed configured snapshot.
- **Verify Trust State** reports snapshot name, staged/runtime trust state, proxy,
  SELinux, result, and limitations.
- **Apply Configured Lab Proxy** uses only `MSAP_DYNAMIC_LAB_PROXY_VALUE`.
- **Clear Lab Proxy** resets the controlled emulator proxy to `:0`.
- **Platform TLS Probe** remains disabled by default and is marked slow/disruptive.

No browser route accepts a proxy address, certificate, CA private key, executable
path, or arbitrary command.

## Optional full Compose web mode

The normal web platform may run in containers. Dynamic Android control still
requires the WSL host agent and these backend settings:

```text
MSAP_DYNAMIC_HOST_AGENT_ENABLED=true
MSAP_DYNAMIC_HOST_AGENT_URL=http://host.docker.internal:8765
MSAP_DYNAMIC_HOST_AGENT_TOKEN=<same temporary local token>
MINIO_ENDPOINT=http://minio:9000
MINIO_PUBLIC_ENDPOINT=http://127.0.0.1:9000
```

Do not invoke Android control directly inside the containers. The agent binds to
`127.0.0.1` by default; do not expose it publicly.

## Evidence interpretation and limits

- Screenshot, package launch, and force-stop prove browser-to-managed-emulator
  control. They do not prove a vulnerability or malware behavior.
- Frida smoke proves connection, version agreement, fixed-process attachment,
  bounded script injection/event receipt, and cleanup. It is not an assessed-APK
  vulnerability result.
- mitmproxy smoke proves correlated host laboratory HTTP/TLS flows and records the
  emulator proxy state. It does not prove every app connection is interceptable;
  pinning, custom trust, QUIC, native TLS, and VPN behavior need targeted testing.
- Screenshots remain transient browser object URLs in this MVP.
