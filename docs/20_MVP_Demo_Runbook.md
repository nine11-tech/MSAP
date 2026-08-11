# MSAP MVP Demo Runbook

The accepted Dynamic Lab MVP provides authenticated control of the managed
Android emulator and verified audit APKs. The browser never sends shell commands,
host filesystem paths, or the host-agent token.

## Local topology

- Docker Compose: PostgreSQL, Redis, MinIO, and `minio-init`.
- WSL host: Django, Celery, Vite, and the loopback dynamic host agent.
- Windows: the running Android emulator.
- Browser: `http://127.0.0.1:5173`.

The host agent is the only process that invokes the configured Android Debug
Bridge. Django sends only allowlisted device and package actions.

## Start the demo

Keep the emulator running, then execute from the repository root:

```bash
scripts/demo/start-local-mvp-demo.sh up
```

The helper starts local infrastructure, applies migrations, creates a temporary
host-agent token, and starts the host agent, Django, Celery, and Vite.

Check or stop the demo with:

```bash
scripts/demo/start-local-mvp-demo.sh status
scripts/demo/start-local-mvp-demo.sh logs
scripts/demo/start-local-mvp-demo.sh down
```

## Upload an APK

1. Open `http://127.0.0.1:5173` and sign in as an analyst or administrator.
2. Open an audit.
3. Select the authorized APK.
4. Complete the browser upload.
5. Confirm that the APK storage state is `VERIFIED`.

The browser calculates SHA-256 before upload. Confirmation validates the MinIO
object size, content type, and checksum metadata before installation is allowed.

## Dynamic Lab demo

1. Open **Dynamic Lab** at `/dynamic`.
2. Confirm that Host agent and Emulator are online.
3. Confirm the serial, Android version, API level, ABI, root UID, SELinux state,
   and last sync.
4. Click **Sync Device**.
5. Select the audit.
6. Select a verified APK.
7. Click **Install APK**.
8. Review the installed package metadata.
9. Click **Launch**.
10. Click **Screenshot** and confirm the emulator PNG renders in the screenshot
    panel.
11. Click **Force Stop**.
12. Use **Clear Data** only when needed and approve the confirmation.
13. Use **Uninstall** only when needed and approve the confirmation.

Use **Refresh Packages** to reload the bounded installed-package inventory.
Viewer accounts can inspect status, package inventory, and screenshots but
cannot install or mutate packages.

## Agentic Dynamic Assessment foundation

Sprint B adds one deterministic readiness workflow to the bottom of the clean
Dynamic Lab page:

1. Confirm the card reports **Foundation available**.
2. As an Analyst or Admin, click **Run Device Readiness Check**.
3. Confirm the persisted run contains exactly `get_device_status` followed by
   `take_screenshot`.
4. Review host-agent reachability, emulator reachability, device identity,
   SELinux state, run duration, and the final environment-readiness result.
5. Review screenshot content type, dimensions when detectable, byte size,
   SHA-256, and capture time.

Viewer accounts can inspect existing runtimes, runs, steps, and artifact
metadata but cannot start a run. The page has no freeform prompt, agent chat,
custom tool selector, or autonomous pentesting control.

## Operational checks

Dynamic Lab reports:

- Host agent online or offline.
- Emulator online or offline.
- MinIO online or offline.
- Celery online or offline.

The screenshot is transient browser state and is not retained as a report
artifact in this MVP. Device events are retained for sync, screenshot, install,
launch, force stop, clear data, and uninstall actions.

## Security boundaries

- Package names must match the Android package-name allowlist.
- Package actions require the package to be installed.
- APK installation reads only a verified audit object through the storage
  provider.
- The host agent uses argument arrays and never invokes `shell=True`.
- The host-agent token is server-side only and is redacted from propagated
  errors.
- Clear Data and Uninstall require browser confirmation.
- Analyst or administrator access is required for device mutation.

## Next runtime milestone

Sprint C/B2 can replace deterministic internal-controller execution with an
ephemeral container sandbox behind the same restricted backend tool gateway.
Sprint B does not claim container isolation.
