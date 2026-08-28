# MSAP Replacement-Machine and Full-Lab Setup

This runbook rebuilds MSAP after a workstation loss. It covers the application
stack, the Android emulator, Windows ADB, Frida, mitmproxy, snapshots, the Host
Agent, and final validation. Commands assume Windows 11 with WSL2 Ubuntu and
Docker Desktop. Adapt package-manager commands for another supported host.

## What Git can and cannot recover

The repository contains application code, rules, migrations, Helm manifests,
and lab automation. It intentionally does **not** contain:

- `.env` files or credentials;
- PostgreSQL or MinIO data;
- authorized APKs or client evidence;
- emulator AVDs or snapshots;
- the mitmproxy private CA;
- downloaded Frida binaries, proxy flows, screenshots, or runtime logs.

Recover secrets from a password manager and business data from encrypted
backups. Recreate the emulator snapshots and mitmproxy CA on the replacement
machine. A source clone alone cannot restore audits or MinIO objects from a lost
machine.

## 1. Install host prerequisites

Enable CPU virtualization in firmware. On Windows, install WSL2 Ubuntu, Docker
Desktop with WSL integration, Android Studio, and Python 3.12 if the optional
Windows-native Host Agent will be used.

From an elevated PowerShell session when WSL is not installed:

```powershell
wsl --install -d Ubuntu
```

In Android Studio's SDK Manager, install:

- Android SDK Platform 35;
- Android SDK Platform-Tools;
- Android Emulator;
- Android SDK Command-line Tools (latest);
- Android SDK Build-Tools 36.0.0;
- the API 35 AOSP/default x86_64 system image.

The Google Play image is not suitable because the lab contract requires
`adb root`. From PowerShell, the equivalent command-line installation is:

```powershell
$sdk = Join-Path $env:LOCALAPPDATA "Android\Sdk"
& "$sdk\cmdline-tools\latest\bin\sdkmanager.bat" --licenses
& "$sdk\cmdline-tools\latest\bin\sdkmanager.bat" `
  "platform-tools" `
  "emulator" `
  "platforms;android-35" `
  "build-tools;36.0.0" `
  "system-images;android-35;default;x86_64"
```

In WSL:

```bash
sudo apt update
sudo apt install -y git curl xz-utils openssl python3 python3-venv python3-pip build-essential
docker version
docker compose version
```

Install Node.js 22 and npm if frontend work or the direct-WSL demo launcher is
needed. Docker Compose can build the frontend without a host Node installation.

## 2. Clone and inspect the repository

Clone into the WSL filesystem rather than `/mnt/c` for normal Linux permission
and I/O behavior:

```bash
git clone <your-authorized-msap-repository-url> MSAP
cd MSAP
git status --short
scripts/security/scan-secrets.sh --history
```

The initial status should be clean. Do not continue with a clone whose origin
or commit is not trusted.

## 3. Create local application configuration

```bash
cp .env.compose.example .env
chmod 600 .env
```

Edit `.env` and replace at least:

- `POSTGRES_PASSWORD`;
- `MINIO_ROOT_PASSWORD`;
- `DJANGO_SECRET_KEY`;
- `MSAP_DYNAMIC_HOST_AGENT_TOKEN`.

Use independent random values from a password manager or cryptographically
secure generator. Keep the deterministic planner, decision, Frida-script, and
evidence-explanation providers until the offline lab passes. If OpenAI mode is
later enabled, store `MSAP_OPENAI_API_KEY` only in the backend environment. It
must never appear in a `VITE_` variable, source file, command log, screenshot,
or support message.

Validate and start the application stack:

```bash
docker compose config --quiet
docker compose up -d --build
docker compose ps
curl -fsS http://127.0.0.1:8000/api/health/
docker compose exec backend python manage.py createsuperuser
```

Open `http://127.0.0.1:5173`. At this point static analysis is usable; the
remaining steps add the isolated dynamic lab.

## 4. Create local development environments

The Host Agent and direct demo launcher use a WSL Python environment. Frontend
dependencies are needed only for direct host development and Playwright.

```bash
python3 -m venv backend/.venv
backend/.venv/bin/python -m pip install --disable-pip-version-check -r backend/requirements.txt
npm ci --prefix frontend
```

Do not copy a virtual environment from the old machine. Recreate it from the
versioned dependency files.

## 5. Create the Android AVD

Create the AVD from PowerShell:

```powershell
$sdk = Join-Path $env:LOCALAPPDATA "Android\Sdk"
"no" | & "$sdk\cmdline-tools\latest\bin\avdmanager.bat" create avd `
  --name "Lab-Root" `
  --package "system-images;android-35;default;x86_64" `
  --device "pixel_6"

& "$sdk\emulator\emulator.exe" `
  -avd "Lab-Root" `
  -no-snapshot-load `
  -no-snapshot-save `
  -no-boot-anim
```

From WSL, verify the required identity:

```bash
cp scripts/dynamic-lab/msap-dynamic-lab.env.example .msap-dynamic-lab.local.env
chmod 600 .msap-dynamic-lab.local.env
source scripts/dynamic-lab/lib/common.sh
msap_adb wait-for-device
msap_adb root
msap_adb wait-for-device
msap_adb shell getprop ro.build.version.sdk
msap_adb shell getprop ro.product.cpu.abi
msap_adb shell getprop ro.build.type
msap_adb shell getenforce
```

Expected values are API `35`, ABI `x86_64`, build type `userdebug`, and SELinux
`Enforcing`. If `adb root` is rejected, delete the AVD and choose the AOSP
`default` image, not a Google Play image.

## 6. Install local Frida and mitmproxy tooling

The bootstrap downloads the official Frida server release and creates two
isolated WSL virtual environments. It also generates a new machine-local
mitmproxy CA.

```bash
scripts/dynamic-lab/bootstrap-local-tooling.sh
```

Copy the three non-secret values printed by the script into
`.msap-dynamic-lab.local.env`:

```dotenv
MSAP_EXPECTED_FRIDA_SERVER_SHA256=<printed-frida-server-sha256>
MSAP_EXPECTED_CA_SHA256=<printed-public-certificate-sha256>
MSAP_EXPECTED_CA_NAME=<printed-android-certificate-name>
```

Record the clean image's APEX CA count as another local trust pin:

```bash
source scripts/dynamic-lab/lib/common.sh
msap_adb shell "find /apex/com.android.conscrypt/cacerts -maxdepth 1 -type f -name '*.0' | wc -l"
```

Set the result as `MSAP_EXPECTED_APEX_CA_COUNT`. Do not copy any file from the
mitmproxy configuration directory into Git. The certificate is public, but its
adjacent private key grants interception capability and must remain private.

## 7. Create clean and instrumented snapshots

First ensure the emulator contains no third-party package, proxy, Frida process,
or permanent MSAP CA:

```bash
source scripts/dynamic-lab/lib/common.sh
msap_cleanup_proxy
msap_adb shell pm list packages -3
msap_adb shell pidof msap-frida-server
msap_verify_no_permanent_ca
msap_assert_selinux_enforcing
```

The package and Frida process commands should return no output. Save the clean
snapshot:

```bash
msap_adb emu avd snapshot save msap-clean-base
msap_snapshot_exists msap-clean-base
```

Provision the checked local Frida binary and **public** CA staging certificate,
then save the instrumented snapshot:

```bash
scripts/dynamic-lab/provision-instrumented-snapshot.sh
scripts/dynamic-lab/restore-instrumented-snapshot.sh
```

The CA is only staged under `/data/local/tmp`; it is not permanently installed
in the Android system or APEX trust store. Runtime TLS tests create a temporary
overlay and remove it during cleanup.

## 8. Configure the WSL Frida bridge

The WSL Frida client reaches the Windows-owned ADB forward through a narrowly
scoped Windows portproxy and firewall rule. Run:

```bash
scripts/dynamic-lab/refresh-frida-bridge.sh
```

Approve the Windows UAC prompt. The script does not disable the firewall. It
allows only the current WSL address to reach the selected Frida bridge port.
Repeat this step when the WSL address changes.

Validate all lab layers:

```bash
scripts/dynamic-lab/preflight.sh
scripts/dynamic-lab/frida-smoke.sh
scripts/dynamic-lab/mitmproxy-smoke.sh
scripts/dynamic-lab/lab-health.sh
```

Run the longer platform TLS probe only when a temporary runtime CA overlay and
cleanup reboot are acceptable:

```bash
scripts/dynamic-lab/platform-tls-probe.sh
```

## 9. Connect the Host Agent

For a Compose backend and WSL-hosted Host Agent, set these local `.env` values:

```dotenv
MSAP_DYNAMIC_HOST_AGENT_ENABLED=true
MSAP_DYNAMIC_LAB_MODE=WSL_BRIDGED
MSAP_DYNAMIC_HOST_AGENT_URL=http://<current-wsl-ip>:8765
```

Find the current WSL IP with `hostname -I`, update only the local `.env`, then:

```bash
docker compose up -d --force-recreate backend worker
scripts/demo/start-compose-host-agent.sh start
scripts/demo/start-compose-host-agent.sh status
docker compose exec -T backend python manage.py demo_health_check
```

The launcher reads the Host Agent token from the running backend container and
does not print it. If the WSL IP changes, update the URL and recreate the backend
and worker containers.

Alternatively, the fully managed direct-WSL demo starts PostgreSQL, Redis, and
MinIO in Compose and runs the Host Agent, Django, Celery, and Vite in WSL:

```bash
docker compose stop backend worker frontend
scripts/demo/start-local-mvp-demo.sh up
scripts/demo/start-local-mvp-demo.sh status
```

Use `scripts/demo/start-local-mvp-demo.sh down` when finished.

## 10. Final acceptance

From the repository root:

```bash
git diff --check
scripts/security/scan-secrets.sh --history
docker compose config --quiet
scripts/dynamic-lab/lab-health.sh
```

Then verify in the browser that authentication works, an authorized APK can be
uploaded, static analysis completes, evidence and scoring render, reports can be
downloaded, and the Dynamic Lab page shows the Host Agent, emulator, and Frida
as available. Keep optional external AI providers disabled for this baseline.

## Backup strategy for the next machine loss

- Push code and migrations to the authorized Git remote.
- Store application and infrastructure secrets in a password manager, never Git.
- Back up PostgreSQL and MinIO to encrypted, access-controlled storage and test
  restoration periodically.
- Retain authorized source APKs and contractual evidence separately according
  to the project's retention policy.
- Prefer rebuilding the AVD, Frida download, Python environments, and mitmproxy
  CA from this runbook. Snapshots and generated CA keys are sensitive and
  host-specific.

If credentials may have been exposed during a loss, revoke and rotate them
before restoring service.

## Common recovery actions

| Symptom | Action |
| --- | --- |
| WSL IP changed | Refresh the Frida bridge and update the Host Agent URL. |
| Emulator drift | Restore `msap-instrumented-base`, then rerun preflight. |
| Frida mismatch | Rerun the tooling bootstrap and snapshot provisioning. |
| Proxy remains enabled | Run `cleanup-runtime-state.sh`. |
| Unexpected package exists | Restore the clean/instrumented snapshot; do not silently allowlist it. |
| SELinux is not enforcing | Quarantine the emulator and recreate/restore the AVD. |
| Permanent MSAP CA detected | Quarantine and recreate the AVD from a clean AOSP image. |
| Host Agent unavailable | Check its bounded log and URL; never expose it without its token. |

See [31_Dynamic_Lab_Operations_Runbook.md](07_Deployment/31_Dynamic_Lab_Operations_Runbook.md)
for routine operation and detailed troubleshooting.
