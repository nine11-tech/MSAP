# Coding-Agent Task: Rebuild and Validate the Complete MSAP Lab

Use this file as the complete task prompt for a coding agent with terminal
access to a replacement Windows/WSL workstation.

## Objective

Starting from an authorized clone of this repository, make the MSAP application
and its local Android dynamic-analysis lab operational. This includes Docker
Compose services, backend/frontend dependencies, Android SDK and a rootable API
35 AVD, clean and instrumented snapshots, Frida client/server, mitmproxy, the
scoped Windows-to-WSL bridge, ADB, the token-authenticated Host Agent, and final
health checks.

The authoritative human runbook is
`docs/21_Workstation_Recovery_Guide.md`. Read it completely before acting, then
use the checked-in scripts instead of recreating private helpers.

## Safety and authority boundaries

1. Analyze only APKs explicitly authorized by the operator. Do not download a
   random APK to prove the lab works.
2. Never print, commit, transmit, or include in a report any `.env` value,
   password, API key, Host Agent token, MinIO key, cookie, private CA key, APK,
   proxy flow, screenshot, or client evidence.
3. Do not commit `.env`, `.msap-dynamic-lab.local.env`, databases, APKs,
   certificates/keys, AVDs, snapshots, logs, `.runtime`, or evidence.
4. Do not disable Windows Firewall, SELinux, TLS verification, CSRF, or
   authentication. Use only the scoped bridge rule created by the repository.
5. Do not install the MSAP mitmproxy CA permanently in Android system/APEX trust
   stores. The supported method is the temporary runtime overlay.
6. Do not add arbitrary shell or unrestricted Frida execution to the Host Agent.
7. Do not delete volumes, AVDs, snapshots, or existing user data without explicit
   operator approval. Preserve unrelated working-tree changes.
8. Ask for approval before network downloads, `sudo`, Windows UAC, package
   installation, or any change outside the repository/local lab directories.
9. Do not push, open a pull request, or rotate external credentials unless the
   operator explicitly asks.

## Execution procedure

1. Record the current branch, remotes, commit, `git status --short`, OS/WSL
   version, Docker/Compose versions, Python version, Node/npm version, and free
   disk space. Do not dump the environment.
2. Run `scripts/security/scan-secrets.sh --history`. Report only file/line or
   commit/path locations, never matched values. Stop and tell the operator to
   revoke/rotate first if a credible secret is found.
3. Verify `.env`, `backend/.env`, `backend/db.sqlite3`,
   `.msap-dynamic-lab.local.env`, `.runtime`, APKs, evidence, CA files, and
   snapshots are untracked/ignored.
4. Install missing prerequisites exactly as described in the recovery guide.
   Use an API 35 `default;x86_64` AOSP image; reject Google Play images because
   the lab requires `adb root`, build type `userdebug`, and SELinux `Enforcing`.
5. Create local application configuration from `.env.compose.example`. Have the
   operator supply or generate unique secrets through a private channel. Keep
   all optional AI providers deterministic and leave the provider key empty for
   baseline validation.
6. Recreate `backend/.venv` from `backend/requirements.txt` and frontend
   dependencies with `npm ci --prefix frontend`. Never copy dependency folders
   from another machine.
7. Run `scripts/dynamic-lab/bootstrap-local-tooling.sh`. Create
   `.msap-dynamic-lab.local.env` from the example and record the generated public
   Frida server SHA-256, public CA SHA-256, Android certificate filename, and
   clean APEX CA count. Do not show or copy private CA material.
8. Create and boot `Lab-Root`; prove API 35, x86_64, `userdebug`, root ADB,
   SELinux `Enforcing`, proxy `:0`, no third-party packages, no Frida process,
   and no generated CA in permanent trust stores.
9. Save `msap-clean-base`. Run
   `scripts/dynamic-lab/provision-instrumented-snapshot.sh` to stage the checked
   Frida binary and public CA, then save `msap-instrumented-base`. Do not
   overwrite an existing snapshot without approval.
10. Run `scripts/dynamic-lab/refresh-frida-bridge.sh` and request the UAC approval
    it needs. Confirm the firewall rule is limited to the current WSL address and
    the configured bridge port.
11. Run, in order:

    ```bash
    scripts/dynamic-lab/restore-instrumented-snapshot.sh
    scripts/dynamic-lab/preflight.sh
    scripts/dynamic-lab/frida-smoke.sh
    scripts/dynamic-lab/mitmproxy-smoke.sh
    scripts/dynamic-lab/lab-health.sh
    ```

    The final state must have the Android proxy off, Frida stopped, SELinux
    enforcing, no unauthorized package, and no permanent MSAP CA.
12. Start the application with Docker Compose. For a WSL Host Agent, set the
    local backend URL to the current WSL IP, recreate backend/worker, and use
    `scripts/demo/start-compose-host-agent.sh start`. Do not reveal the shared
    token. The direct-WSL launcher is an acceptable alternative.
13. Run `docker compose exec -T backend python manage.py demo_health_check` and
    verify the browser login, authorized upload, static analysis, scoring,
    evidence, report download, and Dynamic Lab status without enabling a paid
    or external AI provider.
14. Run repository checks proportional to any changes made: `git diff --check`,
    the secret scan, Django checks/rule validation/migration drift, frontend
    TypeScript/build, Compose config, and Helm lint where the tools are available.

## Required handoff

Return a concise table of each checkpoint as `PASS`, `FAIL`, or `BLOCKED` and
include only sanitized diagnostics. List every file changed. Explicitly state:

- whether any credible secret was found in the tracked tree or reachable Git
  history;
- whether ignored local credential files exist, without showing their values;
- whether the emulator contract and both snapshots are valid;
- whether Frida client/server versions match and cleanup stopped the server;
- whether the proxy is off, SELinux is enforcing, and permanent CA stores are
  clean;
- whether the Host Agent is authenticated and reachable;
- which application and lab checks were actually run.

Do not claim complete success for a skipped or simulated hardware check. If a
step is blocked by virtualization, licensing, network access, credentials, UAC,
or missing operator authorization, stop at that boundary and give the exact
next command or approval needed.
