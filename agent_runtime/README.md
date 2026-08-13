# MSAP Agent Runtime

This image is the untrusted side of the deterministic sandbox. It supports
`DEVICE_READINESS_CHECK`, `BASIC_APP_INTERACTION_CHECK`, the fixed Frida
environment actions, the backend-owned runtime UI modification proof, and
confirmed bounded custom Frida scripts. The
runner derives the fixed sequence from the validated objective input and calls
only:

```text
POST /api/dynamic/agent/runs/{id}/tool-call/
```

Optional APK install, tap, and text calls are omitted exactly when their input
is absent; Django has already recorded those steps as `SKIPPED`. Runtime package
and collector values can only come from the preceding verified install and
bounded logcat outputs.

The runner reads only `MSAP_AGENT_RUN_ID`, `MSAP_AGENT_GATEWAY_URL`,
`MSAP_AGENT_RUN_TOKEN`, `MSAP_AGENT_OBJECTIVE`, and the bounded validated
`MSAP_AGENT_OBJECTIVE_INPUT`. It has no host-agent credential, database or
object-storage credential, ADB client, Docker client/socket, repository mount,
prompt, shell-tool interface, Frida/ADB client, or direct emulator route. Even
Frida objectives call only Django's run-scoped gateway; only the host agent
communicates with the managed emulator.

Sprint D assessment planning does not run in this image. Plan generation,
validation, and approval remain backend-only and never start this container.
The future execution agent may use this isolation boundary only after a separate
approved-plan policy is implemented.

Build it from the repository root:

```bash
docker build -t msap-agent-runtime:local agent_runtime
```

Containers are launched per run by Django with a read-only root filesystem,
non-root user, dropped capabilities, `no-new-privileges`, bounded CPU/memory/PID
resources, and a small `noexec` tmpfs. Do not run this image manually with
long-lived credentials.
