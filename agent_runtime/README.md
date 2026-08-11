# MSAP Agent Runtime

This image is the untrusted side of the Sprint C deterministic sandbox. It
supports only `DEVICE_READINESS_CHECK` and always requests exactly:

1. `get_device_status` with `{}`;
2. `take_screenshot` with `{"capture_reason":"device_readiness"}`.

The runner reads only `MSAP_AGENT_RUN_ID`, `MSAP_AGENT_GATEWAY_URL`,
`MSAP_AGENT_RUN_TOKEN`, and `MSAP_AGENT_OBJECTIVE`. It uses the run token only
as a Bearer credential for the matching Django tool-gateway route. It has no
host-agent credential, database or object-storage credential, ADB client,
Docker client/socket, repository mount, prompt, shell-tool interface, or direct
emulator route.

Build it from the repository root:

```bash
docker build -t msap-agent-runtime:local agent_runtime
```

Containers are launched per run by Django with a read-only root filesystem,
non-root user, dropped capabilities, `no-new-privileges`, bounded CPU/memory/PID
resources, and a small `noexec` tmpfs. Do not run this image manually with
long-lived credentials.
