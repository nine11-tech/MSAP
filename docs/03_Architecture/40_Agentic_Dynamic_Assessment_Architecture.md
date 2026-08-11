# Agentic Dynamic Assessment Architecture

## Purpose

Sprint C establishes a container isolation and evidence foundation for future
agentic mobile assessment playbooks. It does not perform autonomous pentesting,
generate vulnerability findings, or produce malware verdicts.

The current implementation is deterministic: an authenticated Analyst or Admin
can request `DEVICE_READINESS_CHECK`, and the backend executes exactly two
predefined tools in order:

1. `get_device_status`
2. `take_screenshot` with `capture_reason=device_readiness`

There is no prompt-to-tool planning and no LLM integration in Sprint C.

## Current architecture

```text
Browser (session authentication + CSRF)
    |
    v
Django REST API (RBAC and input validation)
    |
    v
Agent Controller (deterministic objective plan)
    |
    v
Internal Controller OR Ephemeral Container Sandbox
    |
    v
Run-scoped Tool Gateway (hashed expiring credential + exact two-tool plan)
    |
    v
Existing token-authenticated Host Agent (token remains backend-only)
    |
    v
Managed Android Emulator
```

The controller persists `AgentRun`, `AgentRunStep`, and `AgentRunArtifact`
records around the boundary calls. Seeded runtimes describe the default
`INTERNAL_CONTROLLER` and opt-in `CONTAINER_SANDBOX` modes. The browser selects
only one of those enum values; it cannot select a command, image, network, tool,
argument, path, or prompt.

## Control and data flow

1. The browser submits only a supported objective and an optional audit ID.
2. Django session authentication, CSRF middleware, and MSAP RBAC are applied.
3. The controller independently selects an enabled runtime of the requested
   enum type. Container selection additionally requires the operator setting.
4. Both planned steps are persisted before execution to make skipped work
   explicit when a preceding step fails.
5. Internal mode executes the fixed plan in Django. Container mode hashes a
   newly generated run token, gives the plaintext token only to the subprocess
   environment, and launches one hardened container with fixed argv.
6. The container requests each exact step from its own run-scoped route. Django
   validates token digest, expiry, route/run binding, run state, objective,
   order, tool name, and exact arguments before calling the existing host-agent
   client.
7. Outputs are normalized to bounded fields before persistence or API exposure.
8. The controller stores a readiness-only result summary and records completion
   in the MSAP security audit log.

Host-agent unavailability creates a truthful failed run with
`HOST_AGENT_UNAVAILABLE`; later work is marked `SKIPPED`. Controlled errors are
returned without a Python traceback, host token, environment variables, or
host-agent response internals.

## Runtime and persistence model

`AgentRuntime` records runtime type, health state, declared capabilities, and
isolation level. Sprint B's internal runtime remains available. Sprint C also
seeds `Sprint C Container Sandbox` with `CONTAINER_ISOLATED`; its effective
availability is false unless `MSAP_AGENT_CONTAINER_ENABLED=true`.

- runtime type `INTERNAL_CONTROLLER`;
- status `AVAILABLE`;
- isolation level `INTERNAL_ONLY`;
- objective `DEVICE_READINESS_CHECK`;
- tools `get_device_status` and `take_screenshot`.

`AgentRun` records the requesting user, optional audit/device, selected runtime,
lifecycle timestamps, a normalized result, and controlled failure information.
It also stores only a SHA-256 run-token digest and expiry, never the plaintext
run token.
`AgentRunStep` provides a unique ordered audit trail for tool invocation input
and output summaries. `AgentRunArtifact` links evidence metadata to the run and
originating step.

Screenshot binary data is not stored in PostgreSQL. Sprint C records its PNG
content type, dimensions when detectable, byte size, SHA-256, and capture time.
`AgentRunArtifact.object_reference` is ready to reference object storage when
the evidence upload path is added.

## Security boundaries

The following constraints are architectural, not UI-only:

- The browser cannot provide a tool sequence, runtime ID, command, path, or
  custom executable content.
- The tool gateway rejects unknown tools and unknown or invalid arguments.
- Each host-agent call uses a bounded timeout and bounded response handling.
- No arbitrary shell or process execution exists in the agent runtime.
- No `shell=True`, direct host filesystem access, home-directory access, or
  environment exposure is introduced.
- Docker is invoked with fixed argv and `shell=False`. The browser cannot supply
  the image, network, name, entrypoint, command, environment, or resource flags.
- The container has no mounts, Docker socket, host network, privileged mode, or
  added capabilities. It runs non-root with a read-only filesystem,
  `no-new-privileges`, a small `noexec` tmpfs, and CPU/memory/PID limits.
- Its four allowed environment values are run ID, fixed objective, configured
  gateway URL, and short-lived run token. Host-agent, database, MinIO, `.env`,
  SSH, repository, and home data are not passed.
- The host-agent token remains inside the existing backend client and is never
  serialized into a model or browser response.
- Viewer can list and inspect runtimes, runs, steps, and artifacts, but cannot
  create runs. Analyst and Admin can create the one supported objective.
- Existing Django CSRF protection, session authentication, django-axes, and
  MSAP RBAC remain enabled.
- Result language is limited to environment readiness. It does not confirm a
  vulnerability and does not classify an application as malware.

## Future GPT-5.5 planner placeholder

A future planner configuration is documented as:

```ini
planner_provider = OPENAI
planner_model = GPT-5.5
```

This is documentation only. A later planner must emit tool-plan JSON, never get
the host-agent token, and only request allowlisted tools. Django must validate
the plan and arguments, execute the tools, and audit every call. There is no API
key, OpenAI dependency, model call, or planner output parser in Sprint C.

## Sprint C limitations

- One fixed objective and two harmless tools only.
- Synchronous execution in the API request lifecycle.
- No cancellation endpoint or asynchronous worker scheduling for agent runs.
- No LLM, autonomous planner, freeform prompt, chat UI, arbitrary code, Frida,
  mitmproxy, UI automation, or arbitrary shell.
- Screenshot metadata is persisted; screenshot bytes are not yet uploaded as an
  agent-run object-storage artifact.
- The default Docker bridge is not an egress allowlist. Operators needing strict
  network isolation must provide a dedicated network/gateway topology with
  `MSAP_AGENT_CONTAINER_NETWORK`; host networking is never selected by MSAP.
