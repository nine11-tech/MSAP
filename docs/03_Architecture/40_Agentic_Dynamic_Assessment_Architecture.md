# Agentic Dynamic Assessment Architecture

## Purpose

Sprint B establishes a secure execution and evidence foundation for future
agentic mobile assessment playbooks. It does not perform autonomous pentesting,
generate vulnerability findings, or produce malware verdicts.

The current implementation is deterministic: an authenticated Analyst or Admin
can request `DEVICE_READINESS_CHECK`, and the backend executes exactly two
predefined tools in order:

1. `get_device_status`
2. `take_screenshot` with `capture_reason=device_readiness`

There is no prompt-to-tool planning and no LLM integration in Sprint B.

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
Restricted Tool Gateway (typed two-tool allowlist and time bounds)
    |
    v
Existing token-authenticated Host Agent (token remains backend-only)
    |
    v
Managed Android Emulator
```

The controller persists `AgentRun`, `AgentRunStep`, and `AgentRunArtifact`
records around the boundary calls. A seeded `AgentRuntime` describes the active
`INTERNAL_CONTROLLER` execution mode. The interface is intentionally narrow so
a container-backed executor can later replace the internal implementation
without allowing the browser to select commands or tools.

## Control and data flow

1. The browser submits only a supported objective and an optional audit ID.
2. Django session authentication, CSRF middleware, and MSAP RBAC are applied.
3. The controller independently selects an enabled, available internal runtime.
4. Both planned steps are persisted before execution to make skipped work
   explicit when a preceding step fails.
5. The tool gateway validates the fixed input schema and calls only existing
   host-agent status/device and screenshot client methods.
6. Outputs are normalized to bounded fields before persistence or API exposure.
7. The controller stores a readiness-only result summary and records completion
   in the MSAP security audit log.

Host-agent unavailability creates a truthful failed run with
`HOST_AGENT_UNAVAILABLE`; later work is marked `SKIPPED`. Controlled errors are
returned without a Python traceback, host token, environment variables, or
host-agent response internals.

## Runtime and persistence model

`AgentRuntime` records runtime type, health state, declared capabilities, and
isolation level. Sprint B seeds `Sprint B Internal Controller` with:

- runtime type `INTERNAL_CONTROLLER`;
- status `AVAILABLE`;
- isolation level `INTERNAL_ONLY`;
- objective `DEVICE_READINESS_CHECK`;
- tools `get_device_status` and `take_screenshot`.

`AgentRun` records the requesting user, optional audit/device, selected runtime,
lifecycle timestamps, a normalized result, and controlled failure information.
`AgentRunStep` provides a unique ordered audit trail for tool invocation input
and output summaries. `AgentRunArtifact` links evidence metadata to the run and
originating step.

Screenshot binary data is not stored in PostgreSQL. Sprint B records its PNG
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
- The host-agent token remains inside the existing backend client and is never
  serialized into a model or browser response.
- Viewer can list and inspect runtimes, runs, steps, and artifacts, but cannot
  create runs. Analyst and Admin can create the one supported objective.
- Existing Django CSRF protection, session authentication, django-axes, and
  MSAP RBAC remain enabled.
- Result language is limited to environment readiness. It does not confirm a
  vulnerability and does not classify an application as malware.

## Future container target

Sprint C/B2 can add `CONTAINER_SANDBOX` behind the same controller interface:

```text
Django Agent Controller
    |
    v
Ephemeral sandbox container
    | restricted authenticated tool protocol
    v
Backend Tool Gateway
    |
    v
Host Agent -> Emulator
```

The sandbox must be ephemeral, non-privileged, resource-limited, network-
restricted, and unable to mount the project, Git metadata, SSH material, user
home, Docker socket, or application secrets. It should receive opaque run/tool
contracts rather than host credentials. Evidence bytes should flow to object
storage through backend-issued, run-scoped references with retention and
redaction controls.

Container isolation is planned, not claimed by Sprint B. The current runtime is
deterministic internal-controller mode with `INTERNAL_ONLY` isolation.

## Sprint B limitations

- One fixed objective and two harmless tools only.
- Synchronous execution in the API request lifecycle.
- No cancellation endpoint or asynchronous worker scheduling for agent runs.
- No sandbox container yet.
- No LLM, autonomous planner, freeform prompt, chat UI, arbitrary code, Frida,
  mitmproxy, UI automation, or arbitrary shell.
- Screenshot metadata is persisted; screenshot bytes are not yet uploaded as an
  agent-run object-storage artifact.
