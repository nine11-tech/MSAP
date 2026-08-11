from __future__ import annotations

from dataclasses import dataclass
import os
import re
import subprocess
from urllib.parse import urlsplit

from django.conf import settings

from apps.dynamic_analysis.models import AgentRun


_DOCKER_RESOURCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,254}$")
_RUN_ENVIRONMENT_KEYS = (
    "MSAP_AGENT_RUN_ID",
    "MSAP_AGENT_GATEWAY_URL",
    "MSAP_AGENT_RUN_TOKEN",
    "MSAP_AGENT_OBJECTIVE",
)


class ContainerRuntimeError(RuntimeError):
    pass


class ContainerRuntimeTimeout(ContainerRuntimeError):
    pass


@dataclass(frozen=True)
class ContainerLaunch:
    argv: tuple[str, ...]
    process_environment: dict[str, str]
    container_environment: dict[str, str]
    container_name: str


def build_container_launch(*, run: AgentRun, run_token: str) -> ContainerLaunch:
    """Build a fixed, operator-configured Docker invocation for one run."""

    if run.objective != AgentRun.Objective.DEVICE_READINESS_CHECK:
        raise ContainerRuntimeError("The sandbox objective is not supported.")
    image = _validated_docker_resource(
        settings.MSAP_AGENT_CONTAINER_IMAGE,
        label="container image",
    )
    configured_network = str(settings.MSAP_AGENT_CONTAINER_NETWORK or "").strip()
    if configured_network:
        configured_network = _validated_docker_resource(
            configured_network,
            label="container network",
        )
    gateway_url = _validated_gateway_url(settings.MSAP_AGENT_GATEWAY_URL)
    container_name = f"msap-agent-run-{run.pk}"
    container_environment = {
        "MSAP_AGENT_RUN_ID": str(run.pk),
        "MSAP_AGENT_GATEWAY_URL": gateway_url,
        "MSAP_AGENT_RUN_TOKEN": run_token,
        "MSAP_AGENT_OBJECTIVE": run.objective,
    }
    argv = [
        "docker",
        "run",
        "--rm",
        "--name",
        container_name,
        "--read-only",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=64m",
        "--memory",
        "256m",
        "--cpus",
        "1",
        "--pids-limit",
        "64",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
    ]
    if configured_network:
        argv.extend(["--network", configured_network])
    else:
        # Linux Docker does not always create this host alias automatically.
        # The fixed alias makes the default local gateway URL reachable without
        # granting host networking to the sandbox.
        argv.extend(["--add-host", "host.docker.internal:host-gateway"])
    for key in _RUN_ENVIRONMENT_KEYS:
        # Values stay out of argv and are copied by the Docker CLI from its
        # deliberately minimal process environment.
        argv.extend(["--env", key])
    argv.append(image)
    process_environment = {"PATH": os.defpath, **container_environment}
    return ContainerLaunch(
        argv=tuple(argv),
        process_environment=process_environment,
        container_environment=container_environment,
        container_name=container_name,
    )


def run_container_sandbox(*, run: AgentRun, run_token: str) -> None:
    launch = build_container_launch(run=run, run_token=run_token)
    timeout_seconds = max(1, int(settings.MSAP_AGENT_CONTAINER_TIMEOUT_SECONDS))
    try:
        completed = subprocess.run(
            launch.argv,
            shell=False,
            check=False,
            env=launch.process_environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        _remove_timed_out_container(launch)
        raise ContainerRuntimeTimeout(
            "The container sandbox exceeded its execution limit."
        ) from None
    except (OSError, ValueError):
        raise ContainerRuntimeError(
            "The container sandbox could not be started."
        ) from None
    if completed.returncode != 0:
        raise ContainerRuntimeError(
            "The container sandbox exited with a controlled failure."
        )


def _remove_timed_out_container(launch: ContainerLaunch) -> None:
    try:
        subprocess.run(
            ("docker", "rm", "--force", launch.container_name),
            shell=False,
            check=False,
            env={"PATH": os.defpath},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired, ValueError):
        # The run is already marked timed out. Cleanup is best-effort and the
        # fixed per-run name prevents this from targeting any other container.
        pass


def _validated_docker_resource(value: object, *, label: str) -> str:
    candidate = str(value or "").strip()
    if not _DOCKER_RESOURCE_RE.fullmatch(candidate):
        raise ContainerRuntimeError(f"The configured {label} is invalid.")
    return candidate


def _validated_gateway_url(value: object) -> str:
    candidate = str(value or "").strip().rstrip("/")
    parsed = urlsplit(candidate)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ContainerRuntimeError("The configured agent gateway URL is invalid.")
    return candidate
