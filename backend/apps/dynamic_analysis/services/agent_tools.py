from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from types import MappingProxyType
import struct
from time import monotonic
from typing import Any

from django.utils import timezone

from apps.dynamic_analysis.services.host_agent_client import (
    DynamicHostAgentClient,
    HostAgentClientError,
)
from apps.dynamic_analysis.services.host_agent_sync import sync_host_agent_device


class AgentToolError(RuntimeError):
    def __init__(self, message: str, *, code: str, failure_category: str):
        super().__init__(message)
        self.code = code
        self.failure_category = failure_category


@dataclass(frozen=True)
class AgentToolSpec:
    name: str
    input_schema: dict[str, Any]
    output_fields: tuple[str, ...]
    timeout_seconds: int


DEVICE_STATUS_OUTPUT_FIELDS = (
    "host_agent_status",
    "emulator_status",
    "serial",
    "android_version",
    "api_level",
    "abi",
    "root_uid",
    "selinux",
    "proxy",
    "focused_app",
    "ready",
)

SCREENSHOT_OUTPUT_FIELDS = (
    "content_type",
    "width",
    "height",
    "size_bytes",
    "sha256",
    "captured_at",
)

TOOL_MANIFEST = MappingProxyType(
    {
        "get_device_status": AgentToolSpec(
            name="get_device_status",
            input_schema={
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
            output_fields=DEVICE_STATUS_OUTPUT_FIELDS,
            timeout_seconds=12,
        ),
        "take_screenshot": AgentToolSpec(
            name="take_screenshot",
            input_schema={
                "type": "object",
                "properties": {
                    "capture_reason": {
                        "type": "string",
                        "enum": ["device_readiness", "manual_check"],
                    }
                },
                "required": ["capture_reason"],
                "additionalProperties": False,
            },
            output_fields=SCREENSHOT_OUTPUT_FIELDS,
            timeout_seconds=15,
        ),
    }
)


def public_tool_manifest() -> dict[str, dict[str, Any]]:
    return {
        name: {
            "name": spec.name,
            "input_schema": spec.input_schema,
            "output_fields": list(spec.output_fields),
            "timeout_seconds": spec.timeout_seconds,
        }
        for name, spec in TOOL_MANIFEST.items()
    }


def execute_agent_tool(
    tool_name: str,
    arguments: dict[str, Any],
    *,
    requested_by=None,
    client: DynamicHostAgentClient | None = None,
) -> dict[str, Any]:
    spec = TOOL_MANIFEST.get(tool_name)
    if spec is None:
        raise AgentToolError(
            "The requested agent tool is not allowlisted.",
            code="UNKNOWN_TOOL",
            failure_category="TOOL_EXECUTION_FAILED",
        )
    validated_arguments = _validate_arguments(tool_name, arguments)
    bounded_client = client or DynamicHostAgentClient(
        timeout_seconds=(6 if tool_name == "get_device_status" else 15),
    )
    started = monotonic()
    try:
        if tool_name == "get_device_status":
            output = _get_device_status(
                bounded_client,
                requested_by=requested_by,
            )
        else:
            output = _take_screenshot(
                bounded_client,
                capture_reason=validated_arguments["capture_reason"],
            )
    except HostAgentClientError as exc:
        raise AgentToolError(
            _safe_host_agent_failure(exc.code),
            code=exc.code,
            failure_category="HOST_AGENT_UNAVAILABLE",
        ) from None
    if monotonic() - started > spec.timeout_seconds:
        raise AgentToolError(
            f"Agent tool {tool_name} exceeded its execution limit.",
            code="AGENT_TOOL_TIMEOUT",
            failure_category="TIMEOUT",
        )
    return {field: output.get(field) for field in spec.output_fields}


def _validate_arguments(tool_name: str, arguments: Any) -> dict[str, Any]:
    if not isinstance(arguments, dict):
        raise AgentToolError(
            "Agent tool arguments must be a JSON object.",
            code="INVALID_TOOL_INPUT",
            failure_category="TOOL_EXECUTION_FAILED",
        )
    if tool_name == "get_device_status":
        if arguments:
            raise AgentToolError(
                "get_device_status does not accept arguments.",
                code="INVALID_TOOL_INPUT",
                failure_category="TOOL_EXECUTION_FAILED",
            )
        return {}
    if set(arguments) != {"capture_reason"}:
        raise AgentToolError(
            "take_screenshot requires only capture_reason.",
            code="INVALID_TOOL_INPUT",
            failure_category="TOOL_EXECUTION_FAILED",
        )
    capture_reason = arguments.get("capture_reason")
    if capture_reason not in {"device_readiness", "manual_check"}:
        raise AgentToolError(
            "capture_reason must be device_readiness or manual_check.",
            code="INVALID_TOOL_INPUT",
            failure_category="TOOL_EXECUTION_FAILED",
        )
    return {"capture_reason": capture_reason}


def _get_device_status(
    client: DynamicHostAgentClient,
    *,
    requested_by=None,
) -> dict[str, Any]:
    payload = client.get_status()
    if not payload.get("connected"):
        code = str(payload.get("code") or "HOST_AGENT_UNAVAILABLE")
        raise AgentToolError(
            _safe_host_agent_failure(code),
            code=code,
            failure_category="HOST_AGENT_UNAVAILABLE",
        )
    raw_device = payload.get("device")
    device = raw_device if isinstance(raw_device, dict) else {}
    serial = _bounded_text(device.get("serial"), 128)
    emulator_online = device.get("state") == "device"
    ready = bool(serial and emulator_online)
    if serial:
        sync_host_agent_device(payload, requested_by=requested_by)
    return {
        "host_agent_status": "REACHABLE",
        "emulator_status": "REACHABLE" if emulator_online else "UNAVAILABLE",
        "serial": serial,
        "android_version": _bounded_text(device.get("android_version"), 64),
        "api_level": _nullable_positive_int(device.get("api_level")),
        "abi": _bounded_text(device.get("abi"), 64),
        "root_uid": _nullable_int(device.get("root_uid")),
        "selinux": _bounded_text(device.get("selinux"), 64),
        "proxy": _bounded_text(device.get("proxy"), 255),
        "focused_app": _bounded_text(device.get("focused_app"), 255),
        "ready": ready,
    }


def _take_screenshot(
    client: DynamicHostAgentClient,
    *,
    capture_reason: str,
) -> dict[str, Any]:
    # capture_reason is deliberately validated but is not passed to the host
    # agent. The host boundary exposes a single fixed screenshot action.
    del capture_reason
    screenshot = client.request_screenshot()
    width, height = _png_dimensions(screenshot)
    return {
        "content_type": "image/png",
        "width": width,
        "height": height,
        "size_bytes": len(screenshot),
        "sha256": sha256(screenshot).hexdigest(),
        "captured_at": timezone.now().isoformat(),
    }


def _png_dimensions(payload: bytes) -> tuple[int | None, int | None]:
    if len(payload) < 24 or payload[:8] != b"\x89PNG\r\n\x1a\n":
        return None, None
    if payload[12:16] != b"IHDR":
        return None, None
    width, height = struct.unpack(">II", payload[16:24])
    if width <= 0 or height <= 0:
        return None, None
    return width, height


def _safe_host_agent_failure(code: str) -> str:
    if code == "HOST_AGENT_DISABLED":
        return "The dynamic host agent is disabled. Enable and start it before running this check."
    if code == "HOST_AGENT_NOT_CONFIGURED":
        return "The dynamic host agent is not configured for this environment."
    return "The dynamic host agent is unavailable. Start it and retry the readiness check."


def _bounded_text(value: Any, max_length: int) -> str:
    return str(value or "").replace("\x00", "")[:max_length]


def _nullable_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _nullable_positive_int(value: Any) -> int | None:
    result = _nullable_int(value)
    return result if result is not None and result > 0 else None
