from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from types import MappingProxyType
import re
import struct
from time import monotonic
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from django.conf import settings
from django.utils import timezone

from apps.api.roles import user_role
from apps.apk_files.models import APKFile
from apps.audits.models import Audit
from apps.dynamic_analysis.services.host_agent_client import (
    DynamicHostAgentClient,
    HostAgentClientError,
)
from apps.dynamic_analysis.services.host_agent_sync import (
    record_host_agent_action,
    sync_host_agent_device,
)
from apps.dynamic_analysis.services.frida_scripts import (
    RUNTIME_UI_MODIFICATION_PROOF_SOURCE,
)
from apps.storage.models import ObjectStorageReference
from apps.storage.services.file_provider import APKFileProvider, FileProviderError
from apps.storage.services.minio_storage import MinIOStorageService


PACKAGE_NAME_RE = re.compile(
    r"^[a-zA-Z][a-zA-Z0-9_]*(?:\.[a-zA-Z0-9_]+)+$"
)
COLLECTOR_ID_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")
SAFE_INPUT_TEXT_RE = re.compile(r"^[A-Za-z0-9 @._,:+!?/\-]{1,128}$")
MAX_PACKAGES = 500
MAX_UI_VALUES = 100
MAX_UI_PREVIEW_CHARS = 8000
MAX_LOGCAT_LINES = 500
MAX_FRIDA_SCRIPT_BYTES = 32 * 1024
MAX_FRIDA_EVENTS = 200
MAX_FRIDA_PROCESSES = 500
BUILTIN_FRIDA_UI_PROOF = "__MSAP_BUILTIN_FRIDA_UI_MODIFICATION_PROOF__"


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


def _object_schema(
    properties: dict[str, Any],
    *,
    required: tuple[str, ...] = (),
) -> dict[str, Any]:
    schema: dict[str, Any] = {
        "type": "object",
        "properties": properties,
        "additionalProperties": False,
    }
    if required:
        schema["required"] = list(required)
    return schema


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
    "object_reference_id",
)
PACKAGE_PROPERTY = {"type": "string", "pattern": PACKAGE_NAME_RE.pattern, "maxLength": 255}


TOOL_MANIFEST = MappingProxyType(
    {
        "get_device_status": AgentToolSpec(
            "get_device_status", _object_schema({}), DEVICE_STATUS_OUTPUT_FIELDS, 12
        ),
        "list_packages": AgentToolSpec(
            "list_packages",
            _object_schema(
                {"include_system": {"type": "boolean"}},
                required=("include_system",),
            ),
            ("package_count", "packages"),
            35,
        ),
        "install_verified_apk": AgentToolSpec(
            "install_verified_apk",
            _object_schema(
                {
                    "audit_id": {"type": "integer", "minimum": 1},
                    "apk_file_id": {"type": "integer", "minimum": 1},
                },
                required=("audit_id", "apk_file_id"),
            ),
            (
                "package_name",
                "version_name",
                "version_code",
                "launcher_activity",
                "sha256",
                "install_status",
            ),
            120,
        ),
        "launch_package": AgentToolSpec(
            "launch_package",
            _object_schema({"package_name": PACKAGE_PROPERTY}, required=("package_name",)),
            ("launched", "focused_app"),
            60,
        ),
        "force_stop_package": AgentToolSpec(
            "force_stop_package",
            _object_schema({"package_name": PACKAGE_PROPERTY}, required=("package_name",)),
            ("stopped",),
            60,
        ),
        "clear_package_data": AgentToolSpec(
            "clear_package_data",
            _object_schema(
                {
                    "package_name": PACKAGE_PROPERTY,
                    "confirm": {"type": "boolean", "const": True},
                },
                required=("package_name", "confirm"),
            ),
            ("cleared",),
            60,
        ),
        "take_screenshot": AgentToolSpec(
            "take_screenshot",
            _object_schema(
                {
                    "capture_reason": {
                        "type": "string",
                        "enum": [
                            "device_readiness", "manual_check",
                            "instrumentation_before", "instrumentation_after",
                        ],
                    }
                    ,
                    "audit_id": {"type": "integer", "minimum": 1},
                },
                required=("capture_reason",),
            ),
            SCREENSHOT_OUTPUT_FIELDS,
            15,
        ),
        "start_logcat": AgentToolSpec(
            "start_logcat",
            _object_schema(
                {
                    "package_name": PACKAGE_PROPERTY,
                    "reason": {
                        "type": "string",
                        "enum": ["manual_observation", "agent_step"],
                    },
                    "max_seconds": {"type": "integer", "minimum": 1, "maximum": 60},
                },
                required=("package_name", "reason", "max_seconds"),
            ),
            ("collector_id", "started_at", "max_seconds", "package_filter_applied"),
            65,
        ),
        "stop_logcat": AgentToolSpec(
            "stop_logcat",
            _object_schema(
                {"collector_id": {"type": "string", "maxLength": 64}},
                required=("collector_id",),
            ),
            ("collector_id", "stopped", "supported", "status"),
            10,
        ),
        "get_logcat_excerpt": AgentToolSpec(
            "get_logcat_excerpt",
            _object_schema(
                {
                    "collector_id": {"type": "string", "maxLength": 64},
                    "max_lines": {"type": "integer", "minimum": 1, "maximum": 100},
                },
                required=("collector_id", "max_lines"),
            ),
            ("line_count", "lines", "redaction_applied"),
            10,
        ),
        "dump_ui": AgentToolSpec(
            "dump_ui",
            _object_schema({"package_name": PACKAGE_PROPERTY}, required=("package_name",)),
            (
                "capture_status",
                "reason",
                "node_count",
                "focused_package",
                "focused_activity",
                "target_package_running",
                "target_pid",
                "text_values",
                "resource_ids",
                "raw_preview",
                "xml_sha256",
            ),
            35,
        ),
        "tap_coordinates": AgentToolSpec(
            "tap_coordinates",
            _object_schema(
                {
                    "x": {"type": "integer", "minimum": 0, "maximum": 10000},
                    "y": {"type": "integer", "minimum": 0, "maximum": 10000},
                    "reason": {
                        "type": "string",
                        "enum": ["manual_navigation", "agent_navigation"],
                    },
                },
                required=("x", "y", "reason"),
            ),
            ("tapped", "x", "y"),
            15,
        ),
        "type_text": AgentToolSpec(
            "type_text",
            _object_schema(
                {
                    "text": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 128,
                        "pattern": SAFE_INPUT_TEXT_RE.pattern,
                    },
                    "reason": {
                        "type": "string",
                        "enum": ["manual_navigation", "agent_navigation"],
                    },
                },
                required=("text", "reason"),
            ),
            ("typed", "length", "preview_redacted"),
            15,
        ),
        "frida_status": AgentToolSpec(
            "frida_status",
            _object_schema({"package_name": PACKAGE_PROPERTY}, required=("package_name",)),
            (
                "status", "frida_client_installed", "frida_client_version",
                "frida_server_reachable", "frida_server_version", "version_agreement",
                "frida_rpc", "emulator_serial", "android_version", "api_level", "abi",
                "root_available", "target_package", "target_package_installed",
                "target_pid", "attach_capability", "attach_error", "process_count",
            ),
            45,
        ),
        "frida_ps": AgentToolSpec(
            "frida_ps",
            _object_schema({}),
            ("status", "emulator_serial", "process_count", "processes", "truncated"),
            30,
        ),
        "frida_setup": AgentToolSpec(
            "frida_setup",
            _object_schema({"package_name": PACKAGE_PROPERTY}, required=("package_name",)),
            ("status", "before_state", "actions_taken", "after_state", "verification"),
            90,
        ),
        "frida_attach": AgentToolSpec(
            "frida_attach",
            _object_schema(
                {
                    "package_name": PACKAGE_PROPERTY,
                    "mode": {"type": "string", "enum": ["attach", "spawn"]},
                    "timeout": {"type": "integer", "minimum": 1, "maximum": 30},
                },
                required=("package_name", "mode", "timeout"),
            ),
            (
                "status", "package_name", "mode", "pid", "frida_version",
                "architecture", "attach_duration_seconds", "attach_event_received",
                "cleanup_state",
            ),
            45,
        ),
        "frida_run_js": AgentToolSpec(
            "frida_run_js",
            _object_schema(
                {
                    "package_name": PACKAGE_PROPERTY,
                    "mode": {"type": "string", "enum": ["attach", "spawn"]},
                    "source": {
                        "type": "string", "minLength": 1,
                        "maxLength": MAX_FRIDA_SCRIPT_BYTES,
                    },
                    "timeout": {"type": "integer", "minimum": 1, "maximum": 30},
                    "capture_logcat": {"type": "boolean"},
                    "capture_screenshot": {"type": "boolean"},
                },
                required=(
                    "package_name", "mode", "source", "timeout",
                    "capture_logcat", "capture_screenshot",
                ),
            ),
            (
                "status", "package_name", "mode", "pid", "frida_version",
                "architecture", "script_sha256", "script_size_bytes", "script_started",
                "script_loaded", "script_completed", "events", "event_count",
                "error_count", "duration_seconds", "started_at", "finished_at",
                "cleanup_state", "before_screenshot_sha256", "after_screenshot_sha256",
                "logcat",
            ),
            50,
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
    validated = _validate_arguments(tool_name, arguments, requested_by=requested_by)
    bounded_client = client or DynamicHostAgentClient(
        timeout_seconds=max(6, spec.timeout_seconds),
    )
    started = monotonic()
    try:
        output = _dispatch_tool(
            tool_name,
            validated,
            client=bounded_client,
            requested_by=requested_by,
        )
    except HostAgentClientError as exc:
        if exc.code.startswith("HOST_AGENT_") and exc.code not in {
            "HOST_AGENT_DISABLED",
            "HOST_AGENT_NOT_CONFIGURED",
            "HOST_AGENT_UNREACHABLE",
        }:
            raise AgentToolError(
                str(exc)[:500],
                code=exc.code,
                failure_category="TOOL_EXECUTION_FAILED",
            ) from None
        raise AgentToolError(
            _safe_host_agent_failure(exc.code),
            code=exc.code,
            failure_category="HOST_AGENT_UNAVAILABLE",
        ) from None
    except (FileProviderError, OSError, BotoCoreError, ClientError) as exc:
        raise AgentToolError(
            str(exc)[:500],
            code="APK_UNAVAILABLE",
            failure_category="TOOL_EXECUTION_FAILED",
        ) from None
    if monotonic() - started > spec.timeout_seconds:
        raise AgentToolError(
            f"Agent tool {tool_name} exceeded its execution limit.",
            code="AGENT_TOOL_TIMEOUT",
            failure_category="TIMEOUT",
        )
    return {field: output.get(field) for field in spec.output_fields}


def _dispatch_tool(
    tool_name: str,
    arguments: dict[str, Any],
    *,
    client: DynamicHostAgentClient,
    requested_by,
) -> dict[str, Any]:
    if tool_name == "get_device_status":
        return _get_device_status(client, requested_by=requested_by)
    if tool_name == "take_screenshot":
        return _take_screenshot(
            client,
            capture_reason=arguments["capture_reason"],
            audit_id=arguments.get("audit_id"),
        )
    if tool_name == "install_verified_apk":
        return _install_verified_apk(client, arguments, requested_by=requested_by)

    route = {
        "list_packages": "/actions/list-packages",
        "launch_package": "/actions/launch-package",
        "force_stop_package": "/actions/force-stop",
        "clear_package_data": "/actions/clear-data",
        "start_logcat": "/actions/logcat-bounded-capture",
        "stop_logcat": "/actions/logcat-stop",
        "get_logcat_excerpt": "/actions/logcat-excerpt",
        "dump_ui": "/actions/ui-dump",
        "tap_coordinates": "/actions/tap",
        "type_text": "/actions/type-text",
        "frida_status": "/actions/frida-status",
        "frida_ps": "/actions/frida-ps",
        "frida_setup": "/actions/frida-setup",
        "frida_attach": "/actions/frida-attach",
        "frida_run_js": "/actions/frida-run-js",
    }[tool_name]
    body = (
        {"package_name": arguments["package_name"]}
        if tool_name
        in {"launch_package", "force_stop_package", "clear_package_data"}
        else arguments
    )
    if tool_name == "frida_run_js" and body.get("source") == BUILTIN_FRIDA_UI_PROOF:
        body = {**body, "source": RUNTIME_UI_MODIFICATION_PROOF_SOURCE}
    raw = client.request_json(route, method="POST", body=body)
    if raw.get("success") is False and tool_name not in {
        "stop_logcat",
        "get_logcat_excerpt",
        "frida_status",
    }:
        _tool_failure(
            f"The bounded host action for {tool_name} did not succeed.",
            "HOST_ACTION_FAILED",
        )
    if tool_name == "list_packages":
        packages = []
        for item in raw.get("packages", [])[:MAX_PACKAGES]:
            if isinstance(item, str):
                item = {"package_name": item}
            if not isinstance(item, dict):
                continue
            package_name = _package_name_or_empty(item.get("package_name"))
            if package_name:
                packages.append(
                    {
                        "package_name": package_name,
                        "version_name": _bounded_text(item.get("version_name"), 128),
                        "version_code": _nullable_positive_int(item.get("version_code")),
                        "is_system": (
                            bool(item["is_system"]) if "is_system" in item else None
                        ),
                    }
                )
        return {"package_count": len(packages), "packages": packages}
    if tool_name == "launch_package":
        _audit_action("launch-package", raw, requested_by, arguments["package_name"])
        return {"launched": bool(raw.get("success")), "focused_app": _bounded_text(raw.get("focused_app"), 255)}
    if tool_name == "force_stop_package":
        _audit_action("force-stop", raw, requested_by, arguments["package_name"])
        return {"stopped": bool(raw.get("success"))}
    if tool_name == "clear_package_data":
        _audit_action("clear-data", raw, requested_by, arguments["package_name"])
        return {"cleared": bool(raw.get("success"))}
    if tool_name == "start_logcat":
        return {
            "collector_id": _bounded_text(raw.get("collector_id"), 64),
            "started_at": _bounded_text(raw.get("started_at"), 64),
            "max_seconds": _bounded_int(raw.get("max_seconds"), 1, 60),
            "package_filter_applied": bool(raw.get("package_filter_applied")),
        }
    if tool_name == "stop_logcat":
        return {
            "collector_id": _bounded_text(raw.get("collector_id"), 64),
            "stopped": bool(raw.get("stopped")),
            "supported": bool(raw.get("supported")),
            "status": _bounded_text(raw.get("status"), 64),
        }
    if tool_name == "get_logcat_excerpt":
        lines = [
            _bounded_text(line, 1000)
            for line in raw.get("lines", [])[: arguments["max_lines"]]
            if isinstance(line, str)
        ]
        return {
            "line_count": len(lines),
            "lines": lines,
            "redaction_applied": bool(raw.get("redaction_applied")),
        }
    if tool_name == "dump_ui":
        return {
            "capture_status": _bounded_text(raw.get("capture_status"), 32),
            "reason": _bounded_text(raw.get("reason"), 500),
            "node_count": _bounded_int(raw.get("node_count"), 0, 10000),
            "focused_package": _package_name_or_empty(raw.get("focused_package")),
            "focused_activity": _bounded_text(raw.get("focused_activity"), 255),
            "target_package_running": bool(raw.get("target_package_running")),
            "target_pid": _nullable_positive_int(raw.get("target_pid")),
            "text_values": _bounded_string_list(raw.get("text_values"), MAX_UI_VALUES, 256),
            "resource_ids": _bounded_string_list(raw.get("resource_ids"), MAX_UI_VALUES, 255),
            "raw_preview": _bounded_text(raw.get("raw_preview"), MAX_UI_PREVIEW_CHARS),
            "xml_sha256": _bounded_sha256(raw.get("xml_sha256")),
        }
    if tool_name == "tap_coordinates":
        _audit_action("tap", raw, requested_by, metadata={"x": arguments["x"], "y": arguments["y"]})
        return {"tapped": bool(raw.get("success")), "x": arguments["x"], "y": arguments["y"]}
    if tool_name == "frida_status":
        return _normalize_frida_status(raw)
    if tool_name == "frida_ps":
        processes = []
        for item in raw.get("processes", [])[:MAX_FRIDA_PROCESSES]:
            if not isinstance(item, dict):
                continue
            pid = _nullable_positive_int(item.get("pid"))
            if not pid:
                continue
            processes.append({
                "pid": pid,
                "name": _bounded_text(item.get("name"), 255),
                "application": _package_name_or_empty(item.get("application")),
            })
        return {
            "status": _bounded_text(raw.get("status"), 16),
            "emulator_serial": _bounded_text(raw.get("emulator_serial"), 128),
            "process_count": len(processes),
            "processes": processes,
            "truncated": bool(raw.get("truncated")),
        }
    if tool_name == "frida_setup":
        return {
            "status": _bounded_text(raw.get("status"), 16),
            "before_state": _normalize_frida_status(raw.get("before_state")),
            "actions_taken": _bounded_string_list(raw.get("actions_taken"), 20, 128),
            "after_state": _normalize_frida_status(raw.get("after_state")),
            "verification": _bounded_mapping(raw.get("verification"), 20, 500),
        }
    if tool_name == "frida_attach":
        return {
            "status": _bounded_text(raw.get("status"), 16),
            "package_name": _package_name_or_empty(raw.get("package_name")),
            "mode": _bounded_text(raw.get("mode"), 16),
            "pid": _nullable_positive_int(raw.get("pid")),
            "frida_version": _bounded_text(raw.get("frida_version"), 32),
            "architecture": _bounded_text(raw.get("architecture"), 64),
            "attach_duration_seconds": _nullable_float(raw.get("attach_duration_seconds")),
            "attach_event_received": bool(raw.get("attach_event_received")),
            "cleanup_state": _bounded_text(raw.get("cleanup_state"), 32),
        }
    if tool_name == "frida_run_js":
        events = [
            _bounded_mapping(item, 32, 1000)
            for item in raw.get("events", [])[:MAX_FRIDA_EVENTS]
            if isinstance(item, dict)
        ]
        logcat = raw.get("logcat") if isinstance(raw.get("logcat"), dict) else {}
        return {
            "status": _bounded_text(raw.get("status"), 16),
            "package_name": _package_name_or_empty(raw.get("package_name")),
            "mode": _bounded_text(raw.get("mode"), 16),
            "pid": _nullable_positive_int(raw.get("pid")),
            "frida_version": _bounded_text(raw.get("frida_version"), 32),
            "architecture": _bounded_text(raw.get("architecture"), 64),
            "script_sha256": _bounded_sha256(raw.get("script_sha256")),
            "script_size_bytes": _bounded_int(raw.get("script_size_bytes"), 1, MAX_FRIDA_SCRIPT_BYTES),
            "script_started": bool(raw.get("script_started")),
            "script_loaded": bool(raw.get("script_loaded")),
            "script_completed": bool(raw.get("script_completed")),
            "events": events,
            "event_count": len(events),
            "error_count": _bounded_int(raw.get("error_count"), 0, MAX_FRIDA_EVENTS),
            "duration_seconds": _nullable_float(raw.get("duration_seconds")),
            "started_at": _bounded_text(raw.get("started_at"), 64),
            "finished_at": _bounded_text(raw.get("finished_at"), 64),
            "cleanup_state": _bounded_text(raw.get("cleanup_state"), 32),
            "before_screenshot_sha256": _bounded_sha256(raw.get("before_screenshot_sha256")),
            "after_screenshot_sha256": _bounded_sha256(raw.get("after_screenshot_sha256")),
            "logcat": {
                "t0": _bounded_text(logcat.get("t0"), 64),
                "t1": _bounded_text(logcat.get("t1"), 64),
                "t2": _bounded_text(logcat.get("t2"), 64),
                "pid": _nullable_positive_int(logcat.get("pid")),
                "package_name": _package_name_or_empty(logcat.get("package_name")),
                "line_count": _bounded_int(logcat.get("line_count"), 0, 100),
                "lines": _bounded_string_list(logcat.get("lines"), 100, 1000),
                "sha256": _bounded_sha256(logcat.get("sha256")),
                "redaction_applied": bool(logcat.get("redaction_applied")),
            },
        }
    _audit_action("type-text", raw, requested_by, metadata={"length": len(arguments["text"]), "preview": "[redacted]"})
    return {"typed": bool(raw.get("success")), "length": len(arguments["text"]), "preview_redacted": "[redacted]"}


def _validate_arguments(tool_name: str, arguments: Any, *, requested_by=None) -> dict[str, Any]:
    if not isinstance(arguments, dict):
        _invalid("Agent tool arguments must be a JSON object.")
    required_fields = {
        "get_device_status": set(),
        "list_packages": {"include_system"},
        "install_verified_apk": {"audit_id", "apk_file_id"},
        "launch_package": {"package_name"},
        "force_stop_package": {"package_name"},
        "clear_package_data": {"package_name", "confirm"},
        "take_screenshot": {"capture_reason"},
        "start_logcat": {"package_name", "reason", "max_seconds"},
        "stop_logcat": {"collector_id"},
        "get_logcat_excerpt": {"collector_id", "max_lines"},
        "dump_ui": {"package_name"},
        "tap_coordinates": {"x", "y", "reason"},
        "type_text": {"text", "reason"},
        "frida_status": {"package_name"},
        "frida_ps": set(),
        "frida_setup": {"package_name"},
        "frida_attach": {"package_name", "mode", "timeout"},
        "frida_run_js": {
            "package_name", "mode", "source", "timeout",
            "capture_logcat", "capture_screenshot",
        },
    }[tool_name]
    if tool_name == "take_screenshot":
        if set(arguments) not in ({"capture_reason"}, {"capture_reason", "audit_id"}):
            _invalid(f"{tool_name} arguments do not match its typed schema.")
    elif set(arguments) != required_fields:
        _invalid(f"{tool_name} arguments do not match its typed schema.")
    validated = dict(arguments)
    if tool_name == "get_device_status":
        return validated
    if tool_name == "list_packages":
        if not isinstance(arguments["include_system"], bool):
            _invalid("include_system must be a boolean.")
        return validated
    if tool_name == "install_verified_apk":
        for field in ("audit_id", "apk_file_id"):
            validated[field] = _positive_integer(arguments[field], field)
        return validated
    if "package_name" in arguments:
        if not isinstance(arguments["package_name"], str) or not PACKAGE_NAME_RE.fullmatch(arguments["package_name"]):
            _invalid("Invalid Android package name.")
    if tool_name == "clear_package_data":
        if arguments["confirm"] is not True:
            _invalid("clear_package_data requires confirm=true.")
        if user_role(requested_by) not in {"ADMIN", "ANALYST"}:
            raise AgentToolError(
                "Only an Analyst or Admin can clear application data.",
                code="TOOL_PERMISSION_DENIED",
                failure_category="TOOL_EXECUTION_FAILED",
            )
    if tool_name in {"frida_attach", "frida_run_js"}:
        if arguments["mode"] not in {"attach", "spawn"}:
            _invalid("Frida mode must be attach or spawn.")
        validated["timeout"] = _integer_in_range(arguments["timeout"], 1, 30, "timeout")
    if tool_name == "frida_run_js":
        if user_role(requested_by) not in {"ADMIN", "ANALYST"}:
            raise AgentToolError(
                "Only an Analyst or Admin can execute Frida JavaScript.",
                code="TOOL_PERMISSION_DENIED",
                failure_category="TOOL_EXECUTION_FAILED",
            )
        source = arguments["source"]
        if not isinstance(source, str) or not source.strip():
            _invalid("Frida JavaScript source cannot be empty.")
        if len(source.encode("utf-8")) > MAX_FRIDA_SCRIPT_BYTES or "\x00" in source:
            _invalid(
                f"Frida JavaScript must be at most {MAX_FRIDA_SCRIPT_BYTES} bytes "
                "with no NUL characters."
            )
        if not isinstance(arguments["capture_logcat"], bool) or not isinstance(
            arguments["capture_screenshot"], bool
        ):
            _invalid("Frida evidence capture flags must be booleans.")
    if tool_name == "take_screenshot" and arguments["capture_reason"] not in {
        "device_readiness", "manual_check", "instrumentation_before", "instrumentation_after",
    }:
        _invalid("Invalid screenshot capture_reason.")
    if tool_name == "take_screenshot" and "audit_id" in arguments:
        validated["audit_id"] = _positive_integer(arguments["audit_id"], "audit_id")
    if tool_name == "start_logcat":
        if arguments["reason"] not in {"manual_observation", "agent_step"}:
            _invalid("Invalid logcat reason.")
        validated["max_seconds"] = _integer_in_range(arguments["max_seconds"], 1, 60, "max_seconds")
    if tool_name in {"stop_logcat", "get_logcat_excerpt"}:
        collector_id = arguments["collector_id"]
        if not isinstance(collector_id, str) or not COLLECTOR_ID_RE.fullmatch(collector_id):
            _invalid("Invalid collector_id.")
    if tool_name == "get_logcat_excerpt":
        validated["max_lines"] = _integer_in_range(arguments["max_lines"], 1, 100, "max_lines")
    if tool_name == "tap_coordinates":
        validated["x"] = _integer_in_range(arguments["x"], 0, 10000, "x")
        validated["y"] = _integer_in_range(arguments["y"], 0, 10000, "y")
        if arguments["reason"] not in {"manual_navigation", "agent_navigation"}:
            _invalid("Invalid tap reason.")
    if tool_name == "type_text":
        text = arguments["text"]
        if not isinstance(text, str) or not SAFE_INPUT_TEXT_RE.fullmatch(text):
            _invalid("Text must be 1 to 128 safe printable characters with no controls.")
        if arguments["reason"] not in {"manual_navigation", "agent_navigation"}:
            _invalid("Invalid text input reason.")
    return validated


def _install_verified_apk(client, arguments: dict, *, requested_by=None) -> dict:
    apk_file = APKFile.objects.select_related("storage_reference").filter(
        pk=arguments["apk_file_id"],
        audit_id=arguments["audit_id"],
    ).first()
    if apk_file is None:
        _tool_failure("APK file must belong to the selected audit.", "APK_NOT_AUTHORIZED")
    storage_reference = apk_file.storage_reference
    if storage_reference is None or storage_reference.storage_status != ObjectStorageReference.StorageStatus.VERIFIED:
        _tool_failure("Selected APK object must be VERIFIED before installation.", "APK_NOT_VERIFIED")
    with APKFileProvider().open_apk_local_copy(apk_file) as apk_path:
        calculated_sha256 = _validate_verified_apk_bytes(apk_file, apk_path)
        result = client.install_apk(apk_path, expected_sha256=calculated_sha256)
    metadata = (
        result.get("package_metadata")
        if isinstance(result.get("package_metadata"), dict)
        else {}
    )
    # Reinstalling an already-present APK does not add a package to the host
    # agent's before/after inventory. If aapt/aapt2 is also unavailable there,
    # the host can truthfully report a successful install with empty package
    # metadata. The selected APK record is already audit-owned, VERIFIED, and
    # checksum-bound to the installed bytes, so its strictly validated package
    # metadata is the established backend fallback for this case.
    package_name = _package_name_or_empty(
        result.get("package_name")
        or metadata.get("package_name")
        or apk_file.package_name
    )
    if result.get("success") and package_name:
        update_fields = []
        if apk_file.package_name != package_name:
            apk_file.package_name = package_name
            update_fields.append("package_name")
        version_name = _bounded_text(metadata.get("version_name"), 128)
        if version_name and apk_file.version_name != version_name:
            apk_file.version_name = version_name
            update_fields.append("version_name")
        if update_fields:
            apk_file.save(update_fields=update_fields)
    record_host_agent_action(
        "install-apk",
        result,
        requested_by=requested_by,
        audit_id=apk_file.audit_id,
        apk_file_id=apk_file.id,
        package_name=package_name,
    )
    if not result.get("success"):
        _tool_failure("Verified APK installation did not succeed.", "HOST_ACTION_FAILED")
    if not package_name:
        _tool_failure(
            "Verified APK installed, but no valid package name could be determined.",
            "PACKAGE_METADATA_UNAVAILABLE",
        )
    return {
        "package_name": package_name,
        "version_name": _bounded_text(
            metadata.get("version_name") or apk_file.version_name,
            128,
        ),
        "version_code": _bounded_text(metadata.get("version_code"), 64),
        "launcher_activity": _bounded_text(metadata.get("launchable_activity"), 255),
        "sha256": _bounded_sha256(result.get("sha256") or calculated_sha256),
        "install_status": "PASS" if result.get("success") else "FAIL",
    }


def _validate_verified_apk_bytes(apk_file: APKFile, apk_path) -> str:
    size_bytes = apk_path.stat().st_size
    max_size = min(
        int(settings.MSAP_MAX_APK_SIZE_BYTES),
        int(settings.MSAP_DYNAMIC_HOST_AGENT_MAX_APK_SIZE_BYTES),
    )
    if size_bytes <= 0 or size_bytes > max_size:
        raise FileProviderError(f"Verified APK size must be between 1 and {max_size} bytes.")
    digest = sha256()
    with apk_path.open("rb") as apk_stream:
        prefix = apk_stream.read(4)
        digest.update(prefix)
        for chunk in iter(lambda: apk_stream.read(1024 * 1024), b""):
            digest.update(chunk)
    if prefix not in {b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"}:
        raise FileProviderError("Verified object does not have an APK/ZIP signature.")
    expected_sizes = {value for value in (apk_file.size_bytes, apk_file.storage_reference.size_bytes) if value is not None}
    if any(value != size_bytes for value in expected_sizes):
        raise FileProviderError("Verified APK size does not match stored metadata.")
    calculated = digest.hexdigest()
    expected_hashes = {value.strip().lower() for value in (apk_file.sha256, apk_file.storage_reference.sha256) if value and value.strip()}
    if any(value != calculated for value in expected_hashes):
        raise FileProviderError("Verified APK SHA-256 does not match stored metadata.")
    return calculated


def _get_device_status(client: DynamicHostAgentClient, *, requested_by=None) -> dict[str, Any]:
    payload = client.get_status()
    if not payload.get("connected"):
        code = str(payload.get("code") or "HOST_AGENT_UNAVAILABLE")
        raise AgentToolError(_safe_host_agent_failure(code), code=code, failure_category="HOST_AGENT_UNAVAILABLE")
    raw_device = payload.get("device")
    device = raw_device if isinstance(raw_device, dict) else {}
    serial = _bounded_text(device.get("serial"), 128)
    emulator_online = device.get("state") == "device"
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
        "ready": bool(serial and emulator_online),
    }


def _take_screenshot(
    client: DynamicHostAgentClient,
    *,
    capture_reason: str,
    audit_id: int | None = None,
) -> dict[str, Any]:
    screenshot = client.request_screenshot()
    width, height = _png_dimensions(screenshot)
    digest = sha256(screenshot).hexdigest()
    object_reference_id = None
    if audit_id is not None:
        audit = Audit.objects.select_related("project").filter(pk=audit_id).first()
        if audit is None:
            _tool_failure("Screenshot audit does not exist.", "AUDIT_NOT_FOUND")
        storage = MinIOStorageService()
        object_key = storage.build_object_key(
            audit.project_id,
            audit.id,
            "agent-instrumentation",
            f"{capture_reason}.png",
        )
        bucket = settings.MINIO_BUCKET_EVIDENCE
        storage.upload_bytes(bucket, object_key, screenshot, "image/png")
        reference = ObjectStorageReference.objects.create(
            bucket=bucket,
            object_key=object_key,
            object_type=ObjectStorageReference.ObjectType.EVIDENCE_SNIPPET,
            storage_status=ObjectStorageReference.StorageStatus.VERIFIED,
            content_type="image/png",
            size_bytes=len(screenshot),
            sha256=digest,
            audit=audit,
            project=audit.project,
            retention_policy=ObjectStorageReference.RetentionPolicy.ACTIVE_AUDIT,
            encryption_status=ObjectStorageReference.EncryptionStatus.EXPECTED,
            redaction_status=ObjectStorageReference.RedactionStatus.NOT_REQUIRED,
            access_scope=ObjectStorageReference.AccessScope.AUDIT,
        )
        object_reference_id = reference.pk
    return {
        "content_type": "image/png",
        "width": width,
        "height": height,
        "size_bytes": len(screenshot),
        "sha256": digest,
        "captured_at": timezone.now().isoformat(),
        "object_reference_id": object_reference_id,
    }


def _audit_action(action: str, result: dict, requested_by, package_name: str = "", metadata: dict | None = None) -> None:
    audited_result = dict(result)
    if metadata:
        audited_result["evidence"] = metadata
    record_host_agent_action(action, audited_result, requested_by=requested_by, package_name=package_name)


def _png_dimensions(payload: bytes) -> tuple[int | None, int | None]:
    if len(payload) < 24 or payload[:8] != b"\x89PNG\r\n\x1a\n" or payload[12:16] != b"IHDR":
        return None, None
    width, height = struct.unpack(">II", payload[16:24])
    return (width, height) if width > 0 and height > 0 else (None, None)


def _invalid(message: str):
    raise AgentToolError(message, code="INVALID_TOOL_INPUT", failure_category="TOOL_EXECUTION_FAILED")


def _tool_failure(message: str, code: str):
    raise AgentToolError(message, code=code, failure_category="TOOL_EXECUTION_FAILED")


def _positive_integer(value: Any, label: str) -> int:
    return _integer_in_range(value, 1, 2_147_483_647, label)


def _integer_in_range(value: Any, minimum: int, maximum: int, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        _invalid(f"{label} must be an integer from {minimum} to {maximum}.")
    return value


def _bounded_int(value: Any, minimum: int, maximum: int) -> int | None:
    parsed = _nullable_int(value)
    return parsed if parsed is not None and minimum <= parsed <= maximum else None


def _bounded_string_list(value: Any, max_items: int, max_length: int) -> list[str]:
    if not isinstance(value, list):
        return []
    return [_bounded_text(item, max_length) for item in value[:max_items] if isinstance(item, str)]


def _package_name_or_empty(value: Any) -> str:
    candidate = str(value or "")[:255]
    return candidate if PACKAGE_NAME_RE.fullmatch(candidate) else ""


def _bounded_sha256(value: Any) -> str:
    candidate = str(value or "").lower()
    return candidate if re.fullmatch(r"[a-f0-9]{64}", candidate) else ""


def _safe_host_agent_failure(code: str) -> str:
    if code == "HOST_AGENT_DISABLED":
        return "The dynamic host agent is disabled. Enable and start it before running this check."
    if code == "HOST_AGENT_NOT_CONFIGURED":
        return "The dynamic host agent is not configured for this environment."
    return "The dynamic host agent is unavailable or rejected the bounded mobile action."


def _bounded_text(value: Any, max_length: int) -> str:
    return str(value or "").replace("\x00", "")[:max_length]


def _normalize_frida_status(raw: Any) -> dict:
    raw = raw if isinstance(raw, dict) else {}
    return {
        "status": _bounded_text(raw.get("status"), 16),
        "frida_client_installed": bool(raw.get("frida_client_installed")),
        "frida_client_version": _bounded_text(raw.get("frida_client_version"), 32),
        "frida_server_reachable": bool(raw.get("frida_server_reachable")),
        "frida_server_version": _bounded_text(raw.get("frida_server_version"), 32),
        "version_agreement": bool(raw.get("version_agreement")),
        "frida_rpc": _bounded_text(raw.get("frida_rpc"), 32),
        "emulator_serial": _bounded_text(raw.get("emulator_serial"), 128),
        "android_version": _bounded_text(raw.get("android_version"), 64),
        "api_level": _nullable_positive_int(raw.get("api_level")),
        "abi": _bounded_text(raw.get("abi"), 64),
        "root_available": bool(raw.get("root_available")),
        "target_package": _package_name_or_empty(raw.get("target_package")),
        "target_package_installed": bool(raw.get("target_package_installed")),
        "target_pid": _nullable_positive_int(raw.get("target_pid")),
        "attach_capability": bool(raw.get("attach_capability")),
        "attach_error": _bounded_text(raw.get("attach_error"), 500),
        "process_count": _bounded_int(raw.get("process_count"), 0, MAX_FRIDA_PROCESSES),
    }


def _bounded_mapping(value: Any, max_items: int, max_text_length: int) -> dict:
    if not isinstance(value, dict):
        return {}
    result = {}
    for raw_key, raw_value in list(value.items())[:max_items]:
        key = _bounded_text(raw_key, 64)
        if isinstance(raw_value, (bool, int, float)) or raw_value is None:
            result[key] = raw_value
        else:
            result[key] = _bounded_text(raw_value, max_text_length)
    return result


def _nullable_float(value: Any) -> float | None:
    try:
        return round(float(value), 3)
    except (TypeError, ValueError):
        return None


def _nullable_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _nullable_positive_int(value: Any) -> int | None:
    result = _nullable_int(value)
    return result if result is not None and result > 0 else None
