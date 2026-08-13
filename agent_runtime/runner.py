#!/usr/bin/env python3
"""Deterministic, untrusted-side runner for the MSAP mobile tool sandbox."""

from __future__ import annotations

import json
import os
import re
import sys
from urllib import error as urllib_error
from urllib import request as urllib_request
from urllib.parse import urlsplit


DEVICE_READINESS_CHECK = "DEVICE_READINESS_CHECK"
BASIC_APP_INTERACTION_CHECK = "BASIC_APP_INTERACTION_CHECK"
FRIDA_RUNTIME_ACTION = "FRIDA_RUNTIME_ACTION"
FRIDA_RUNTIME_UI_MODIFICATION_PROOF = "FRIDA_RUNTIME_UI_MODIFICATION_PROOF"
FRIDA_CUSTOM_SCRIPT = "FRIDA_CUSTOM_SCRIPT"
SUPPORTED_OBJECTIVES = {
    DEVICE_READINESS_CHECK,
    BASIC_APP_INTERACTION_CHECK,
    FRIDA_RUNTIME_ACTION,
    FRIDA_RUNTIME_UI_MODIFICATION_PROOF,
    FRIDA_CUSTOM_SCRIPT,
}
PACKAGE_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]*(?:\.[a-zA-Z0-9_]+)+$")
REQUEST_TIMEOUT_SECONDS = 130
MAX_RESPONSE_BYTES = 512 * 1024
MAX_OBJECTIVE_INPUT_BYTES = 40 * 1024


class RunnerError(RuntimeError):
    pass


def main() -> int:
    try:
        run_id, gateway_url, run_token, objective, objective_input = _configuration()
        plan = _build_plan(objective, objective_input)
    except RunnerError as exc:
        _emit("run_failed", category="CONFIGURATION", detail=str(exc))
        return 2

    _emit("run_started", run_id=run_id, objective=objective)
    outputs: dict[str, dict] = {}
    result: dict = {}
    for sequence_number, tool_name, template_arguments in plan:
        arguments = _resolve_arguments(template_arguments, outputs)
        _emit(
            "step_started",
            run_id=run_id,
            sequence_number=sequence_number,
            tool_name=tool_name,
        )
        try:
            result = _call_gateway(
                gateway_url=gateway_url,
                run_id=run_id,
                run_token=run_token,
                tool_name=tool_name,
                arguments=arguments,
            )
            _validate_gateway_result(
                result,
                run_id=run_id,
                sequence_number=sequence_number,
                tool_name=tool_name,
            )
        except RunnerError as exc:
            _emit(
                "step_failed",
                run_id=run_id,
                sequence_number=sequence_number,
                tool_name=tool_name,
                detail=str(exc),
            )
            return 3
        outputs[tool_name] = result["output"]
        _emit(
            "step_completed",
            run_id=run_id,
            sequence_number=sequence_number,
            tool_name=tool_name,
            step_status=result["step_status"],
            run_status=result["run_status"],
            output=result["output"],
        )

    if result.get("run_status") != "SUCCEEDED":
        _emit(
            "run_failed",
            run_id=run_id,
            category="INCOMPLETE",
            detail="The gateway did not finalize the deterministic run.",
        )
        return 4
    _emit("run_completed", run_id=run_id, status="SUCCEEDED")
    return 0


def _configuration() -> tuple[int, str, str, str, dict]:
    # These are the only environment values the runner reads.
    raw_run_id = os.getenv("MSAP_AGENT_RUN_ID", "")
    gateway_url = os.getenv("MSAP_AGENT_GATEWAY_URL", "").rstrip("/")
    run_token = os.getenv("MSAP_AGENT_RUN_TOKEN", "")
    objective = os.getenv("MSAP_AGENT_OBJECTIVE", "")
    raw_objective_input = os.getenv("MSAP_AGENT_OBJECTIVE_INPUT", "{}")
    if not raw_run_id.isascii() or not raw_run_id.isdigit() or int(raw_run_id) < 1:
        raise RunnerError("MSAP_AGENT_RUN_ID must be a positive integer.")
    parsed_url = urlsplit(gateway_url)
    if (
        parsed_url.scheme not in {"http", "https"}
        or not parsed_url.netloc
        or parsed_url.username is not None
        or parsed_url.password is not None
        or parsed_url.query
        or parsed_url.fragment
    ):
        raise RunnerError("MSAP_AGENT_GATEWAY_URL must be an HTTP(S) origin.")
    if not run_token or len(run_token) > 256:
        raise RunnerError("MSAP_AGENT_RUN_TOKEN is missing or invalid.")
    if objective not in SUPPORTED_OBJECTIVES:
        raise RunnerError("The requested objective is not supported.")
    if len(raw_objective_input.encode("utf-8")) > MAX_OBJECTIVE_INPUT_BYTES:
        raise RunnerError("The bounded objective input is too large.")
    try:
        objective_input = json.loads(raw_objective_input)
    except json.JSONDecodeError:
        raise RunnerError("MSAP_AGENT_OBJECTIVE_INPUT must be valid JSON.") from None
    if not isinstance(objective_input, dict):
        raise RunnerError("MSAP_AGENT_OBJECTIVE_INPUT must be a JSON object.")
    return int(raw_run_id), gateway_url, run_token, objective, objective_input


def _build_plan(objective: str, values: dict) -> tuple[tuple[int, str, dict], ...]:
    if objective == DEVICE_READINESS_CHECK:
        if values:
            raise RunnerError("Device readiness does not accept objective input.")
        return (
            (1, "get_device_status", {}),
            (2, "take_screenshot", {"capture_reason": "device_readiness"}),
        )
    if objective in {
        FRIDA_RUNTIME_ACTION,
        FRIDA_RUNTIME_UI_MODIFICATION_PROOF,
        FRIDA_CUSTOM_SCRIPT,
    }:
        return _build_frida_plan(objective, values)
    allowed = {"audit_id", "apk_file_id", "package_name", "tap", "text"}
    if set(values) - allowed:
        raise RunnerError("The basic interaction objective contains unknown fields.")
    audit_id = values.get("audit_id")
    apk_file_id = values.get("apk_file_id")
    package_name = values.get("package_name")
    if isinstance(audit_id, bool) or not isinstance(audit_id, int) or audit_id < 1:
        raise RunnerError("The basic interaction objective requires audit_id.")
    if (apk_file_id is None) == (package_name is None):
        raise RunnerError("Provide exactly one APK or installed package target.")
    if package_name is not None and (
        not isinstance(package_name, str) or not PACKAGE_RE.fullmatch(package_name)
    ):
        raise RunnerError("The objective package name is invalid.")
    if apk_file_id is not None and (
        isinstance(apk_file_id, bool) or not isinstance(apk_file_id, int) or apk_file_id < 1
    ):
        raise RunnerError("The objective APK file ID is invalid.")
    package_template = package_name or "$installed_package"
    plan: list[tuple[int, str, dict]] = [(1, "get_device_status", {})]
    if apk_file_id is not None:
        plan.append(
            (2, "install_verified_apk", {"audit_id": audit_id, "apk_file_id": apk_file_id})
        )
    plan.extend(
        [
            (3, "launch_package", {"package_name": package_template}),
            (4, "take_screenshot", {"capture_reason": "manual_check"}),
            (5, "dump_ui", {"package_name": package_template}),
            (
                6,
                "start_logcat",
                {
                    "package_name": package_template,
                    "reason": "agent_step",
                    "max_seconds": 60,
                },
            ),
        ]
    )
    tap = values.get("tap")
    if tap is not None:
        if not isinstance(tap, dict) or set(tap) != {"x", "y"}:
            raise RunnerError("The objective tap input is invalid.")
        plan.append(
            (
                7,
                "tap_coordinates",
                {"x": tap.get("x"), "y": tap.get("y"), "reason": "agent_navigation"},
            )
        )
    text = values.get("text")
    if text is not None:
        plan.append((8, "type_text", {"text": text, "reason": "agent_navigation"}))
    plan.extend(
        [
            (9, "get_logcat_excerpt", {"collector_id": "$collector_id", "max_lines": 100}),
            (10, "force_stop_package", {"package_name": package_template}),
        ]
    )
    return tuple(plan)


def _build_frida_plan(objective: str, values: dict) -> tuple[tuple[int, str, dict], ...]:
    package_name = values.get("package_name")
    audit_id = values.get("audit_id")
    if isinstance(audit_id, bool) or not isinstance(audit_id, int) or audit_id < 1:
        raise RunnerError("Runtime instrumentation requires audit_id.")
    if not isinstance(package_name, str) or not PACKAGE_RE.fullmatch(package_name):
        raise RunnerError("The instrumentation package name is invalid.")
    if objective == FRIDA_RUNTIME_ACTION:
        allowed = {"audit_id", "package_name", "operation", "mode", "timeout"}
        if set(values) - allowed:
            raise RunnerError("The Frida action contains unknown fields.")
        operation = values.get("operation")
        if operation == "status":
            return (
                (1, "launch_package", {"package_name": package_name}),
                (2, "frida_status", {"package_name": package_name}),
            )
        if operation == "setup":
            return ((1, "frida_setup", {"package_name": package_name}),)
        if operation == "ps":
            return ((1, "frida_ps", {}),)
        if operation == "attach":
            return (
                (1, "launch_package", {"package_name": package_name}),
                (
                    2,
                    "frida_attach",
                    {
                        "package_name": package_name,
                        "mode": values.get("mode", "attach"),
                        "timeout": values.get("timeout", 10),
                    },
                ),
            )
        raise RunnerError("The Frida action is invalid.")
    common_prefix = (
        (1, "get_device_status", {}),
        (2, "launch_package", {"package_name": package_name}),
        (3, "take_screenshot", {"capture_reason": "instrumentation_before", "audit_id": audit_id}),
        (4, "dump_ui", {"package_name": package_name}),
    )
    if objective == FRIDA_RUNTIME_UI_MODIFICATION_PROOF:
        allowed = {"audit_id", "package_name"}
        if set(values) - allowed:
            raise RunnerError("The built-in Frida proof contains unknown fields.")
        return common_prefix + (
            (5, "frida_status", {"package_name": package_name}),
            (6, "frida_attach", {"package_name": package_name, "mode": "attach", "timeout": 10}),
            (
                7,
                "frida_run_js",
                {
                    "package_name": package_name,
                    "mode": "attach",
                    "source": "__MSAP_BUILTIN_FRIDA_UI_MODIFICATION_PROOF__",
                    "timeout": 12,
                    "capture_logcat": True,
                    "capture_screenshot": False,
                },
            ),
            (8, "take_screenshot", {"capture_reason": "instrumentation_after", "audit_id": audit_id}),
            (9, "dump_ui", {"package_name": package_name}),
            (10, "force_stop_package", {"package_name": package_name}),
        )
    allowed = {
        "audit_id", "package_name", "mode", "source", "timeout",
        "capture_logcat", "confirm",
    }
    if set(values) - allowed or values.get("confirm") is not True:
        raise RunnerError("The custom Frida script contract is invalid.")
    source = values.get("source")
    if not isinstance(source, str) or not source.strip() or "\x00" in source:
        raise RunnerError("The custom Frida JavaScript is invalid.")
    if len(source.encode("utf-8")) > 32 * 1024:
        raise RunnerError("The custom Frida JavaScript is too large.")
    return common_prefix + (
        (
            5,
            "frida_run_js",
            {
                "package_name": package_name,
                "mode": values.get("mode", "attach"),
                "source": source,
                "timeout": values.get("timeout", 12),
                "capture_logcat": bool(values.get("capture_logcat", True)),
                "capture_screenshot": False,
            },
        ),
        (6, "take_screenshot", {"capture_reason": "instrumentation_after", "audit_id": audit_id}),
        (7, "dump_ui", {"package_name": package_name}),
        (8, "force_stop_package", {"package_name": package_name}),
    )


def _resolve_arguments(arguments: dict, outputs: dict[str, dict]) -> dict:
    resolved = dict(arguments)
    for key, value in tuple(resolved.items()):
        if value == "$installed_package":
            value = outputs.get("install_verified_apk", {}).get("package_name")
        elif value == "$collector_id":
            value = outputs.get("start_logcat", {}).get("collector_id")
        resolved[key] = value
    return resolved


def _call_gateway(
    *, gateway_url: str, run_id: int, run_token: str, tool_name: str, arguments: dict
) -> dict:
    body = json.dumps(
        {"tool_name": tool_name, "arguments": arguments}, separators=(",", ":")
    ).encode("utf-8")
    endpoint = f"{gateway_url}/api/dynamic/agent/runs/{run_id}/tool-call/"
    request = urllib_request.Request(
        endpoint,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {run_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    try:
        with urllib_request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            payload = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib_error.HTTPError as exc:
        raise RunnerError(f"The tool gateway rejected the call (HTTP {exc.code}).") from None
    except (urllib_error.URLError, TimeoutError, OSError):
        raise RunnerError("The tool gateway is unavailable.") from None
    if len(payload) > MAX_RESPONSE_BYTES:
        raise RunnerError("The tool gateway response exceeded the size limit.")
    try:
        result = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise RunnerError("The tool gateway returned invalid JSON.") from None
    if not isinstance(result, dict):
        raise RunnerError("The tool gateway returned an invalid result.")
    return result


def _validate_gateway_result(
    result: dict, *, run_id: int, sequence_number: int, tool_name: str
) -> None:
    if (
        result.get("run_id") != run_id
        or result.get("sequence_number") != sequence_number
        or result.get("tool_name") != tool_name
        or result.get("step_status") != "SUCCEEDED"
        or not isinstance(result.get("output"), dict)
    ):
        raise RunnerError("The tool gateway response did not match the run step.")


def _emit(event: str, **fields) -> None:
    print(json.dumps({"event": event, **fields}, sort_keys=True), flush=True)


if __name__ == "__main__":
    sys.exit(main())
