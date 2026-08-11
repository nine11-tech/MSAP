#!/usr/bin/env python3
"""Deterministic, untrusted-side runner for the MSAP Sprint C sandbox."""

from __future__ import annotations

import json
import os
import sys
from urllib import error as urllib_error
from urllib import request as urllib_request
from urllib.parse import urlsplit


OBJECTIVE = "DEVICE_READINESS_CHECK"
PLAN = (
    ("get_device_status", {}),
    ("take_screenshot", {"capture_reason": "device_readiness"}),
)
REQUEST_TIMEOUT_SECONDS = 30
MAX_RESPONSE_BYTES = 64 * 1024


class RunnerError(RuntimeError):
    pass


def main() -> int:
    try:
        run_id, gateway_url, run_token, objective = _configuration()
    except RunnerError as exc:
        _emit("run_failed", category="CONFIGURATION", detail=str(exc))
        return 2

    _emit("run_started", run_id=run_id, objective=objective)
    for sequence_number, (tool_name, arguments) in enumerate(PLAN, start=1):
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
        _emit(
            "step_completed",
            run_id=run_id,
            sequence_number=sequence_number,
            tool_name=tool_name,
            step_status=result["step_status"],
            run_status=result["run_status"],
            output=result["output"],
        )

    if result["run_status"] != "SUCCEEDED":
        _emit(
            "run_failed",
            run_id=run_id,
            category="INCOMPLETE",
            detail="The gateway did not finalize the deterministic run.",
        )
        return 4
    _emit("run_completed", run_id=run_id, status="SUCCEEDED")
    return 0


def _configuration() -> tuple[int, str, str, str]:
    # These are the only environment values the runner reads.
    raw_run_id = os.getenv("MSAP_AGENT_RUN_ID", "")
    gateway_url = os.getenv("MSAP_AGENT_GATEWAY_URL", "").rstrip("/")
    run_token = os.getenv("MSAP_AGENT_RUN_TOKEN", "")
    objective = os.getenv("MSAP_AGENT_OBJECTIVE", "")
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
    if objective != OBJECTIVE:
        raise RunnerError("The requested objective is not supported.")
    return int(raw_run_id), gateway_url, run_token, objective


def _call_gateway(
    *,
    gateway_url: str,
    run_id: int,
    run_token: str,
    tool_name: str,
    arguments: dict,
) -> dict:
    body = json.dumps(
        {"tool_name": tool_name, "arguments": arguments},
        separators=(",", ":"),
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
    result: dict,
    *,
    run_id: int,
    sequence_number: int,
    tool_name: str,
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
