from __future__ import annotations

import ast
from datetime import datetime, timezone
from hashlib import sha256
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import time
from typing import Any, Callable

from apps.dynamic_analysis.services.local_scripts import _redacted_preview


MAX_FRIDA_SCRIPT_BYTES = 32 * 1024
MAX_FRIDA_EVENTS = 200
MAX_FRIDA_EVENT_BYTES = 4096
MAX_FRIDA_PROCESSES = 500
MAX_FRIDA_LOGCAT_BYTES = 128 * 1024
MAX_FRIDA_LOGCAT_LINES = 100
FRIDA_SERVER_PATH = "/data/local/tmp/msap-frida-server"
FRIDA_SERVER_PROCESS = "msap-frida-server"
ATTACH_PROBE_SOURCE = (
    'send({type:"attach_probe",success:true,pid:Process.id,'
    'architecture:Process.arch});'
)


class FridaRuntimeError(RuntimeError):
    def __init__(self, message: str, *, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code


class FridaRuntime:
    """Fixed-command Frida adapter for the managed Android lab."""

    def __init__(
        self,
        *,
        serial: str,
        run_adb: Callable[..., dict],
        run_adb_binary: Callable[..., dict],
        adb_text: Callable[..., str],
        run_command: Callable[..., dict],
        screenshot: Callable[[], bytes],
        device_status: Callable[[], dict],
        require_installed_package: Callable[[str], None],
        package_pid: Callable[[str], str],
    ):
        self.serial = serial
        self._run_adb = run_adb
        self._run_adb_binary = run_adb_binary
        self._adb_text = adb_text
        self._run_command = run_command
        self._screenshot = screenshot
        self._device_status = device_status
        self._require_installed_package = require_installed_package
        self._package_pid = package_pid

    def status(self, package_name: str, *, verify_attach: bool = True) -> dict:
        device = self._require_device()
        self._require_installed_package(package_name)
        client_path = self._frida_executable_or_empty(
            "frida", "MSAP_FRIDA_CLIENT_BIN"
        )
        ps_path = self._frida_executable_or_empty(
            "frida-ps", "MSAP_FRIDA_PS_BIN"
        )
        client_version = self._client_version(client_path) if client_path else ""
        server_version = self._server_binary_version()
        endpoint = ""
        endpoint_error = ""
        try:
            endpoint = self._endpoint()
        except FridaRuntimeError as exc:
            endpoint_error = str(exc)
        processes = (
            self._enumerate_processes(ps_path, endpoint, required=False)
            if ps_path and endpoint
            else None
        )
        server_reachable = bool(processes)
        target_pid_text = self._package_pid(package_name)
        target_pid = int(target_pid_text) if target_pid_text else None
        attach_capability = False
        attach_error = endpoint_error
        if verify_attach and server_reachable and target_pid is not None:
            try:
                execution = self._run_script(
                    client_path=client_path,
                    endpoint=endpoint,
                    package_name=package_name,
                    mode="attach",
                    target_pid=target_pid,
                    source=ATTACH_PROBE_SOURCE,
                    timeout_seconds=6,
                )
                attach_capability = bool(
                    execution["success"]
                    and any(
                        event.get("type") == "attach_probe"
                        and event.get("success") is True
                        and event.get("pid") == target_pid
                        for event in execution["events"]
                    )
                )
                if not attach_capability:
                    attach_error = "Frida connected but did not return the attach probe event."
            except FridaRuntimeError as exc:
                attach_error = str(exc)
        elif verify_attach and not client_path:
            attach_error = "Frida client is not installed in the host-agent environment."
        elif verify_attach and target_pid is None:
            attach_error = "Target package is installed but not running."
        elif verify_attach and not server_reachable:
            attach_error = "Frida server is not reachable."
        return {
            "success": bool(
                client_path
                and client_version
                and server_reachable
                and server_version
                and client_version == server_version
                and (attach_capability if verify_attach else True)
            ),
            "status": "PASS" if (
                client_path
                and client_version
                and server_reachable
                and server_version
                and client_version == server_version
                and (attach_capability if verify_attach else True)
            ) else "FAIL",
            "frida_client_installed": bool(client_path),
            "frida_client_version": client_version,
            "frida_server_reachable": server_reachable,
            "frida_server_version": server_version,
            "version_agreement": bool(
                client_version and server_version and client_version == server_version
            ),
            "frida_rpc": "CONNECTED" if server_reachable else "UNAVAILABLE",
            "endpoint": endpoint,
            "emulator_serial": self.serial,
            "android_version": str(device.get("android_version") or "")[:64],
            "api_level": _positive_int_or_none(device.get("api_level")),
            "abi": str(device.get("abi") or "")[:64],
            "root_available": device.get("root_uid") == 0,
            "target_package": package_name,
            "target_package_installed": True,
            "target_pid": target_pid,
            "attach_capability": attach_capability,
            "attach_error": attach_error[:500],
            "process_count": len(processes or []),
        }

    def setup(self, package_name: str) -> dict:
        self._require_installed_package(package_name)
        before_state = self.status(package_name, verify_attach=False)
        actions_taken: list[str] = []
        client_version = before_state["frida_client_version"]
        server_version = before_state["frida_server_version"]
        if not client_version:
            raise FridaRuntimeError("Frida client is not installed in the host-agent environment.")
        if not server_version:
            raise FridaRuntimeError(
                f"Managed Frida server binary is missing or not executable at {FRIDA_SERVER_PATH}."
            )
        if client_version != server_version:
            raise FridaRuntimeError(
                f"Frida client/server version mismatch: {client_version} != {server_version}."
            )

        root_uid = self._adb_text("shell", "id", "-u", timeout_seconds=10)
        if root_uid.strip() != "0":
            root_result = self._run_adb("root", timeout_seconds=20)
            if root_result["return_code"] != 0:
                raise FridaRuntimeError("ADB root is required to manage Frida server.")
            self._run_adb("wait-for-device", timeout_seconds=30)
            actions_taken.append("restarted_adbd_as_root")

        forward_result = self._run_adb(
            "forward", "tcp:27042", "tcp:27042", timeout_seconds=15
        )
        if forward_result["return_code"] != 0:
            raise FridaRuntimeError("The fixed ADB Frida port forward could not be configured.")
        actions_taken.append("verified_adb_forward_27042")

        if not before_state["frida_server_reachable"]:
            for _attempt in range(2):
                time.sleep(0.35)
                retry_state = self.status(package_name, verify_attach=False)
                actions_taken.append("retried_frida_rpc")
                if retry_state["frida_server_reachable"]:
                    before_state = retry_state
                    break

        if not before_state["frida_server_reachable"]:
            server_pid = self._server_process_pid()
            if server_pid:
                self._stop_server(server_pid)
                actions_taken.append("stopped_unreachable_managed_server")
            start_result = self._run_adb(
                "shell", FRIDA_SERVER_PATH, "-D", timeout_seconds=20
            )
            if start_result["return_code"] == 0:
                actions_taken.append("started_managed_frida_server")
            else:
                # A concurrently healthy managed daemon can make the fixed
                # start argv return non-zero because its listener is already
                # bound. Accept only a subsequent real RPC verification.
                recovery_state = self.status(package_name, verify_attach=False)
                if not recovery_state["frida_server_reachable"]:
                    raise FridaRuntimeError("Managed Frida server failed to start.")
                actions_taken.append(
                    "server_start_returned_nonzero_rpc_already_verified"
                )

        after_state = self.status(package_name, verify_attach=False)
        if not (
            after_state["frida_server_reachable"]
            and after_state["version_agreement"]
            and after_state["frida_rpc"] == "CONNECTED"
        ):
            raise FridaRuntimeError(
                "Frida setup completed actions but RPC verification still failed.",
                status_code=502,
            )
        return {
            "success": True,
            "status": "PASS",
            "before_state": before_state,
            "actions_taken": actions_taken,
            "after_state": after_state,
            "verification": {
                "client_version": after_state["frida_client_version"],
                "server_version": after_state["frida_server_version"],
                "version_agreement": after_state["version_agreement"],
                "device": self.serial,
                "frida_rpc": after_state["frida_rpc"],
            },
        }

    def ps(self) -> dict:
        self._require_device()
        client_path = self._frida_executable("frida-ps", "MSAP_FRIDA_PS_BIN")
        endpoint = self._endpoint()
        processes = self._enumerate_processes(client_path, endpoint, required=True)
        applications = self._enumerate_applications(client_path, endpoint)
        package_by_pid = {
            item["pid"]: item["package"]
            for item in applications
            if item.get("pid") is not None and item.get("package")
        }
        for process in processes:
            process["application"] = package_by_pid.get(process["pid"], "")
        return {
            "success": True,
            "status": "PASS",
            "emulator_serial": self.serial,
            "endpoint": endpoint,
            "process_count": len(processes),
            "processes": processes[:MAX_FRIDA_PROCESSES],
            "truncated": len(processes) >= MAX_FRIDA_PROCESSES,
        }

    def attach(self, package_name: str, mode: str, timeout_seconds: int) -> dict:
        self._require_device()
        self._require_installed_package(package_name)
        timeout_seconds = _bounded_int(timeout_seconds, 1, 30, "timeout")
        if mode not in {"attach", "spawn"}:
            raise FridaRuntimeError("Frida attach mode must be attach or spawn.")
        client_path = self._frida_executable("frida", "MSAP_FRIDA_CLIENT_BIN")
        endpoint = self._endpoint()
        target_pid_text = self._package_pid(package_name)
        target_pid = int(target_pid_text) if target_pid_text else None
        if mode == "attach" and target_pid is None:
            raise FridaRuntimeError(
                f"Target package is installed but not running: {package_name}",
                status_code=409,
            )
        execution = self._run_script(
            client_path=client_path,
            endpoint=endpoint,
            package_name=package_name,
            mode=mode,
            target_pid=target_pid,
            source=ATTACH_PROBE_SOURCE,
            timeout_seconds=timeout_seconds,
        )
        attach_event = next(
            (event for event in execution["events"] if event.get("type") == "attach_probe"),
            None,
        )
        actual_pid = _positive_int_or_none(
            attach_event.get("pid") if attach_event else target_pid
        )
        if not execution["success"] or not attach_event or not actual_pid:
            raise FridaRuntimeError(
                "Frida attach did not produce a verified in-process probe event.",
                status_code=502,
            )
        return {
            "success": True,
            "status": "PASS",
            "package_name": package_name,
            "mode": mode,
            "pid": actual_pid,
            "frida_version": self._client_version(client_path),
            "architecture": str(attach_event.get("architecture") or "")[:64],
            "attach_duration_seconds": execution["duration_seconds"],
            "attach_event_received": True,
            "cleanup_state": execution["cleanup_state"],
        }

    def run_js(
        self,
        *,
        package_name: str,
        mode: str,
        source: str,
        timeout_seconds: int,
        capture_logcat: bool,
        capture_screenshot: bool,
    ) -> dict:
        self._require_device()
        self._require_installed_package(package_name)
        timeout_seconds = _bounded_int(timeout_seconds, 1, 30, "timeout")
        if mode not in {"attach", "spawn"}:
            raise FridaRuntimeError("Frida script mode must be attach or spawn.")
        if not isinstance(source, str) or not source.strip():
            raise FridaRuntimeError("Frida JavaScript source cannot be empty.")
        source_bytes = source.encode("utf-8")
        if len(source_bytes) > MAX_FRIDA_SCRIPT_BYTES:
            raise FridaRuntimeError(
                f"Frida JavaScript exceeds the {MAX_FRIDA_SCRIPT_BYTES}-byte limit."
            )
        if "\x00" in source:
            raise FridaRuntimeError("Frida JavaScript cannot contain NUL characters.")
        if not isinstance(capture_logcat, bool) or not isinstance(capture_screenshot, bool):
            raise FridaRuntimeError("Frida evidence capture flags must be booleans.")

        client_path = self._frida_executable("frida", "MSAP_FRIDA_CLIENT_BIN")
        endpoint = self._endpoint()
        target_pid_text = self._package_pid(package_name)
        target_pid = int(target_pid_text) if target_pid_text else None
        if mode == "attach" and target_pid is None:
            raise FridaRuntimeError(
                f"Target package is installed but not running: {package_name}",
                status_code=409,
            )
        before_screenshot_sha256 = ""
        if capture_screenshot:
            before_screenshot_sha256 = sha256(self._screenshot()).hexdigest()
        t0 = datetime.now(timezone.utc).isoformat()
        if capture_logcat:
            self._run_adb("logcat", "-c", timeout_seconds=10)

        execution = self._run_script(
            client_path=client_path,
            endpoint=endpoint,
            package_name=package_name,
            mode=mode,
            target_pid=target_pid,
            source=source,
            timeout_seconds=timeout_seconds,
        )
        t1 = execution["started_at"]
        actual_pid = _positive_int_or_none(execution.get("pid") or target_pid)
        after_screenshot_sha256 = ""
        if capture_screenshot:
            after_screenshot_sha256 = sha256(self._screenshot()).hexdigest()
        log_lines: list[str] = []
        logcat_redaction_applied = False
        if capture_logcat and actual_pid:
            log_result = self._run_adb_binary(
                "exec-out",
                "logcat",
                "-d",
                "-v",
                "threadtime",
                "--pid",
                str(actual_pid),
                "-t",
                "500",
                timeout_seconds=15,
                max_output_bytes=MAX_FRIDA_LOGCAT_BYTES + 1,
            )
            log_text, logcat_redaction_applied = _redacted_preview(
                log_result["stdout"][:MAX_FRIDA_LOGCAT_BYTES].decode(
                    "utf-8", errors="replace"
                )
            )
            log_lines = log_text.replace("\r", "").splitlines()[-MAX_FRIDA_LOGCAT_LINES:]
        t2 = datetime.now(timezone.utc).isoformat()
        logcat_digest = sha256("\n".join(log_lines).encode("utf-8")).hexdigest()
        # A probe is allowed to report a negative domain observation (for
        # example, ui_modification success=false).  The tool still executed
        # correctly and that bounded result belongs in evidence for the
        # deterministic oracle to evaluate.  Only runtime/script failures make
        # the gateway call fail.
        error_events = [
            event
            for event in execution["events"]
            if event.get("type") in {"script_error", "error", "exception"}
        ]
        if not execution["success"] or error_events:
            raise FridaRuntimeError(
                "Frida JavaScript execution failed or emitted an error event.",
                status_code=502,
            )
        return {
            "success": True,
            "status": "PASS",
            "package_name": package_name,
            "mode": mode,
            "pid": actual_pid,
            "frida_version": self._client_version(client_path),
            "architecture": execution.get("architecture", ""),
            "script_sha256": sha256(source_bytes).hexdigest(),
            "script_size_bytes": len(source_bytes),
            "script_started": execution["script_started"],
            "script_loaded": execution["script_loaded"],
            "script_completed": execution["script_completed"],
            "events": execution["events"],
            "event_count": len(execution["events"]),
            "error_count": len(error_events),
            "duration_seconds": execution["duration_seconds"],
            "started_at": execution["started_at"],
            "finished_at": execution["finished_at"],
            "cleanup_state": execution["cleanup_state"],
            "before_screenshot_sha256": before_screenshot_sha256,
            "after_screenshot_sha256": after_screenshot_sha256,
            "logcat": {
                "t0": t0,
                "t1": t1,
                "t2": t2,
                "pid": actual_pid,
                "package_name": package_name,
                "line_count": len(log_lines),
                "lines": log_lines,
                "sha256": logcat_digest,
                "redaction_applied": bool(logcat_redaction_applied),
            },
        }

    def _run_script(
        self,
        *,
        client_path: str,
        endpoint: str,
        package_name: str,
        mode: str,
        target_pid: int | None,
        source: str,
        timeout_seconds: int,
    ) -> dict:
        completion_delay_ms = max(500, min(3000, timeout_seconds * 1000 - 750))
        wrapped_source = (
            'send({type:"script_start",success:true,pid:Process.id,'
            'architecture:Process.arch});\n'
            "try {\n"
            + source
            + '\n send({type:"script_loaded",success:true,pid:Process.id});\n'
            + "} catch (error) { send({type:\"script_error\",success:false,error:String(error),pid:Process.id}); }\n"
            + f'setTimeout(function () {{ send({{type:"script_completion",success:true,pid:Process.id}}); }}, {completion_delay_ms});'
        )
        argv = [client_path, "-q", "-H", endpoint]
        if mode == "spawn":
            argv.extend(["-f", package_name])
        else:
            if target_pid is None:
                raise FridaRuntimeError("Attach mode requires a running target PID.")
            argv.extend(["-p", str(target_pid)])
        argv.extend(["-e", wrapped_source, "-t", str(timeout_seconds)])
        started_at = datetime.now(timezone.utc)
        result = self._run_command(
            argv,
            timeout_seconds=timeout_seconds + 10,
        )
        finished_at = datetime.now(timezone.utc)
        if result.get("timed_out"):
            raise FridaRuntimeError(
                "Frida JavaScript execution exceeded its bounded timeout.",
                status_code=504,
            )
        combined_output = "\n".join(
            [result.get("stdout_preview", ""), result.get("stderr_preview", "")]
        )
        events = _parse_frida_events(combined_output)
        pid = next(
            (
                _positive_int_or_none(event.get("pid"))
                for event in events
                if _positive_int_or_none(event.get("pid"))
            ),
            target_pid,
        )
        architecture = next(
            (
                str(event.get("architecture") or "")[:64]
                for event in events
                if event.get("architecture")
            ),
            "",
        )
        script_started = any(event.get("type") == "script_start" for event in events)
        script_loaded = any(event.get("type") == "script_loaded" for event in events)
        script_completed = any(
            event.get("type") == "script_completion" for event in events
        )
        success = bool(
            result.get("return_code") == 0
            and not result.get("timed_out")
            and script_started
            and script_loaded
            and script_completed
        )
        return {
            "success": success,
            "events": events,
            "pid": pid,
            "architecture": architecture,
            "script_started": script_started,
            "script_loaded": script_loaded,
            "script_completed": script_completed,
            "started_at": started_at.isoformat(),
            "finished_at": finished_at.isoformat(),
            "duration_seconds": max(
                0.0, round((finished_at - started_at).total_seconds(), 3)
            ),
            "cleanup_state": "DETACHED" if not result.get("timed_out") else "TIMEOUT",
        }

    def _require_device(self) -> dict:
        device = self._device_status()
        if not isinstance(device, dict) or device.get("state") != "device":
            raise FridaRuntimeError(
                f"Configured Android device is unavailable: {self.serial}",
                status_code=503,
            )
        if str(device.get("serial") or "") != self.serial:
            raise FridaRuntimeError(
                "Host-agent device response did not match the configured emulator serial.",
                status_code=502,
            )
        return device

    def _enumerate_processes(
        self, executable: str, endpoint: str, *, required: bool
    ) -> list[dict] | None:
        result = self._run_command(
            [executable, "-H", endpoint],
            timeout_seconds=20,
        )
        if result.get("return_code") != 0 or result.get("timed_out"):
            if required:
                raise FridaRuntimeError(
                    "Frida client could not enumerate emulator processes.",
                    status_code=503,
                )
            return None
        processes = _parse_process_table(result.get("stdout_preview", ""))
        if not processes and required:
            raise FridaRuntimeError(
                "Frida process enumeration returned zero real processes.",
                status_code=502,
            )
        return processes

    def _enumerate_applications(self, executable: str, endpoint: str) -> list[dict]:
        result = self._run_command(
            [executable, "-H", endpoint, "-ai"],
            timeout_seconds=20,
        )
        if result.get("return_code") != 0 or result.get("timed_out"):
            return []
        return _parse_application_table(result.get("stdout_preview", ""))

    def _server_process_pid(self) -> int | None:
        output = self._adb_text(
            "shell", "pidof", FRIDA_SERVER_PROCESS, timeout_seconds=10
        )
        return next(
            (
                int(value)
                for value in output.split()
                if value.isascii() and value.isdigit() and int(value) > 1
            ),
            None,
        )

    def _stop_server(self, pid: int) -> None:
        command_line = self._adb_text(
            "shell", "cat", f"/proc/{pid}/cmdline", timeout_seconds=10
        )
        if FRIDA_SERVER_PATH not in command_line:
            raise FridaRuntimeError(
                "Refusing to stop a process that is not the managed Frida server."
            )
        result = self._run_adb("shell", "kill", str(pid), timeout_seconds=10)
        if result["return_code"] != 0:
            raise FridaRuntimeError("Managed Frida server could not be stopped.")

    def _server_binary_version(self) -> str:
        output = self._adb_text(
            "shell", FRIDA_SERVER_PATH, "--version", timeout_seconds=15
        )
        return _version_or_empty(output)

    def _client_version(self, executable: str) -> str:
        result = self._run_command([executable, "--version"], timeout_seconds=10)
        if result.get("return_code") != 0 or result.get("timed_out"):
            return ""
        return _version_or_empty(result.get("stdout_preview", ""))

    @staticmethod
    def _frida_executable(command_name: str, environment_name: str) -> str:
        candidate = FridaRuntime._frida_executable_or_empty(
            command_name, environment_name
        )
        if candidate:
            return candidate
        raise FridaRuntimeError(
            f"Required Frida client command is unavailable: {command_name}",
            status_code=503,
        )

    @staticmethod
    def _frida_executable_or_empty(command_name: str, environment_name: str) -> str:
        configured = str(os.getenv(environment_name, "") or "").strip()
        candidate = configured or shutil.which(command_name) or ""
        if not candidate:
            return ""
        resolved = Path(candidate).resolve()
        if not resolved.is_file() or not os.access(resolved, os.X_OK):
            return ""
        return str(resolved)

    def _endpoint(self) -> str:
        configured = str(os.getenv("MSAP_FRIDA_ENDPOINT", "") or "").strip()
        if configured:
            return _validated_endpoint(configured)
        ip_path = shutil.which("ip")
        if not ip_path:
            raise FridaRuntimeError(
                "Frida endpoint is not configured and the Windows gateway cannot be resolved."
            )
        result = self._run_command(
            [ip_path, "route", "show", "default"], timeout_seconds=5
        )
        match = re.search(r"\bvia\s+(\d+\.\d+\.\d+\.\d+)\b", result.get("stdout_preview", ""))
        if not match:
            raise FridaRuntimeError("Windows gateway for the Frida bridge was not found.")
        port = _bounded_int(
            _environment_int("MSAP_FRIDA_BRIDGE_PORT", 27043),
            1,
            65535,
            "Frida bridge port",
        )
        return _validated_endpoint(f"{match.group(1)}:{port}")


def _parse_process_table(output: str) -> list[dict]:
    processes: list[dict] = []
    for line in output.replace("\r", "").splitlines():
        fields = line.strip().split(maxsplit=1)
        if len(fields) != 2 or not fields[0].isascii() or not fields[0].isdigit():
            continue
        pid = int(fields[0])
        if pid <= 0:
            continue
        processes.append({"pid": pid, "name": fields[1][:255], "application": ""})
        if len(processes) >= MAX_FRIDA_PROCESSES:
            break
    return processes


def _parse_application_table(output: str) -> list[dict]:
    applications: list[dict] = []
    for line in output.replace("\r", "").splitlines():
        fields = line.strip().split()
        if len(fields) < 3:
            continue
        raw_pid, package_name = fields[0], fields[-1]
        name = " ".join(fields[1:-1])
        pid = int(raw_pid) if raw_pid.isascii() and raw_pid.isdigit() else None
        if not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_]*(?:\.[a-zA-Z0-9_]+)+", package_name):
            continue
        applications.append(
            {"pid": pid, "name": name[:255], "package": package_name[:255]}
        )
        if len(applications) >= MAX_FRIDA_PROCESSES:
            break
    return applications


def _parse_frida_events(output: str) -> list[dict]:
    events: list[dict] = []
    for line in output.replace("\r", "").splitlines():
        parsed_values: list[Any] = []
        for index, character in enumerate(line):
            if character != "{":
                continue
            fragment = line[index:].strip()
            candidates = [fragment]
            final_brace = fragment.rfind("}")
            if final_brace >= 0 and final_brace + 1 < len(fragment):
                candidates.insert(0, fragment[: final_brace + 1])
            for candidate in candidates:
                try:
                    parsed_values.append(json.loads(candidate))
                    break
                except json.JSONDecodeError:
                    try:
                        parsed_values.append(ast.literal_eval(candidate))
                        break
                    except (SyntaxError, ValueError):
                        continue
            if parsed_values:
                break
        for parsed in parsed_values:
            if not isinstance(parsed, dict):
                continue
            payload = parsed.get("payload") if parsed.get("type") == "send" else parsed
            if not isinstance(payload, dict):
                continue
            encoded = json.dumps(payload, separators=(",", ":"), default=str).encode(
                "utf-8"
            )
            if len(encoded) > MAX_FRIDA_EVENT_BYTES:
                payload = {
                    "type": str(payload.get("type") or "oversized_event")[:64],
                    "success": False,
                    "error": "Frida event exceeded the size limit.",
                    "truncated": True,
                }
            else:
                payload = _bounded_event(payload)
            events.append(payload)
            if len(events) >= MAX_FRIDA_EVENTS:
                return events
    return events


def _bounded_event(value: dict) -> dict:
    bounded: dict[str, Any] = {}
    for raw_key, raw_value in list(value.items())[:32]:
        key = str(raw_key)[:64]
        if isinstance(raw_value, bool) or raw_value is None:
            bounded[key] = raw_value
        elif isinstance(raw_value, int):
            bounded[key] = raw_value
        elif isinstance(raw_value, float):
            bounded[key] = round(raw_value, 6)
        else:
            text, _redacted = _redacted_preview(str(raw_value))
            bounded[key] = text[:1000]
    return bounded


def _validated_endpoint(value: str) -> str:
    match = re.fullmatch(r"([^:\s]{1,253}):(\d{1,5})", value)
    if not match:
        raise FridaRuntimeError("Configured Frida endpoint is invalid.")
    host, raw_port = match.groups()
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", host):
            raise FridaRuntimeError("Configured Frida endpoint host is invalid.") from None
    port = _bounded_int(int(raw_port), 1, 65535, "Frida endpoint port")
    return f"{host}:{port}"


def _version_or_empty(value: Any) -> str:
    candidate = str(value or "").strip().splitlines()[0] if str(value or "").strip() else ""
    match = re.search(r"\b(\d+\.\d+(?:\.\d+)?)\b", candidate)
    return match.group(1) if match else ""


def _positive_int_or_none(value: Any) -> int | None:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _bounded_int(value: Any, minimum: int, maximum: int, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise FridaRuntimeError(f"{label} must be an integer from {minimum} to {maximum}.")
    return value


def _environment_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default
