from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import signal
import subprocess

from django.conf import settings
from django.utils import timezone


ALLOWED_DYNAMIC_LAB_SCRIPTS = frozenset(
    {
        "preflight.sh",
        "restore-instrumented-snapshot.sh",
        "refresh-frida-bridge.sh",
        "frida-smoke.sh",
        "mitmproxy-smoke.sh",
        "platform-tls-probe.sh",
        "cleanup-runtime-state.sh",
        "lab-health.sh",
    }
)
MAX_PREVIEW_CHARS = 8000
MAX_ERROR_PREVIEW_CHARS = 1200
PROCESS_TERMINATE_GRACE_SECONDS = 5
DEFAULT_DYNAMIC_STAGE_TIMEOUT_SECONDS = {
    "preflight": 420,
    "restore_instrumented_snapshot": 600,
    "refresh_frida_bridge": 420,
    "frida_smoke": 300,
    "mitmproxy_smoke": 300,
    "platform_tls_probe": 900,
    "cleanup_runtime_state": 420,
}
RESULT_MARKER_RE = re.compile(r"^([A-Z0-9_]+_RESULT)=(PASS|FAIL)$")
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(api[_-]?key|authorization|bearer|cookie|credential|password|"
    r"private[_-]?key|secret|session[_-]?id|token)\b(\s*[:=]\s*)([^\s]+)"
)
CERTIFICATE_BLOCK_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)
PRIVATE_KEY_BLOCK_RE = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    re.DOTALL,
)
URL_CREDENTIAL_RE = re.compile(r"([a-z][a-z0-9+.-]*://)([^/\s:@]+):([^/\s@]+)@")


class DynamicScriptExecutionError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        result: "DynamicScriptResult | None" = None,
        stage_name: str = "",
        script_name: str = "",
        timeout_seconds: int | None = None,
    ):
        super().__init__(message)
        self.result = result
        self.stage_name = stage_name or (result.stage_name if result else "")
        self.script_name = script_name or (result.script_name if result else "")
        self.timeout_seconds = (
            timeout_seconds if timeout_seconds is not None else (
                result.timeout_seconds if result else None
            )
        )


@dataclass(frozen=True)
class DynamicScriptResult:
    stage_name: str
    script_name: str
    return_code: int
    stdout_preview: str
    stderr_preview: str
    stdout_path: str | None
    stderr_path: str | None
    started_at: object
    finished_at: object
    duration_seconds: float
    pass_markers: list[str]
    fail_markers: list[str]
    redaction_applied: bool = False
    timed_out: bool = False
    timeout_seconds: int | None = None


def run_dynamic_lab_script(
    script_name: str,
    timeout_seconds: int | None = None,
    extra_env: dict[str, str] | None = None,
) -> DynamicScriptResult:
    if not settings.MSAP_DYNAMIC_RUNNER_ENABLED:
        raise DynamicScriptExecutionError("Dynamic MVP runner is disabled.")

    script_path = _resolve_allowed_script(script_name)
    stage_name = _stage_name_from_script(script_name)
    timeout = (
        _bounded_timeout(timeout_seconds, stage_name=stage_name)
        if timeout_seconds is not None
        else get_dynamic_stage_timeout(stage_name)
    )
    env = _build_script_env(extra_env)

    started_at = timezone.now()
    process: subprocess.Popen | None = None
    try:
        process = subprocess.Popen(
            [str(script_path)],
            cwd=str(settings.PROJECT_ROOT),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
            **_process_group_kwargs(),
        )
        try:
            stdout, stderr = process.communicate(timeout=timeout)
            return_code = process.returncode
        except subprocess.TimeoutExpired as exc:
            stdout, stderr = _output_after_timeout(process, exc)
            finished_at = timezone.now()
            result = _build_result(
                script_name=script_name,
                return_code=process.returncode if process.returncode is not None else -1,
                stdout=stdout,
                stderr=stderr,
                started_at=started_at,
                finished_at=finished_at,
                timed_out=True,
                timeout_seconds=timeout,
            )
            raise DynamicScriptExecutionError(
                _script_failure_message(
                    "Dynamic lab script timed out.",
                    result,
                    timeout_seconds=timeout,
                ),
                result=result,
                stage_name=stage_name,
                script_name=script_name,
                timeout_seconds=timeout,
            ) from exc
        stdout = _coerce_text(stdout)
        stderr = _coerce_text(stderr)
    except OSError as exc:
        finished_at = timezone.now()
        result = _build_result(
            script_name=script_name,
            return_code=-1,
            stdout="",
            stderr=str(exc),
            started_at=started_at,
            finished_at=finished_at,
            timeout_seconds=timeout,
        )
        raise DynamicScriptExecutionError(
            _script_failure_message("Dynamic lab script could not start.", result),
            result=result,
            stage_name=stage_name,
            script_name=script_name,
            timeout_seconds=timeout,
        ) from exc

    finished_at = timezone.now()
    result = _build_result(
        script_name=script_name,
        return_code=return_code,
        stdout=stdout,
        stderr=stderr,
        started_at=started_at,
        finished_at=finished_at,
        timeout_seconds=timeout,
    )
    if result.fail_markers:
        raise DynamicScriptExecutionError(
            _script_failure_message(
                "Dynamic lab script reported FAIL marker.",
                result,
            ),
            result=result,
            stage_name=stage_name,
            script_name=script_name,
            timeout_seconds=timeout,
        )
    if return_code != 0:
        raise DynamicScriptExecutionError(
            _script_failure_message(
                f"Dynamic lab script exited with {return_code}.",
                result,
            ),
            result=result,
            stage_name=stage_name,
            script_name=script_name,
            timeout_seconds=timeout,
        )
    return result


def get_dynamic_stage_timeout(stage_name_or_script_name: str) -> int:
    stage_name = _stage_name_from_script(stage_name_or_script_name)
    timeout = DEFAULT_DYNAMIC_STAGE_TIMEOUT_SECONDS.get(
        stage_name,
        DEFAULT_DYNAMIC_STAGE_TIMEOUT_SECONDS["preflight"],
    )

    global_timeout = int(getattr(settings, "MSAP_DYNAMIC_STAGE_TIMEOUT_SECONDS", 0) or 0)
    if global_timeout:
        timeout = global_timeout

    timeout_overrides = _configured_stage_timeout_overrides()
    timeout = timeout_overrides.get(stage_name, timeout)
    return _bounded_timeout(timeout, stage_name=stage_name)


def _resolve_allowed_script(script_name: str) -> Path:
    if script_name not in ALLOWED_DYNAMIC_LAB_SCRIPTS:
        raise DynamicScriptExecutionError(
            f"Dynamic lab script is not allowlisted: {script_name}"
        )

    script_dir = Path(settings.MSAP_DYNAMIC_LAB_SCRIPT_DIR).resolve()
    script_path = (script_dir / script_name).resolve()
    if script_path.parent != script_dir:
        raise DynamicScriptExecutionError("Dynamic lab script path escaped script dir.")
    if not script_path.exists():
        raise DynamicScriptExecutionError(
            f"Dynamic lab script does not exist: {script_name}"
        )
    if not script_path.is_file():
        raise DynamicScriptExecutionError(
            f"Dynamic lab script is not a file: {script_name}"
        )
    if not os.access(script_path, os.X_OK):
        raise DynamicScriptExecutionError(
            f"Dynamic lab script is not executable: {script_name}"
        )
    return script_path


def _build_result(
    *,
    script_name: str,
    return_code: int,
    stdout: str,
    stderr: str,
    started_at,
    finished_at,
    timed_out: bool = False,
    timeout_seconds: int | None = None,
) -> DynamicScriptResult:
    stdout_preview, stdout_redacted = _redacted_preview(stdout)
    stderr_preview, stderr_redacted = _redacted_preview(stderr)
    pass_markers, fail_markers = _parse_result_markers(stdout, stderr)
    duration = max(0.0, (finished_at - started_at).total_seconds())
    return DynamicScriptResult(
        stage_name=_stage_name_from_script(script_name),
        script_name=script_name,
        return_code=return_code,
        stdout_preview=stdout_preview,
        stderr_preview=stderr_preview,
        stdout_path=None,
        stderr_path=None,
        started_at=started_at,
        finished_at=finished_at,
        duration_seconds=duration,
        pass_markers=pass_markers,
        fail_markers=fail_markers,
        redaction_applied=stdout_redacted or stderr_redacted,
        timed_out=timed_out,
        timeout_seconds=timeout_seconds,
    )


def _parse_result_markers(*streams: str) -> tuple[list[str], list[str]]:
    pass_markers = []
    fail_markers = []
    for stream in streams:
        for line in stream.splitlines():
            match = RESULT_MARKER_RE.fullmatch(line.strip())
            if not match:
                continue
            marker = f"{match.group(1)}={match.group(2)}"
            if match.group(2) == "PASS":
                pass_markers.append(marker)
            else:
                fail_markers.append(marker)
    return pass_markers, fail_markers


def _redacted_preview(value: str) -> tuple[str, bool]:
    redacted = value
    redacted = PRIVATE_KEY_BLOCK_RE.sub("[REDACTED_PRIVATE_KEY]", redacted)
    redacted = CERTIFICATE_BLOCK_RE.sub("[REDACTED_CERTIFICATE]", redacted)
    redacted = URL_CREDENTIAL_RE.sub(r"\1[REDACTED]:[REDACTED]@", redacted)
    redacted = SECRET_ASSIGNMENT_RE.sub(r"\1\2[REDACTED]", redacted)
    redaction_applied = redacted != value
    truncated = _tail_preview(redacted)
    return truncated, redaction_applied


def _tail_preview(value: str) -> str:
    if len(value) <= MAX_PREVIEW_CHARS:
        return value
    return f"[truncated to last {MAX_PREVIEW_CHARS} characters]\n{value[-MAX_PREVIEW_CHARS:]}"


def _stage_name_from_script(script_name: str) -> str:
    return script_name.removesuffix(".sh").replace("-", "_")


def _configured_stage_timeout_overrides() -> dict[str, int]:
    configured = getattr(settings, "MSAP_DYNAMIC_STAGE_TIMEOUTS", None)
    if configured is None:
        raw_json = getattr(settings, "MSAP_DYNAMIC_STAGE_TIMEOUTS_JSON", "")
        if not raw_json:
            return {}
        try:
            configured = json.loads(raw_json)
        except json.JSONDecodeError as exc:
            raise DynamicScriptExecutionError(
                "MSAP_DYNAMIC_STAGE_TIMEOUTS_JSON must be a JSON object."
            ) from exc

    if not isinstance(configured, Mapping):
        raise DynamicScriptExecutionError(
            "Dynamic stage timeout overrides must be a mapping."
        )

    normalized: dict[str, int] = {}
    for key, value in configured.items():
        stage_name = _stage_name_from_script(str(key))
        normalized[stage_name] = int(value)
    return normalized


def _bounded_timeout(timeout_seconds: int, *, stage_name: str) -> int:
    try:
        timeout = int(timeout_seconds)
    except (TypeError, ValueError) as exc:
        raise DynamicScriptExecutionError(
            f"Dynamic script timeout for {stage_name} must be an integer."
        ) from exc

    minimum = int(getattr(settings, "MSAP_DYNAMIC_STAGE_TIMEOUT_MIN_SECONDS", 1))
    maximum = int(getattr(settings, "MSAP_DYNAMIC_STAGE_TIMEOUT_MAX_SECONDS", 1800))
    if timeout < minimum:
        raise DynamicScriptExecutionError(
            f"Dynamic script timeout for {stage_name} must be at least {minimum} second."
        )
    return min(timeout, maximum)


def _build_script_env(extra_env: dict[str, str] | None = None) -> dict[str, str]:
    env = os.environ.copy()
    for key, value in (extra_env or {}).items():
        env[str(key)] = str(value)

    env["MSAP_DYNAMIC_RUNNER_ENABLED"] = "true"
    env.setdefault("MSAP_ANDROID_SERIAL", settings.MSAP_DYNAMIC_MVP_DEVICE_SERIAL)
    env.setdefault("HOME", str(Path.home()))
    env["PATH"] = _prepend_path(
        env.get("PATH", ""),
        str(Path(env["HOME"]) / ".local" / "bin"),
    )
    return env


def _prepend_path(path_value: str, path_entry: str) -> str:
    entries = [entry for entry in path_value.split(os.pathsep) if entry]
    if path_entry not in entries:
        entries.insert(0, path_entry)
    return os.pathsep.join(entries)


def _process_group_kwargs() -> dict:
    if os.name == "posix":
        return {"start_new_session": True}
    if os.name == "nt":
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    return {}


def _output_after_timeout(
    process: subprocess.Popen,
    exc: subprocess.TimeoutExpired,
) -> tuple[str, str]:
    stdout = _coerce_text(exc.stdout)
    stderr = _coerce_text(exc.stderr)
    _terminate_process_group(process, force=False)
    try:
        stdout_after, stderr_after = process.communicate(
            timeout=PROCESS_TERMINATE_GRACE_SECONDS
        )
        return _coerce_text(stdout_after) or stdout, _coerce_text(stderr_after) or stderr
    except subprocess.TimeoutExpired as second_exc:
        stdout = _coerce_text(second_exc.stdout) or stdout
        stderr = _coerce_text(second_exc.stderr) or stderr
        _terminate_process_group(process, force=True)
        try:
            stdout_after, stderr_after = process.communicate(timeout=1)
            stdout = _coerce_text(stdout_after) or stdout
            stderr = _coerce_text(stderr_after) or stderr
        except subprocess.TimeoutExpired:
            pass
        return stdout, stderr


def _terminate_process_group(process: subprocess.Popen, *, force: bool) -> None:
    if process.poll() is not None:
        return
    if os.name == "posix":
        try:
            process_group_id = os.getpgid(process.pid)
        except ProcessLookupError:
            return
        os.killpg(
            process_group_id,
            signal.SIGKILL if force else signal.SIGTERM,
        )
        return
    if force:
        process.kill()
    else:
        process.terminate()


def _script_failure_message(
    prefix: str,
    result: DynamicScriptResult,
    *,
    timeout_seconds: int | None = None,
) -> str:
    timeout_fragment = (
        f" timeout={timeout_seconds}s" if timeout_seconds is not None else ""
    )
    message = (
        f"{prefix} stage={result.stage_name} script={result.script_name}"
        f"{timeout_fragment} return_code={result.return_code}"
    )
    stdout_preview = _short_error_preview(result.stdout_preview)
    stderr_preview = _short_error_preview(result.stderr_preview)
    if stdout_preview:
        message = f"{message}\nstdout_preview:\n{stdout_preview}"
    if stderr_preview:
        message = f"{message}\nstderr_preview:\n{stderr_preview}"
    return message


def _short_error_preview(value: str) -> str:
    if len(value) <= MAX_ERROR_PREVIEW_CHARS:
        return value
    return f"[truncated]\n{value[-MAX_ERROR_PREVIEW_CHARS:]}"


def _coerce_text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)
