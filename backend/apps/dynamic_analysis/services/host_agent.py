from __future__ import annotations

from hashlib import sha256
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hmac
import json
import logging
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import threading
import time
from urllib.parse import urlsplit

from django.conf import settings

from apps.dynamic_analysis.services.local_scripts import _redacted_preview


logger = logging.getLogger("msap.security")

HOST_AGENT_VERSION = "1.0"
TOKEN_HEADER = "X-MSAP-Agent-Token"
APK_SHA256_HEADER = "X-MSAP-APK-SHA256"
PACKAGE_NAME_RE = re.compile(
    r"^[a-zA-Z][a-zA-Z0-9_]*(?:\.[a-zA-Z0-9_]+)+$"
)
ACTIVITY_COMPONENT_RE = re.compile(
    r"^[a-zA-Z][a-zA-Z0-9_]*(?:\.[a-zA-Z0-9_]+)+/[a-zA-Z0-9_.$]+$"
)
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
APK_ZIP_PREFIXES = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
MAX_JSON_BODY_BYTES = 16 * 1024
MAX_COMMAND_OUTPUT_BYTES = 256 * 1024
MAX_SCREENSHOT_BYTES = 24 * 1024 * 1024
MAX_PACKAGES = 5000

class HostAgentRequestError(ValueError):
    def __init__(self, message: str, status_code: int = HTTPStatus.BAD_REQUEST):
        super().__init__(message)
        self.status_code = int(status_code)


class DynamicHostAgent:
    """Allowlisted adapter between local HTTP requests and Android lab tooling."""

    def __init__(self, *, token: str, serial: str | None = None):
        if not token:
            raise ValueError("A non-empty dynamic host-agent token is required.")
        self.token = token
        self.serial = serial or settings.MSAP_DYNAMIC_ADB_SERIAL

    def health(self) -> dict:
        adb_path = self._adb_path()
        dynamic_env_detected = bool(
            os.getenv("ADB_WIN")
            and (os.getenv("MSAP_ANDROID_SERIAL") or self.serial)
        )
        return {
            "status": "ok",
            "version": HOST_AGENT_VERSION,
            "dynamic_env_detected": dynamic_env_detected,
            "adb_path_present": bool(adb_path and Path(adb_path).is_file()),
            "serial": self.serial,
        }

    def devices(self) -> dict:
        adb_path = self._adb_path()
        if not adb_path:
            return {
                "serial": self.serial,
                "state": "unavailable",
                "adb_path_present": False,
                "root_uid": None,
                "api_level": None,
                "android_version": "",
                "abi": "",
                "selinux": "",
                "proxy": "",
                "focused_app": "",
            }

        devices_result = self._run_command([adb_path, "devices"], timeout_seconds=15)
        state = _device_state(devices_result["stdout_preview"], self.serial)
        device = {
            "serial": self.serial,
            "state": state,
            "adb_path_present": True,
            "root_uid": None,
            "api_level": None,
            "android_version": "",
            "abi": "",
            "selinux": "",
            "proxy": "",
            "focused_app": "",
        }
        if state != "device":
            return device

        root_uid = self._adb_text("shell", "id", "-u", timeout_seconds=10)
        api_level = self._adb_text(
            "shell", "getprop", "ro.build.version.sdk", timeout_seconds=10
        )
        device.update(
            {
                "root_uid": _integer_or_none(root_uid),
                "api_level": _integer_or_none(api_level),
                "android_version": self._adb_text(
                    "shell",
                    "getprop",
                    "ro.build.version.release",
                    timeout_seconds=10,
                ),
                "abi": self._adb_text(
                    "shell", "getprop", "ro.product.cpu.abi", timeout_seconds=10
                ),
                "selinux": self._adb_text(
                    "shell", "getenforce", timeout_seconds=10
                ),
                "proxy": self._adb_text(
                    "shell",
                    "settings",
                    "get",
                    "global",
                    "http_proxy",
                    timeout_seconds=10,
                ),
            }
        )
        focus_output = self._adb_text(
            "shell", "dumpsys", "window", "windows", timeout_seconds=15
        )
        device["focused_app"] = _focused_package(focus_output)
        return device

    def screenshot(self) -> bytes:
        result = self._run_adb_binary(
            "exec-out",
            "screencap",
            "-p",
            timeout_seconds=30,
        )
        if result["return_code"] != 0:
            raise HostAgentRequestError(
                "Android screenshot capture failed.",
                HTTPStatus.BAD_GATEWAY,
            )
        screenshot = result["stdout"]
        if not screenshot.startswith(b"\x89PNG\r\n\x1a\n"):
            raise HostAgentRequestError(
                "Android screenshot response was not a PNG.",
                HTTPStatus.BAD_GATEWAY,
            )
        if len(screenshot) > MAX_SCREENSHOT_BYTES:
            raise HostAgentRequestError(
                "Android screenshot exceeded the response limit.",
                HTTPStatus.BAD_GATEWAY,
            )
        return screenshot

    def list_packages(self) -> dict:
        result = self._run_adb(
            "shell", "pm", "list", "packages", timeout_seconds=30
        )
        packages = []
        for line in result["stdout_preview"].splitlines():
            package_name = line.strip().removeprefix("package:")
            if PACKAGE_NAME_RE.fullmatch(package_name):
                packages.append(package_name)
            if len(packages) >= MAX_PACKAGES:
                break
        return {
            "success": result["return_code"] == 0,
            "serial": self.serial,
            "count": len(packages),
            "packages": packages,
            "truncated": len(packages) >= MAX_PACKAGES,
            "return_code": result["return_code"],
            "duration_seconds": result["duration_seconds"],
        }

    def package_action(self, action: str, body: dict) -> dict:
        package_name = body.get("package_name")
        if not isinstance(package_name, str) or not PACKAGE_NAME_RE.fullmatch(
            package_name
        ):
            raise HostAgentRequestError("A valid Android package name is required.")
        if action == "launch-package":
            return self.launch_package(package_name)
        self._require_installed_package(package_name)
        argv = {
            "force-stop": ("shell", "am", "force-stop", package_name),
            "clear-data": ("shell", "pm", "clear", package_name),
            "uninstall": ("uninstall", package_name),
        }[action]
        result = self._run_adb(*argv, timeout_seconds=60)
        return {
            "action": action,
            "package_name": package_name,
            "success": result["return_code"] == 0,
            "status": "PASS" if result["return_code"] == 0 else "FAIL",
            **_public_command_result(result),
        }

    def launch_package(self, package_name: str) -> dict:
        self._require_installed_package(package_name)
        component = self._resolve_launchable_activity(package_name)
        if component:
            result = self._run_adb(
                "shell",
                "am",
                "start",
                "-n",
                component,
                timeout_seconds=45,
            )
            launch_method = "resolved_activity"
        else:
            result = self._run_adb(
                "shell",
                "monkey",
                "-p",
                package_name,
                "-c",
                "android.intent.category.LAUNCHER",
                "1",
                timeout_seconds=45,
            )
            launch_method = "bounded_monkey_fallback"
        success = result["return_code"] == 0
        focused_app = ""
        focused_activity = ""
        if success:
            time.sleep(1)
            focus_output = self._adb_text(
                "shell", "dumpsys", "window", "windows", timeout_seconds=15
            )
            focused_app, focused_activity = _focused_component(focus_output)
        return {
            "action": "launch-package",
            "package_name": package_name,
            "success": success,
            "status": "PASS" if success else "FAIL",
            "launch_method": launch_method,
            "launchable_activity": component,
            "focused_app": focused_app,
            "focused_activity": focused_activity,
            **_public_command_result(result),
        }

    def install_apk(self, request: BaseHTTPRequestHandler) -> dict:
        content_length = _required_content_length(request)
        max_size = int(settings.MSAP_DYNAMIC_HOST_AGENT_MAX_APK_SIZE_BYTES)
        if content_length > max_size:
            raise HostAgentRequestError(
                f"APK exceeds the host-agent limit of {max_size} bytes.",
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
            )

        expected_sha256 = request.headers.get(APK_SHA256_HEADER, "").strip().lower()
        if expected_sha256 and not SHA256_RE.fullmatch(expected_sha256):
            raise HostAgentRequestError("APK SHA-256 header is invalid.")

        temp_root = Path.home() / ".local" / "share" / "msap-dynamic" / "agent" / "tmp"
        temp_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        temporary_path: Path | None = None
        digest = sha256()
        started = time.monotonic()
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb",
                prefix="upload-",
                suffix=".apk",
                dir=temp_root,
                delete=False,
            ) as temporary_file:
                temporary_path = Path(temporary_file.name)
                remaining = content_length
                prefix = b""
                while remaining:
                    chunk = request.rfile.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise HostAgentRequestError("APK upload ended unexpectedly.")
                    if len(prefix) < 4:
                        prefix = (prefix + chunk)[:4]
                    digest.update(chunk)
                    temporary_file.write(chunk)
                    remaining -= len(chunk)

            calculated_sha256 = digest.hexdigest()
            if not prefix.startswith(APK_ZIP_PREFIXES):
                raise HostAgentRequestError("Uploaded bytes are not an APK/ZIP file.")
            if expected_sha256 and not hmac.compare_digest(
                calculated_sha256, expected_sha256
            ):
                raise HostAgentRequestError("Uploaded APK SHA-256 did not match.")

            before_packages = set(self.list_packages()["packages"])
            apk_metadata = self._read_apk_badging(temporary_path)
            install_path = self._host_command_path(temporary_path, self._adb_path())
            result = self._run_adb(
                "install",
                "-r",
                "-g",
                install_path,
                timeout_seconds=max(
                    1,
                    int(settings.MSAP_DYNAMIC_HOST_AGENT_TIMEOUT_SECONDS) - 2,
                ),
            )
            success = result["return_code"] == 0 and "Success" in (
                result["stdout_preview"] + result["stderr_preview"]
            )
            package_metadata = {
                "package_name": "",
                "version_name": "",
                "version_code": "",
                "installed_apk_path": "",
                "launchable_activity": "",
                "requested_permission_count": 0,
                "granted_permission_count": 0,
            }
            if success:
                after_packages = set(self.list_packages()["packages"])
                package_name = apk_metadata.get("package_name", "")
                new_packages = sorted(after_packages - before_packages)
                if not package_name and len(new_packages) == 1:
                    package_name = new_packages[0]
                if PACKAGE_NAME_RE.fullmatch(package_name):
                    package_metadata = self._installed_package_metadata(
                        package_name,
                        apk_metadata=apk_metadata,
                    )
            return {
                "action": "install-apk",
                "success": success,
                "install_status": "PASS" if success else "FAIL",
                "status": "PASS" if success else "FAIL",
                "sha256": calculated_sha256,
                "size_bytes": content_length,
                "duration_seconds": round(time.monotonic() - started, 3),
                "package_name": package_metadata.get("package_name", ""),
                "package_metadata": package_metadata,
                **_public_command_result(result),
            }
        finally:
            if (
                temporary_path is not None
                and temporary_path.exists()
                and not settings.MSAP_DYNAMIC_HOST_AGENT_KEEP_TEMP_APKS
            ):
                temporary_path.unlink(missing_ok=True)

    def _read_apk_badging(self, apk_path: Path) -> dict:
        build_tools_dir = os.getenv("MSAP_BUILD_TOOLS_DIR", "").strip()
        candidates = [
            os.getenv("AAPT2", "").strip(),
            str(Path(build_tools_dir) / "aapt2.exe") if build_tools_dir else "",
            shutil.which("aapt2") or "",
            shutil.which("aapt") or "",
        ]
        tool_path = next((value for value in candidates if value and Path(value).is_file()), "")
        if not tool_path:
            return {}
        result = self._run_command(
            [tool_path, "dump", "badging", self._host_command_path(apk_path, tool_path)],
            timeout_seconds=30,
        )
        if result["return_code"] != 0:
            return {}
        output = result["stdout_preview"]
        package_match = re.search(
            r"^package:\s+name='([^']+)'(?:\s+versionCode='([^']*)')?(?:\s+versionName='([^']*)')?",
            output,
            re.MULTILINE,
        )
        launch_match = re.search(
            r"^launchable-activity:\s+name='([^']+)'",
            output,
            re.MULTILINE,
        )
        package_name = package_match.group(1) if package_match else ""
        if not PACKAGE_NAME_RE.fullmatch(package_name):
            package_name = ""
        launchable_activity = launch_match.group(1) if launch_match else ""
        return {
            "package_name": package_name,
            "version_code": package_match.group(2) if package_match else "",
            "version_name": package_match.group(3) if package_match else "",
            "launchable_activity": launchable_activity,
        }

    def _installed_package_metadata(self, package_name: str, *, apk_metadata: dict) -> dict:
        dumpsys = self._adb_text(
            "shell", "dumpsys", "package", package_name, timeout_seconds=30
        )
        path_output = self._adb_text("shell", "pm", "path", package_name, timeout_seconds=15)
        installed_path = ""
        for line in path_output.splitlines():
            candidate = line.removeprefix("package:").strip()
            if candidate.startswith("/") and candidate.endswith(".apk"):
                installed_path = candidate
                break
        version_code_match = re.search(r"\bversionCode=(\d+)", dumpsys)
        version_name_match = re.search(r"\bversionName=([^\s]+)", dumpsys)
        requested_permissions = set(
            re.findall(r"\b(?:android\.)?permission\.[A-Za-z0-9_.]+", dumpsys)
        )
        granted_permissions = set(
            re.findall(
                r"\b((?:android\.)?permission\.[A-Za-z0-9_.]+): granted=true",
                dumpsys,
            )
        )
        return {
            "package_name": package_name,
            "version_name": (
                version_name_match.group(1)
                if version_name_match
                else apk_metadata.get("version_name", "")
            ),
            "version_code": (
                version_code_match.group(1)
                if version_code_match
                else apk_metadata.get("version_code", "")
            ),
            "installed_apk_path": installed_path,
            "launchable_activity": self._resolve_launchable_activity(package_name)
            or apk_metadata.get("launchable_activity", ""),
            "requested_permission_count": len(requested_permissions),
            "granted_permission_count": len(granted_permissions),
        }

    def _resolve_launchable_activity(self, package_name: str) -> str:
        output = self._adb_text(
            "shell",
            "cmd",
            "package",
            "resolve-activity",
            "--brief",
            "-a",
            "android.intent.action.MAIN",
            "-c",
            "android.intent.category.LAUNCHER",
            package_name,
            timeout_seconds=20,
        )
        for line in reversed(output.splitlines()):
            candidate = line.strip()
            if ACTIVITY_COMPONENT_RE.fullmatch(candidate):
                return candidate
        return ""

    def _host_command_path(self, path: Path, executable: str | None) -> str:
        if executable and executable.lower().endswith(".exe"):
            wslpath = shutil.which("wslpath")
            if wslpath:
                result = self._run_command(
                    [wslpath, "-w", str(path)],
                    timeout_seconds=10,
                )
                if result["return_code"] == 0 and result["stdout_preview"].strip():
                    return result["stdout_preview"].strip()
        return str(path)

    def _require_installed_package(self, package_name: str) -> None:
        result = self._run_adb(
            "shell", "pm", "path", package_name, timeout_seconds=15
        )
        installed = result["return_code"] == 0 and any(
            line.strip().startswith("package:")
            for line in result["stdout_preview"].splitlines()
        )
        if not installed:
            raise HostAgentRequestError(
                f"Target package is not installed: {package_name}",
                HTTPStatus.BAD_REQUEST,
            )

    def _adb_path(self) -> str | None:
        configured = os.getenv("ADB_WIN", "").strip()
        if configured and Path(configured).is_file():
            return configured
        return shutil.which("adb.exe") or shutil.which("adb")

    def _adb_text(self, *args: str, timeout_seconds: int) -> str:
        result = self._run_adb(*args, timeout_seconds=timeout_seconds)
        if result["return_code"] != 0:
            return ""
        return result["stdout_preview"].strip().replace("\r", "")

    def _run_adb(self, *args: str, timeout_seconds: int) -> dict:
        adb_path = self._adb_path()
        if not adb_path:
            raise HostAgentRequestError(
                "ADB is unavailable in the dynamic host environment.",
                HTTPStatus.SERVICE_UNAVAILABLE,
            )
        return self._run_command(
            [adb_path, "-s", self.serial, *args],
            timeout_seconds=timeout_seconds,
        )

    def _run_adb_binary(self, *args: str, timeout_seconds: int) -> dict:
        adb_path = self._adb_path()
        if not adb_path:
            raise HostAgentRequestError(
                "ADB is unavailable in the dynamic host environment.",
                HTTPStatus.SERVICE_UNAVAILABLE,
            )
        return _run_process(
            [adb_path, "-s", self.serial, *args],
            timeout_seconds=timeout_seconds,
            binary=True,
        )

    def _run_command(self, argv: list[str], *, timeout_seconds: int) -> dict:
        return _run_process(argv, timeout_seconds=timeout_seconds, binary=False)


class DynamicHostAgentHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address, agent: DynamicHostAgent):
        self.agent = agent
        super().__init__(server_address, DynamicHostAgentRequestHandler)


class DynamicHostAgentRequestHandler(BaseHTTPRequestHandler):
    server_version = "MSAPDynamicHostAgent"
    sys_version = ""

    def do_GET(self):  # noqa: N802
        if not self._authorized():
            return
        path = urlsplit(self.path).path
        if path == "/health":
            self._send_json(HTTPStatus.OK, self.server.agent.health())
            return
        if path == "/devices":
            self._send_json(
                HTTPStatus.OK,
                {"devices": [self.server.agent.devices()]},
            )
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"detail": "Route not found."})

    def do_POST(self):  # noqa: N802
        if not self._authorized():
            return
        path = urlsplit(self.path).path
        try:
            if path == "/actions/screenshot":
                self._require_empty_or_json_body()
                self._send_png(self.server.agent.screenshot())
                return
            if path == "/actions/list-packages":
                self._require_empty_or_json_body()
                self._send_json(HTTPStatus.OK, self.server.agent.list_packages())
                return
            if path in {
                "/actions/launch-package",
                "/actions/force-stop",
                "/actions/clear-data",
                "/actions/uninstall",
            }:
                body = self._read_json_body()
                action_name = path.removeprefix("/actions/")
                self._send_json(
                    HTTPStatus.OK,
                    self.server.agent.package_action(action_name, body),
                )
                return
            if path == "/actions/install-apk":
                self._send_json(
                    HTTPStatus.OK,
                    self.server.agent.install_apk(self),
                )
                return
            self._send_json(HTTPStatus.NOT_FOUND, {"detail": "Route not found."})
        except HostAgentRequestError as exc:
            self._send_json(exc.status_code, {"detail": str(exc)})
        except Exception:
            logger.exception("dynamic_host_agent_request_failed path=%s", path)
            self._send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"detail": "The dynamic host-agent action failed unexpectedly."},
            )

    def log_message(self, format_string, *args):
        logger.info(
            "dynamic_host_agent remote=%s message=%s",
            self.client_address[0],
            format_string % args,
        )

    def _authorized(self) -> bool:
        provided = self.headers.get(TOKEN_HEADER, "")
        if not provided or not hmac.compare_digest(provided, self.server.agent.token):
            self._send_json(
                HTTPStatus.UNAUTHORIZED,
                {"detail": "Host-agent authentication failed."},
            )
            return False
        return True

    def _read_json_body(self) -> dict:
        content_length = _content_length(self)
        if content_length <= 0:
            return {}
        if content_length > MAX_JSON_BODY_BYTES:
            raise HostAgentRequestError("JSON request body is too large.")
        raw_body = self.rfile.read(content_length)
        try:
            body = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HostAgentRequestError("Request body must be valid JSON.") from exc
        if not isinstance(body, dict):
            raise HostAgentRequestError("Request body must be a JSON object.")
        return body

    def _require_empty_or_json_body(self) -> None:
        if _content_length(self):
            self._read_json_body()

    def _send_json(self, status_code: int, payload: dict) -> None:
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(int(status_code))
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(encoded)

    def _send_png(self, payload: bytes) -> None:
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "image/png")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)


def serve_dynamic_host_agent(*, host: str, port: int, token: str) -> None:
    agent = DynamicHostAgent(token=token)
    server = DynamicHostAgentHTTPServer((host, port), agent)
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()


def _run_process(argv: list[str], *, timeout_seconds: int, binary: bool) -> dict:
    started = time.monotonic()
    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []
    try:
        process = subprocess.Popen(
            argv,
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=os.name == "posix",
        )
    except OSError as exc:
        raise HostAgentRequestError(
            "Allowlisted host command could not start.",
            HTTPStatus.SERVICE_UNAVAILABLE,
        ) from exc
    stdout_limit = (
        MAX_SCREENSHOT_BYTES + 1 if binary else MAX_COMMAND_OUTPUT_BYTES
    )
    stdout_reader = threading.Thread(
        target=_drain_stream_bounded,
        args=(process.stdout, stdout_limit, stdout_chunks),
        daemon=True,
    )
    stderr_reader = threading.Thread(
        target=_drain_stream_bounded,
        args=(process.stderr, MAX_COMMAND_OUTPUT_BYTES, stderr_chunks),
        daemon=True,
    )
    stdout_reader.start()
    stderr_reader.start()
    timed_out = False
    try:
        process.wait(timeout=max(1, int(timeout_seconds)))
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        process.wait(timeout=5)
    stdout_reader.join(timeout=5)
    stderr_reader.join(timeout=5)
    stdout = b"".join(stdout_chunks)
    stderr = b"".join(stderr_chunks)

    duration = round(time.monotonic() - started, 3)
    if binary:
        return {
            "return_code": -1 if timed_out else process.returncode,
            # Keep one byte beyond the hard limit so the caller can reject a
            # truncated/oversized PNG deterministically.
            "stdout": stdout,
            "stderr": stderr,
            "duration_seconds": duration,
            "timed_out": timed_out,
        }

    stdout_preview, stdout_redacted = _redacted_preview(
        stdout.decode("utf-8", errors="replace")
    )
    stderr_preview, stderr_redacted = _redacted_preview(
        stderr.decode("utf-8", errors="replace")
    )
    return {
        "return_code": -1 if timed_out else process.returncode,
        "stdout_preview": stdout_preview,
        "stderr_preview": stderr_preview,
        "duration_seconds": duration,
        "timed_out": timed_out,
        "redaction_applied": stdout_redacted or stderr_redacted,
    }


def _drain_stream_bounded(stream, limit: int, chunks: list[bytes]) -> None:
    """Drain a child pipe without retaining more than the configured limit."""
    retained = 0
    try:
        while True:
            chunk = stream.read(64 * 1024)
            if not chunk:
                break
            if retained < limit:
                bounded_chunk = chunk[: limit - retained]
                chunks.append(bounded_chunk)
                retained += len(bounded_chunk)
    finally:
        stream.close()


def _public_command_result(result: dict) -> dict:
    return {
        "return_code": result["return_code"],
        "stdout_preview": result["stdout_preview"],
        "stderr_preview": result["stderr_preview"],
        "duration_seconds": result["duration_seconds"],
        "timed_out": result["timed_out"],
        "redaction_applied": result["redaction_applied"],
    }


def _content_length(request: BaseHTTPRequestHandler) -> int:
    value = request.headers.get("Content-Length", "0")
    try:
        content_length = int(value)
    except (TypeError, ValueError) as exc:
        raise HostAgentRequestError("Content-Length must be an integer.") from exc
    if content_length < 0:
        raise HostAgentRequestError("Content-Length cannot be negative.")
    return content_length


def _required_content_length(request: BaseHTTPRequestHandler) -> int:
    content_length = _content_length(request)
    if content_length <= 0:
        raise HostAgentRequestError("APK request body is empty.")
    return content_length


def _device_state(output: str, serial: str) -> str:
    for line in output.replace("\r", "").splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[0] == serial:
            return fields[1]
    return "offline"


def _integer_or_none(value: str) -> int | None:
    try:
        return int(value.strip())
    except (TypeError, ValueError):
        return None


def _focused_package(output: str) -> str:
    package_name, _activity = _focused_component(output)
    return package_name


def _focused_component(output: str) -> tuple[str, str]:
    match = re.search(
        r"(?:mCurrentFocus|mFocusedApp).*?\s([a-zA-Z][a-zA-Z0-9_.]+)/",
        output,
    )
    package_name = match.group(1) if match else ""
    activity_match = re.search(
        r"(?:mCurrentFocus|mFocusedApp).*?\s([a-zA-Z][a-zA-Z0-9_.]+/[a-zA-Z0-9_.$]+)",
        output,
    )
    return package_name, activity_match.group(1) if activity_match else ""
