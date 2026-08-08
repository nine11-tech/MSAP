from __future__ import annotations

from hashlib import sha256
import http.client
import json
from pathlib import Path
import socket
import ssl
from urllib import error as urllib_error
from urllib import request as urllib_request
from urllib.parse import urljoin, urlsplit

from django.conf import settings

from apps.dynamic_analysis.services.host_agent import (
    APK_SHA256_HEADER,
    TOKEN_HEADER,
)


MAX_AGENT_JSON_BYTES = 512 * 1024


class HostAgentClientError(RuntimeError):
    def __init__(self, message: str, *, code: str, status_code: int = 502):
        super().__init__(message)
        self.code = code
        self.status_code = status_code

    def as_dict(self) -> dict:
        return {
            "connected": False,
            "code": self.code,
            "detail": str(self),
        }


class DynamicHostAgentClient:
    def __init__(
        self,
        *,
        enabled: bool | None = None,
        base_url: str | None = None,
        token: str | None = None,
        timeout_seconds: int | None = None,
    ):
        self.enabled = (
            settings.MSAP_DYNAMIC_HOST_AGENT_ENABLED
            if enabled is None
            else bool(enabled)
        )
        self.base_url = (
            settings.MSAP_DYNAMIC_HOST_AGENT_URL
            if base_url is None
            else base_url
        ).strip()
        self.token = (
            settings.MSAP_DYNAMIC_HOST_AGENT_TOKEN if token is None else token
        )
        self.timeout_seconds = max(
            1,
            int(
                settings.MSAP_DYNAMIC_HOST_AGENT_TIMEOUT_SECONDS
                if timeout_seconds is None
                else timeout_seconds
            ),
        )

    def get_status(self) -> dict:
        try:
            self._ensure_configured()
            health = self.request_json("/health")
            device_response = self.request_json("/devices")
        except HostAgentClientError as exc:
            payload = exc.as_dict()
            payload["enabled"] = self.enabled
            return payload

        devices = device_response.get("devices", [])
        device = devices[0] if devices and isinstance(devices[0], dict) else None
        return {
            "connected": True,
            "enabled": True,
            "code": "HOST_AGENT_CONNECTED",
            "detail": "Dynamic host agent is connected.",
            "agent": health,
            "device": device,
        }

    def request_json(
        self,
        path: str,
        *,
        method: str = "GET",
        body: dict | None = None,
    ) -> dict:
        self._ensure_configured()
        encoded_body = None
        headers = {
            "Accept": "application/json",
            TOKEN_HEADER: self.token,
        }
        if body is not None:
            encoded_body = json.dumps(body, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib_request.Request(
            self._url(path),
            data=encoded_body,
            method=method,
            headers=headers,
        )
        try:
            with urllib_request.urlopen(
                request,
                timeout=self.timeout_seconds,
            ) as response:
                payload = response.read(MAX_AGENT_JSON_BYTES + 1)
        except urllib_error.HTTPError as exc:
            payload = exc.read(MAX_AGENT_JSON_BYTES)
            detail = _safe_agent_error_detail(payload)
            raise HostAgentClientError(
                detail,
                code="HOST_AGENT_HTTP_ERROR",
                status_code=502,
            ) from None
        except (urllib_error.URLError, TimeoutError, socket.timeout, OSError):
            raise self._unreachable_error() from None
        return _decode_json_payload(payload)

    def request_screenshot(self) -> bytes:
        self._ensure_configured()
        request = urllib_request.Request(
            self._url("/actions/screenshot"),
            data=b"{}",
            method="POST",
            headers={
                "Accept": "image/png",
                "Content-Type": "application/json",
                TOKEN_HEADER: self.token,
            },
        )
        try:
            with urllib_request.urlopen(
                request,
                timeout=self.timeout_seconds,
            ) as response:
                payload = response.read(24 * 1024 * 1024 + 1)
        except urllib_error.HTTPError as exc:
            detail = _safe_agent_error_detail(exc.read(MAX_AGENT_JSON_BYTES))
            raise HostAgentClientError(
                detail,
                code="HOST_AGENT_SCREENSHOT_FAILED",
                status_code=502,
            ) from None
        except (urllib_error.URLError, TimeoutError, socket.timeout, OSError):
            raise self._unreachable_error() from None
        if len(payload) > 24 * 1024 * 1024:
            raise HostAgentClientError(
                "Host-agent screenshot exceeded the response limit.",
                code="HOST_AGENT_RESPONSE_TOO_LARGE",
            )
        if not payload.startswith(b"\x89PNG\r\n\x1a\n"):
            raise HostAgentClientError(
                "Host-agent returned an invalid screenshot.",
                code="HOST_AGENT_INVALID_RESPONSE",
            )
        return payload

    def install_apk(self, apk_path: str | Path, *, expected_sha256: str = "") -> dict:
        self._ensure_configured()
        path = Path(apk_path)
        try:
            size_bytes = path.stat().st_size
        except OSError as exc:
            raise HostAgentClientError(
                "APK bytes are unavailable to the backend.",
                code="APK_UNAVAILABLE",
                status_code=400,
            ) from exc
        max_size = int(settings.MSAP_DYNAMIC_HOST_AGENT_MAX_APK_SIZE_BYTES)
        if size_bytes <= 0 or size_bytes > max_size:
            raise HostAgentClientError(
                f"APK size must be between 1 and {max_size} bytes.",
                code="APK_SIZE_INVALID",
                status_code=400,
            )

        calculated_sha256 = _file_sha256(path)
        if expected_sha256 and calculated_sha256 != expected_sha256.strip().lower():
            raise HostAgentClientError(
                "APK SHA-256 does not match stored metadata.",
                code="APK_CHECKSUM_MISMATCH",
                status_code=400,
            )

        parsed, request_path = self._connection_target("/actions/install-apk")
        connection_class = (
            http.client.HTTPSConnection
            if parsed.scheme == "https"
            else http.client.HTTPConnection
        )
        connection_kwargs = {"timeout": self.timeout_seconds}
        if parsed.scheme == "https":
            connection_kwargs["context"] = ssl.create_default_context()
        connection = connection_class(
            parsed.hostname,
            parsed.port,
            **connection_kwargs,
        )
        try:
            connection.putrequest("POST", request_path)
            connection.putheader("Accept", "application/json")
            connection.putheader(
                "Content-Type", "application/vnd.android.package-archive"
            )
            connection.putheader("Content-Length", str(size_bytes))
            connection.putheader(TOKEN_HEADER, self.token)
            connection.putheader(APK_SHA256_HEADER, calculated_sha256)
            connection.endheaders()
            with path.open("rb") as apk_file:
                for chunk in iter(lambda: apk_file.read(1024 * 1024), b""):
                    connection.send(chunk)
            response = connection.getresponse()
            payload = response.read(MAX_AGENT_JSON_BYTES + 1)
            if response.status < 200 or response.status >= 300:
                raise HostAgentClientError(
                    _safe_agent_error_detail(payload),
                    code="HOST_AGENT_INSTALL_FAILED",
                    status_code=502,
                )
        except HostAgentClientError:
            raise
        except (TimeoutError, socket.timeout, OSError, http.client.HTTPException):
            raise self._unreachable_error() from None
        finally:
            connection.close()
        return _decode_json_payload(payload)

    def _ensure_configured(self) -> None:
        if not self.enabled:
            raise HostAgentClientError(
                "Start the local dynamic host agent on WSL to control the emulator.",
                code="HOST_AGENT_DISABLED",
                status_code=409,
            )
        if not self.base_url or not self.token:
            raise HostAgentClientError(
                "Dynamic host-agent URL and local token must be configured.",
                code="HOST_AGENT_NOT_CONFIGURED",
                status_code=409,
            )
        parsed = urlsplit(self.base_url)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise HostAgentClientError(
                "Dynamic host-agent URL is invalid.",
                code="HOST_AGENT_NOT_CONFIGURED",
                status_code=409,
            )

    def _url(self, path: str) -> str:
        return urljoin(f"{self.base_url.rstrip('/')}/", path.lstrip("/"))

    def _connection_target(self, path: str):
        parsed = urlsplit(self._url(path))
        request_path = parsed.path or "/"
        if parsed.query:
            request_path = f"{request_path}?{parsed.query}"
        return parsed, request_path

    @staticmethod
    def _unreachable_error() -> HostAgentClientError:
        return HostAgentClientError(
            "Backend cannot reach host-agent. Check "
            "MSAP_DYNAMIC_HOST_AGENT_URL and agent process.",
            code="HOST_AGENT_UNREACHABLE",
            status_code=503,
        )


def _decode_json_payload(payload: bytes) -> dict:
    if len(payload) > MAX_AGENT_JSON_BYTES:
        raise HostAgentClientError(
            "Host-agent JSON response exceeded the response limit.",
            code="HOST_AGENT_RESPONSE_TOO_LARGE",
        )
    try:
        decoded = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HostAgentClientError(
            "Host-agent returned an invalid JSON response.",
            code="HOST_AGENT_INVALID_RESPONSE",
        ) from exc
    if not isinstance(decoded, dict):
        raise HostAgentClientError(
            "Host-agent returned an invalid response object.",
            code="HOST_AGENT_INVALID_RESPONSE",
        )
    return decoded


def _safe_agent_error_detail(payload: bytes) -> str:
    try:
        decoded = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return "Dynamic host-agent rejected the request."
    if isinstance(decoded, dict) and isinstance(decoded.get("detail"), str):
        return decoded["detail"][:1000]
    return "Dynamic host-agent rejected the request."


def _file_sha256(path: Path) -> str:
    digest = sha256()
    try:
        with path.open("rb") as apk_file:
            for chunk in iter(lambda: apk_file.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise HostAgentClientError(
            "APK checksum could not be calculated.",
            code="APK_UNAVAILABLE",
            status_code=400,
        ) from exc
    return digest.hexdigest()
