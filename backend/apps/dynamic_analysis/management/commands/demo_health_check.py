from __future__ import annotations

from datetime import datetime, timezone
import socket
import socket

import boto3
import redis
from botocore.config import Config
from celery import current_app
from django.conf import settings
from django.core.management.base import BaseCommand
from django.db import connection

from apps.dynamic_analysis.services.host_agent_client import (
    DynamicHostAgentClient,
    HostAgentClientError,
)


TARGET_PACKAGE = "owasp.sat.agoat"


class Command(BaseCommand):
    help = "Run safe local demo health checks for the dynamic validation lab."

    def add_arguments(self, parser):
        parser.add_argument("--target-package", default=TARGET_PACKAGE)

    def handle(self, *args, **options):
        target_package = options["target_package"]
        checked_at = datetime.now(timezone.utc).isoformat()
        self.stdout.write(f"DEMO_HEALTH_CHECKED_AT={checked_at}")
        self.stdout.write(
            f"MSAP_DYNAMIC_HOST_AGENT_URL={settings.MSAP_DYNAMIC_HOST_AGENT_URL or '(unset)'}"
        )
        self.stdout.write(
            f"MSAP_DYNAMIC_LAB_MODE={getattr(settings, 'MSAP_DYNAMIC_LAB_MODE', 'WINDOWS_HOST_AGENT')}"
        )
        self.stdout.write(f"MSAP_DYNAMIC_ADB_SERIAL={settings.MSAP_DYNAMIC_ADB_SERIAL}")

        self.stdout.write("")
        self.stdout.write("TOPOLOGY:")
        topology_failed = self._print_topology()
        self.stdout.write("")

        results = [
            ("backend", self._check_backend),
            ("postgresql", self._check_postgresql),
            ("redis", self._check_redis),
            ("celery", self._check_celery),
            ("minio", self._check_minio),
            ("host_agent", self._check_host_agent),
            ("emulator", self._check_emulator),
            ("target_app", lambda: self._check_target_app(target_package)),
            ("frida", lambda: self._check_frida(target_package)),
        ]

        failed = topology_failed
        for label, check in results:
            ok, detail = self._safe_check(check)
            failed = failed or not ok
            status = "OK" if ok else "FAIL"
            self.stdout.write(f"{label.upper()} {status} - {detail}")

        self.stdout.write("")
        self.stdout.write(f"DEMO_HEALTH_RESULT={'FAIL' if failed else 'PASS'}")
        if failed:
            raise SystemExit(1)

    def _safe_check(self, check):
        try:
            return check()
        except Exception as exc:
            return False, type(exc).__name__

    def _print_topology(self) -> bool:
        """Explain the configured backend -> Host Agent topology and suggest fixes."""
        url = settings.MSAP_DYNAMIC_HOST_AGENT_URL or "(unset)"
        mode = getattr(settings, "MSAP_DYNAMIC_LAB_MODE", "WINDOWS_HOST_AGENT")
        self.stdout.write(f"configured_url={url}")
        self.stdout.write(f"lab_mode={mode}")
        self.stdout.write("expected_topology=Docker/WSL backend -> Host Agent (ADB/Frida)")

        resolved = ""
        if url.startswith(("http://", "https://")):
            hostname = url.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
            if hostname and hostname not in {"host.docker.internal", "localhost", "127.0.0.1", "::1"}:
                try:
                    resolved = socket.gethostbyname(hostname)
                except OSError:
                    resolved = "UNRESOLVABLE"
        self.stdout.write(f"resolved_address={resolved or '(loopback or host alias)'}")

        connection_result = "SKIPPED"
        try:
            client = DynamicHostAgentClient(timeout_seconds=15)
            payload = client.get_status()
            connection_result = "CONNECTED" if payload.get("connected") else payload.get("code", "FAILED")
        except Exception as exc:
            connection_result = type(exc).__name__
        self.stdout.write(f"connection_result={connection_result}")

        if url == "(unset)":
            self.stdout.write(
                "suggested_fix=Set MSAP_DYNAMIC_HOST_AGENT_URL for the Host Agent."
            )
            return True
        if url.startswith("http://host.docker.internal:"):
            self.stdout.write(
                "suggested_fix=Docker resolves host.docker.internal to the Docker/Windows host. "
                "If the Host Agent runs in WSL, use the WSL interface IP instead, e.g. "
                "http://<WSL_IP>:8765 . On a Windows-native Host Agent keep "
                "http://host.docker.internal:8765 ."
            )
            return connection_result != "CONNECTED"
        if connection_result != "CONNECTED":
            self.stdout.write(
                "suggested_fix=Backend cannot reach the Host Agent. Verify the agent process "
                "is running (scripts/demo/start-windows-host-agent.ps1 or "
                "python manage.py run_dynamic_host_agent) and that the URL matches the "
                "Windows/WSL interface reachable from the backend container."
            )
            return True
        self.stdout.write("suggested_fix=None (Host Agent reachable).")
        return False

    def _check_backend(self):
        return True, "Django management command executed"

    def _check_postgresql(self):
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()
        return True, "database query succeeded"

    def _check_redis(self):
        client = redis.Redis.from_url(
            settings.REDIS_URL,
            socket_connect_timeout=settings.MSAP_STATUS_TIMEOUT_SECONDS,
            socket_timeout=settings.MSAP_STATUS_TIMEOUT_SECONDS,
        )
        if client.ping() is not True:
            return False, "ping returned non-OK"
        return True, "ping succeeded"

    def _check_celery(self):
        inspector = current_app.control.inspect(
            timeout=settings.MSAP_STATUS_TIMEOUT_SECONDS
        )
        replies = inspector.ping() or {}
        if not replies:
            return False, "no worker response"
        return True, f"{len(replies)} worker(s) responded"

    def _check_minio(self):
        endpoint = settings.MINIO_ENDPOINT
        if not endpoint.startswith(("http://", "https://")):
            scheme = "https" if settings.MINIO_SECURE else "http"
            endpoint = f"{scheme}://{endpoint}"
        client = boto3.client(
            "s3",
            endpoint_url=endpoint,
            aws_access_key_id=settings.MINIO_ACCESS_KEY,
            aws_secret_access_key=settings.MINIO_SECRET_KEY,
            config=Config(
                connect_timeout=settings.MSAP_STATUS_TIMEOUT_SECONDS,
                read_timeout=settings.MSAP_STATUS_TIMEOUT_SECONDS,
                retries={"max_attempts": 0},
            ),
        )
        buckets = {bucket["Name"] for bucket in client.list_buckets().get("Buckets", [])}
        required = {
            settings.MINIO_BUCKET_APK_UPLOADS,
            settings.MINIO_BUCKET_ARTIFACTS,
            settings.MINIO_BUCKET_EVIDENCE,
            settings.MINIO_BUCKET_REPORTS,
            settings.MINIO_BUCKET_EXPORTS,
        }
        missing = sorted(required - buckets)
        if missing:
            return False, f"{len(missing)} required bucket(s) missing"
        return True, "required buckets present"

    def _host_status(self):
        return DynamicHostAgentClient(timeout_seconds=20).get_status()

    def _check_host_agent(self):
        payload = self._host_status()
        if payload.get("connected") is not True:
            return False, payload.get("code") or "not connected"
        agent = payload.get("agent") if isinstance(payload, dict) else None
        detail = payload.get("detail") or "connected"
        if isinstance(agent, dict) and agent.get("host_agent_status"):
            detail = f"host_agent_status={agent.get('host_agent_status')}"
        return True, detail

    def _check_emulator(self):
        payload = self._host_status()
        device = payload.get("device") if isinstance(payload, dict) else None
        if not isinstance(device, dict):
            return False, "no device payload"
        serial = device.get("serial") or ""
        state = device.get("state") or ""
        if serial != settings.MSAP_DYNAMIC_ADB_SERIAL:
            return False, f"serial {serial or '(missing)'} != {settings.MSAP_DYNAMIC_ADB_SERIAL}"
        if state != "device":
            return False, f"device state is {state or '(missing)'}"
        return True, f"{serial} state=device"

    def _check_target_app(self, package_name):
        payload = self._host_status()
        agent = payload.get("agent") if isinstance(payload, dict) else None
        if isinstance(agent, dict) and agent.get("target_package_installed") is True:
            return True, f"{package_name} installed"
        if isinstance(agent, dict) and agent.get("target_package_installed") is False:
            return False, f"{package_name} not installed"
        try:
            probe = DynamicHostAgentClient(timeout_seconds=15).request_json(
                "/actions/list-packages",
                method="POST",
                body={"include_system": False},
            )
        except HostAgentClientError as exc:
            return False, exc.code
        packages = probe.get("packages") or []
        names = {
            item.get("package_name") if isinstance(item, dict) else item
            for item in packages
        }
        if package_name not in names:
            return False, f"{package_name} not installed"
        return True, f"{package_name} installed"

    def _check_frida(self, package_name):
        payload = self._host_status()
        agent = payload.get("agent") if isinstance(payload, dict) else None
        if isinstance(agent, dict) and agent.get("frida_client_available") is False:
            return False, "frida client unavailable"
        if isinstance(agent, dict) and agent.get("frida_server_status") == "NOT_REACHABLE":
            return False, "frida server not reachable"
        try:
            status_probe = DynamicHostAgentClient(timeout_seconds=45).request_json(
                "/actions/frida-status",
                method="POST",
                body={"package_name": package_name},
            )
        except HostAgentClientError as exc:
            return False, exc.code
        except Exception as exc:
            return False, type(exc).__name__
        client_ok = status_probe.get("frida_client_installed") is True
        server_ok = status_probe.get("frida_server_reachable") is True
        rpc = status_probe.get("frida_rpc") or "UNKNOWN"
        if client_ok and server_ok:
            return True, f"client/server reachable rpc={rpc}"
        return False, f"client={client_ok} server={server_ok} rpc={rpc}"