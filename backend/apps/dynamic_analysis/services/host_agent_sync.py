from __future__ import annotations

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from apps.dynamic_analysis.models import (
    DynamicDevice,
    DynamicDeviceCapability,
    DynamicDeviceEvent,
    DynamicDeviceLease,
    DynamicDevicePool,
)
from apps.dynamic_analysis.services.host_agent_client import DynamicHostAgentClient


HOST_AGENT_POOL_SLUG = "local-dynamic-host-agent"


def fetch_and_sync_host_agent(*, requested_by=None) -> dict:
    status_payload = DynamicHostAgentClient().get_status()
    if status_payload.get("connected") and isinstance(
        status_payload.get("device"), dict
    ):
        device = sync_host_agent_device(
            status_payload,
            requested_by=requested_by,
        )
        status_payload["synced_device_id"] = device.id
        status_payload["last_sync_at"] = device.last_health_check_at
    return status_payload


@transaction.atomic
def sync_host_agent_device(
    status_payload: dict,
    *,
    requested_by=None,
) -> DynamicDevice:
    agent = status_payload.get("agent") or {}
    payload = status_payload.get("device") or {}
    serial = str(payload.get("serial") or agent.get("serial") or "").strip()
    if not serial:
        raise ValueError("Host-agent device response did not include a serial.")

    now = timezone.now()
    pool, _created = DynamicDevicePool.objects.update_or_create(
        slug=HOST_AGENT_POOL_SLUG,
        defaults={
            "name": "Local Dynamic Host Agent",
            "description": (
                "Android emulator controlled through the token-authenticated WSL "
                "dynamic host agent."
            ),
            "is_active": True,
            "max_concurrent_leases": 1,
        },
    )
    existing = DynamicDevice.objects.filter(serial=serial).first()
    api_level = _positive_int(payload.get("api_level"))
    if api_level is None:
        api_level = existing.api_level if existing is not None else 1
    abi = str(payload.get("abi") or "")
    if not abi:
        abi = existing.abi if existing is not None else "unknown"

    online = payload.get("state") == "device"
    target_status = (
        DynamicDevice.Status.AVAILABLE if online else DynamicDevice.Status.OFFLINE
    )
    if existing is not None and online and DynamicDeviceLease.objects.filter(
        device=existing,
        lease_status=DynamicDeviceLease.LeaseStatus.ACTIVE,
    ).exists():
        target_status = DynamicDevice.Status.LEASED

    root_uid = payload.get("root_uid")
    has_frida = payload.get("frida_smoke") is True
    if existing is not None and payload.get("frida_smoke") is None:
        has_frida = existing.has_frida
    has_mitm_ready = payload.get("mitmproxy_smoke") is True
    if existing is not None and payload.get("mitmproxy_smoke") is None:
        has_mitm_ready = existing.has_mitm_ready

    metadata = {
        "managed_by": "dynamic_host_agent",
        "agent_version": str(agent.get("version") or ""),
        "agent_dynamic_env_detected": bool(agent.get("dynamic_env_detected")),
        "adb_path_present": bool(payload.get("adb_path_present")),
        "adb_state": str(payload.get("state") or "unknown"),
        "proxy": str(payload.get("proxy") or ""),
        "focused_app": str(payload.get("focused_app") or ""),
        "frida_server_running": bool(payload.get("frida_server_running")),
        "frida_smoke": payload.get("frida_smoke"),
        "mitmproxy_smoke": payload.get("mitmproxy_smoke"),
    }
    device, _created = DynamicDevice.objects.update_or_create(
        serial=serial,
        defaults={
            "pool": pool,
            "name": f"Host Agent Emulator ({serial})",
            "kind": DynamicDevice.Kind.EMULATOR,
            "host_type": DynamicDevice.HostType.WINDOWS_WSL,
            "host_identifier": "local-dynamic-host-agent",
            "status": target_status,
            "api_level": api_level,
            "android_version": str(payload.get("android_version") or ""),
            "abi": abi,
            "is_rooted": root_uid == 0,
            "selinux_mode": str(payload.get("selinux") or ""),
            "has_frida": has_frida,
            "has_mitm_ready": has_mitm_ready,
            "last_seen_at": now if online else (existing.last_seen_at if existing else None),
            "last_health_check_at": now,
            "metadata": metadata,
        },
    )
    _sync_capabilities(device, payload, now)
    DynamicDeviceEvent.objects.create(
        device=device,
        event_type=DynamicDeviceEvent.EventType.HEALTH_CHECK,
        severity=(
            DynamicDeviceEvent.Severity.INFO
            if online
            else DynamicDeviceEvent.Severity.WARNING
        ),
        message="Device synchronized from the local dynamic host agent.",
        created_by=(
            requested_by
            if getattr(requested_by, "is_authenticated", False)
            else None
        ),
        metadata={
            "agent_version": metadata["agent_version"],
            "adb_state": metadata["adb_state"],
            "status": device.status,
        },
    )
    return device


def record_host_agent_action(
    action: str,
    result: dict,
    *,
    requested_by=None,
    audit_id: int | None = None,
    apk_file_id: int | None = None,
    package_name: str = "",
) -> None:
    serial = str(result.get("serial") or settings.MSAP_DYNAMIC_ADB_SERIAL)
    device = DynamicDevice.objects.filter(serial=serial).first()
    if device is None:
        return
    success = bool(result.get("success", False))
    event_type = DynamicDeviceEvent.EventType.OPERATOR_NOTE
    if action == "restore-instrumented-snapshot" and success:
        event_type = DynamicDeviceEvent.EventType.SNAPSHOT_RESTORED
    elif action == "cleanup-runtime-state":
        event_type = DynamicDeviceEvent.EventType.CLEANUP
    elif not success:
        event_type = DynamicDeviceEvent.EventType.ERROR
    DynamicDeviceEvent.objects.create(
        device=device,
        event_type=event_type,
        severity=(
            DynamicDeviceEvent.Severity.INFO
            if success
            else DynamicDeviceEvent.Severity.WARNING
        ),
        message=f"Host-agent action {action} {'passed' if success else 'failed'}.",
        created_by=(
            requested_by
            if getattr(requested_by, "is_authenticated", False)
            else None
        ),
        metadata={
            "action": action,
            "success": success,
            "status": str(result.get("status") or result.get("install_status") or ""),
            "return_code": result.get("return_code"),
            "duration_seconds": result.get("duration_seconds"),
            "audit_id": audit_id,
            "apk_file_id": apk_file_id,
            "package_name": package_name,
            "package_metadata": result.get("package_metadata") or {},
            "evidence": result.get("evidence") or {},
        },
    )


def _sync_capabilities(device: DynamicDevice, payload: dict, checked_at) -> None:
    capability_values = (
        (
            DynamicDeviceCapability.CapabilityType.ADB,
            "Android Debug Bridge",
            payload.get("state") == "device",
        ),
        (
            DynamicDeviceCapability.CapabilityType.ROOT,
            "ADB root shell",
            payload.get("root_uid") == 0,
        ),
        (
            DynamicDeviceCapability.CapabilityType.FRIDA,
            "Frida smoke",
            device.has_frida,
        ),
        (
            DynamicDeviceCapability.CapabilityType.MITMPROXY_ROUTE,
            "mitmproxy smoke",
            device.has_mitm_ready,
        ),
    )
    for capability_type, name, available in capability_values:
        DynamicDeviceCapability.objects.update_or_create(
            device=device,
            capability_type=capability_type,
            name=name,
            defaults={
                "is_available": bool(available),
                "details": {"source": "dynamic_host_agent"},
                "checked_at": checked_at,
            },
        )


def _positive_int(value) -> int | None:
    try:
        result = int(value)
    except (TypeError, ValueError):
        return None
    return result if result > 0 else None
