from django.utils import timezone

from apps.dynamic_analysis.models import (
    DynamicDevice,
    DynamicDeviceCapability,
    DynamicDeviceEvent,
)


class DynamicHealthPayloadError(ValueError):
    pass


SECRET_KEY_FRAGMENTS = {
    "api_key",
    "apikey",
    "auth",
    "bearer",
    "cookie",
    "credential",
    "password",
    "private_key",
    "secret",
    "session",
    "token",
}


DEVICE_UPDATE_FIELDS = {
    "api_level",
    "android_version",
    "abi",
    "avd_name",
    "is_rooted",
    "selinux_mode",
    "has_frida",
    "has_mitm_ready",
    "current_snapshot",
    "metadata",
    "last_seen_at",
}


def update_device_health(device: DynamicDevice, health_payload: dict) -> DynamicDevice:
    if not isinstance(health_payload, dict):
        raise DynamicHealthPayloadError("Health payload must be an object.")
    _reject_secret_keys(health_payload)

    capabilities = health_payload.get("capabilities", [])
    if capabilities is None:
        capabilities = []
    if not isinstance(capabilities, list):
        raise DynamicHealthPayloadError("capabilities must be a list.")

    status_value = health_payload.get("status")
    if status_value is not None and status_value not in DynamicDevice.Status.values:
        raise DynamicHealthPayloadError(f"Unknown device status: {status_value}")

    now = timezone.now()
    update_fields = {"last_health_check_at", "updated_at"}
    for field in DEVICE_UPDATE_FIELDS:
        if field in health_payload:
            setattr(device, field, health_payload[field])
            update_fields.add(field)

    if "last_seen_at" not in health_payload:
        device.last_seen_at = now
        update_fields.add("last_seen_at")
    device.last_health_check_at = now

    if status_value is not None:
        if (
            status_value == DynamicDevice.Status.QUARANTINED
            and not health_payload.get("quarantine_reason")
            and not device.quarantine_reason
        ):
            raise DynamicHealthPayloadError(
                "quarantine_reason is required when status is QUARANTINED."
            )
        device.status = status_value
        update_fields.add("status")
    if "quarantine_reason" in health_payload:
        device.quarantine_reason = health_payload["quarantine_reason"]
        update_fields.add("quarantine_reason")

    device.save(update_fields=sorted(update_fields))
    for capability_payload in capabilities:
        _upsert_capability(device, capability_payload, now)

    DynamicDeviceEvent.objects.create(
        device=device,
        event_type=DynamicDeviceEvent.EventType.HEALTH_CHECK,
        severity=_health_severity(device.status),
        message="Dynamic device health metadata updated.",
        metadata={
            "status": device.status,
            "capability_count": len(capabilities),
        },
    )
    return device


def _upsert_capability(
    device: DynamicDevice,
    capability_payload: dict,
    checked_at,
) -> None:
    if not isinstance(capability_payload, dict):
        raise DynamicHealthPayloadError("Each capability must be an object.")
    _reject_secret_keys(capability_payload)

    capability_type = capability_payload.get("capability_type")
    name = capability_payload.get("name")
    if capability_type not in DynamicDeviceCapability.CapabilityType.values:
        raise DynamicHealthPayloadError(
            f"Unknown capability_type: {capability_type}"
        )
    if not name:
        raise DynamicHealthPayloadError("Capability name is required.")
    details = capability_payload.get("details", {})
    if not isinstance(details, dict):
        raise DynamicHealthPayloadError("Capability details must be an object.")

    DynamicDeviceCapability.objects.update_or_create(
        device=device,
        capability_type=capability_type,
        name=name,
        defaults={
            "version": capability_payload.get("version", ""),
            "is_available": bool(capability_payload.get("is_available", False)),
            "details": details,
            "checked_at": capability_payload.get("checked_at") or checked_at,
        },
    )


def _health_severity(status_value: str) -> str:
    if status_value == DynamicDevice.Status.QUARANTINED:
        return DynamicDeviceEvent.Severity.CRITICAL
    if status_value in {
        DynamicDevice.Status.OFFLINE,
        DynamicDevice.Status.UNHEALTHY,
        DynamicDevice.Status.MAINTENANCE,
    }:
        return DynamicDeviceEvent.Severity.WARNING
    return DynamicDeviceEvent.Severity.INFO


def _reject_secret_keys(value, path: str = "") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized_key = str(key).lower()
            if any(fragment in normalized_key for fragment in SECRET_KEY_FRAGMENTS):
                raise DynamicHealthPayloadError(
                    f"Health payload contains sensitive key: {path}{key}"
                )
            _reject_secret_keys(child, f"{path}{key}.")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_secret_keys(child, f"{path}{index}.")
