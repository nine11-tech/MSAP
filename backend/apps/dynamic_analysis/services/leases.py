import secrets
from datetime import timedelta

from django.db import IntegrityError, transaction
from django.db.models import Count, Q
from django.utils import timezone

from apps.dynamic_analysis.models import (
    DynamicDevice,
    DynamicDeviceEvent,
    DynamicDeviceLease,
    DynamicDevicePool,
)


class DynamicLeaseError(ValueError):
    pass


UNLEASEABLE_STATUSES = {
    DynamicDevice.Status.LEASED,
    DynamicDevice.Status.PREPARING,
    DynamicDevice.Status.BUSY,
    DynamicDevice.Status.OFFLINE,
    DynamicDevice.Status.UNHEALTHY,
    DynamicDevice.Status.QUARANTINED,
    DynamicDevice.Status.MAINTENANCE,
}


def find_available_device(
    *,
    pool: DynamicDevicePool | None = None,
    api_level: int | None = None,
    abi: str | None = None,
    capabilities: list[str | dict] | None = None,
) -> DynamicDevice | None:
    if pool is not None:
        pool = DynamicDevicePool.objects.get(pk=pool.pk)
        if not pool.is_active or _pool_active_lease_count(pool) >= pool.max_concurrent_leases:
            return None

    queryset = DynamicDevice.objects.filter(status=DynamicDevice.Status.AVAILABLE)
    if pool is not None:
        queryset = queryset.filter(pool=pool)
    else:
        queryset = queryset.filter(Q(pool__isnull=True) | Q(pool__is_active=True))
    if api_level is not None:
        queryset = queryset.filter(api_level=api_level)
    if abi:
        queryset = queryset.filter(abi=abi)

    for capability in capabilities or []:
        if isinstance(capability, str):
            queryset = queryset.filter(
                capabilities__capability_type=capability,
                capabilities__is_available=True,
            )
        elif isinstance(capability, dict):
            filters = {
                "capabilities__capability_type": capability.get("capability_type"),
                "capabilities__is_available": True,
            }
            if capability.get("name"):
                filters["capabilities__name"] = capability["name"]
            if capability.get("version"):
                filters["capabilities__version"] = capability["version"]
            queryset = queryset.filter(**filters)
        else:
            raise DynamicLeaseError("Capabilities must be strings or objects.")

    return (
        queryset.exclude(leases__lease_status=DynamicDeviceLease.LeaseStatus.ACTIVE)
        .select_related("pool")
        .order_by("created_at", "id")
        .distinct()
        .first()
    )


def create_lease(
    *,
    device: DynamicDevice,
    audit,
    job=None,
    leased_by=None,
    ttl_minutes: int = 60,
) -> DynamicDeviceLease:
    if ttl_minutes < 1 or ttl_minutes > 24 * 60:
        raise DynamicLeaseError("Lease TTL must be between 1 and 1440 minutes.")
    if job is not None and job.audit_id != audit.id:
        raise DynamicLeaseError("Lease job must belong to the selected audit.")

    with transaction.atomic():
        device = DynamicDevice.objects.select_for_update().select_related("pool").get(
            pk=device.pk
        )
        _validate_device_can_be_leased(device)
        if _has_active_lease(device):
            raise DynamicLeaseError("Device already has an active lease.")
        if (
            device.pool_id is not None
            and _pool_active_lease_count(device.pool) >= device.pool.max_concurrent_leases
        ):
            raise DynamicLeaseError("Device pool has reached active lease capacity.")

        now = timezone.now()
        try:
            lease = DynamicDeviceLease.objects.create(
                device=device,
                audit=audit,
                job=job,
                leased_by=leased_by if getattr(leased_by, "is_authenticated", False) else None,
                lease_status=DynamicDeviceLease.LeaseStatus.ACTIVE,
                lease_token=secrets.token_urlsafe(32),
                started_at=now,
                expires_at=now + timedelta(minutes=ttl_minutes),
                heartbeat_at=now,
            )
        except IntegrityError as exc:
            raise DynamicLeaseError("Device already has an active lease.") from exc

        previous_status = device.status
        device.status = DynamicDevice.Status.LEASED
        device.save(update_fields=["status", "updated_at"])
        _create_device_event(
            device,
            DynamicDeviceEvent.EventType.LEASE_CREATED,
            "Device lease created.",
            lease=lease,
            created_by=leased_by,
            metadata={
                "previous_status": previous_status,
                "lease_id": lease.id,
                "job_id": job.id if job is not None else None,
            },
        )
        return lease


def release_lease(
    lease: DynamicDeviceLease,
    *,
    reason: str,
    released_by=None,
) -> DynamicDeviceLease:
    if not reason:
        raise DynamicLeaseError("Release reason is required.")

    with transaction.atomic():
        lease = (
            DynamicDeviceLease.objects.select_for_update()
            .select_related("device")
            .get(pk=lease.pk)
        )
        device = DynamicDevice.objects.select_for_update().get(pk=lease.device_id)
        if lease.lease_status == DynamicDeviceLease.LeaseStatus.RELEASED:
            return lease

        now = timezone.now()
        lease.lease_status = DynamicDeviceLease.LeaseStatus.RELEASED
        lease.released_at = now
        lease.release_reason = reason
        lease.save(
            update_fields=[
                "lease_status",
                "released_at",
                "release_reason",
                "updated_at",
            ]
        )

        previous_status = device.status
        if device.status != DynamicDevice.Status.QUARANTINED:
            if reason.upper() == "QUARANTINED":
                device.status = DynamicDevice.Status.QUARANTINED
                device.quarantine_reason = "Lease released with quarantine reason."
                event_type = DynamicDeviceEvent.EventType.QUARANTINED
            else:
                device.status = DynamicDevice.Status.AVAILABLE
                device.quarantine_reason = ""
                event_type = DynamicDeviceEvent.EventType.LEASE_RELEASED
            device.save(update_fields=["status", "quarantine_reason", "updated_at"])
        else:
            event_type = DynamicDeviceEvent.EventType.LEASE_RELEASED

        _create_device_event(
            device,
            event_type,
            "Device lease released.",
            lease=lease,
            created_by=released_by,
            metadata={
                "previous_status": previous_status,
                "release_reason": reason,
            },
        )
        return lease


def mark_lease_expired(lease: DynamicDeviceLease) -> DynamicDeviceLease:
    with transaction.atomic():
        lease = (
            DynamicDeviceLease.objects.select_for_update()
            .select_related("device")
            .get(pk=lease.pk)
        )
        device = DynamicDevice.objects.select_for_update().get(pk=lease.device_id)
        if lease.lease_status == DynamicDeviceLease.LeaseStatus.EXPIRED:
            return lease

        lease.lease_status = DynamicDeviceLease.LeaseStatus.EXPIRED
        lease.save(update_fields=["lease_status", "updated_at"])
        device.status = DynamicDevice.Status.QUARANTINED
        device.quarantine_reason = (
            "Lease expired before cleanup could prove device integrity."
        )
        device.save(update_fields=["status", "quarantine_reason", "updated_at"])
        _create_device_event(
            device,
            DynamicDeviceEvent.EventType.LEASE_EXPIRED,
            "Device lease expired; device quarantined pending operator recovery.",
            lease=lease,
            metadata={"lease_id": lease.id},
            severity=DynamicDeviceEvent.Severity.WARNING,
        )
        return lease


def heartbeat_lease(lease: DynamicDeviceLease) -> DynamicDeviceLease:
    with transaction.atomic():
        lease = DynamicDeviceLease.objects.select_for_update().get(pk=lease.pk)
        if lease.lease_status != DynamicDeviceLease.LeaseStatus.ACTIVE:
            raise DynamicLeaseError("Only active leases can receive heartbeats.")
        lease.heartbeat_at = timezone.now()
        lease.save(update_fields=["heartbeat_at", "updated_at"])
        return lease


def quarantine_device(
    device: DynamicDevice,
    *,
    reason: str,
    created_by=None,
    lease: DynamicDeviceLease | None = None,
) -> DynamicDevice:
    if not reason:
        raise DynamicLeaseError("Quarantine reason is required.")

    with transaction.atomic():
        device = DynamicDevice.objects.select_for_update().get(pk=device.pk)
        previous_status = device.status
        device.status = DynamicDevice.Status.QUARANTINED
        device.quarantine_reason = reason
        device.save(update_fields=["status", "quarantine_reason", "updated_at"])
        _create_device_event(
            device,
            DynamicDeviceEvent.EventType.QUARANTINED,
            reason,
            lease=lease,
            created_by=created_by,
            severity=DynamicDeviceEvent.Severity.WARNING,
            metadata={"previous_status": previous_status},
        )
        return device


def _validate_device_can_be_leased(device: DynamicDevice) -> None:
    if device.status in UNLEASEABLE_STATUSES:
        raise DynamicLeaseError(f"Device status {device.status} cannot be leased.")
    if device.status != DynamicDevice.Status.AVAILABLE:
        raise DynamicLeaseError("Only available devices can be leased.")
    if device.pool_id is not None and not device.pool.is_active:
        raise DynamicLeaseError("Device pool is inactive.")
    if device.quarantine_reason:
        raise DynamicLeaseError("Device has a quarantine reason and cannot be leased.")


def _has_active_lease(device: DynamicDevice) -> bool:
    return DynamicDeviceLease.objects.filter(
        device=device,
        lease_status=DynamicDeviceLease.LeaseStatus.ACTIVE,
    ).exists()


def _pool_active_lease_count(pool: DynamicDevicePool) -> int:
    return (
        DynamicDeviceLease.objects.filter(
            device__pool=pool,
            lease_status=DynamicDeviceLease.LeaseStatus.ACTIVE,
        )
        .aggregate(count=Count("id"))
        .get("count", 0)
    )


def _create_device_event(
    device: DynamicDevice,
    event_type: str,
    message: str,
    *,
    lease: DynamicDeviceLease | None = None,
    severity: str = DynamicDeviceEvent.Severity.INFO,
    metadata: dict | None = None,
    created_by=None,
) -> DynamicDeviceEvent:
    return DynamicDeviceEvent.objects.create(
        device=device,
        lease=lease,
        event_type=event_type,
        severity=severity,
        message=message,
        metadata=metadata or {},
        created_by=created_by if getattr(created_by, "is_authenticated", False) else None,
    )
