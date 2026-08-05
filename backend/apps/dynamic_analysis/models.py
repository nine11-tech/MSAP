from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models import Q
from django.utils import timezone


class DynamicDevicePool(models.Model):
    name = models.CharField(max_length=255)
    slug = models.SlugField(max_length=128, unique=True)
    description = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)
    max_concurrent_leases = models.PositiveIntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]
        indexes = [
            models.Index(fields=["is_active"]),
        ]
        constraints = [
            models.CheckConstraint(
                condition=Q(max_concurrent_leases__gte=1),
                name="dynamic_pool_max_leases_gte_1",
            ),
        ]

    def __str__(self) -> str:
        return self.name


class DynamicDevice(models.Model):
    class Kind(models.TextChoices):
        EMULATOR = "EMULATOR", "Emulator"
        PHYSICAL = "PHYSICAL", "Physical"
        REMOTE = "REMOTE", "Remote"

    class HostType(models.TextChoices):
        WINDOWS_WSL = "WINDOWS_WSL", "Windows WSL"
        LINUX = "LINUX", "Linux"
        MACOS = "MACOS", "macOS"
        CI_RUNNER = "CI_RUNNER", "CI runner"
        OTHER = "OTHER", "Other"

    class Status(models.TextChoices):
        AVAILABLE = "AVAILABLE", "Available"
        LEASED = "LEASED", "Leased"
        PREPARING = "PREPARING", "Preparing"
        BUSY = "BUSY", "Busy"
        OFFLINE = "OFFLINE", "Offline"
        UNHEALTHY = "UNHEALTHY", "Unhealthy"
        QUARANTINED = "QUARANTINED", "Quarantined"
        MAINTENANCE = "MAINTENANCE", "Maintenance"

    pool = models.ForeignKey(
        DynamicDevicePool,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="devices",
    )
    name = models.CharField(max_length=255)
    serial = models.CharField(max_length=128, unique=True)
    kind = models.CharField(max_length=32, choices=Kind.choices)
    host_type = models.CharField(max_length=32, choices=HostType.choices)
    host_identifier = models.CharField(max_length=255, blank=True)
    status = models.CharField(
        max_length=32,
        choices=Status.choices,
        default=Status.MAINTENANCE,
    )
    api_level = models.PositiveIntegerField()
    android_version = models.CharField(max_length=64, blank=True)
    abi = models.CharField(max_length=64)
    avd_name = models.CharField(max_length=128, blank=True)
    is_rooted = models.BooleanField(default=False)
    selinux_mode = models.CharField(max_length=64, blank=True)
    has_frida = models.BooleanField(default=False)
    has_mitm_ready = models.BooleanField(default=False)
    current_snapshot = models.CharField(max_length=128, blank=True)
    last_seen_at = models.DateTimeField(null=True, blank=True)
    last_health_check_at = models.DateTimeField(null=True, blank=True)
    quarantine_reason = models.TextField(blank=True)
    notes = models.TextField(blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]
        indexes = [
            models.Index(fields=["status"]),
            models.Index(fields=["abi"]),
            models.Index(fields=["api_level"]),
            models.Index(fields=["pool"]),
            models.Index(fields=["status", "abi", "api_level"]),
            models.Index(fields=["has_frida", "has_mitm_ready"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["host_identifier", "name"],
                name="unique_dynamic_device_name_per_host",
            ),
        ]

    def clean(self):
        super().clean()
        if self.status == self.Status.QUARANTINED and not self.quarantine_reason:
            raise ValidationError(
                {"quarantine_reason": "Quarantined devices require a reason."}
            )

    def __str__(self) -> str:
        return f"{self.name} ({self.serial})"


class DynamicDeviceCapability(models.Model):
    class CapabilityType(models.TextChoices):
        ADB = "ADB", "ADB"
        ROOT = "ROOT", "Root"
        FRIDA = "FRIDA", "Frida"
        MITMPROXY_ROUTE = "MITMPROXY_ROUTE", "mitmproxy route"
        RUNTIME_CA = "RUNTIME_CA", "Runtime CA"
        SNAPSHOT = "SNAPSHOT", "Snapshot"
        UI_AUTOMATION = "UI_AUTOMATION", "UI automation"
        STORAGE_ACCESS = "STORAGE_ACCESS", "Storage access"
        NETWORK_CAPTURE = "NETWORK_CAPTURE", "Network capture"

    device = models.ForeignKey(
        DynamicDevice,
        on_delete=models.CASCADE,
        related_name="capabilities",
    )
    capability_type = models.CharField(max_length=32, choices=CapabilityType.choices)
    name = models.CharField(max_length=128)
    version = models.CharField(max_length=128, blank=True)
    is_available = models.BooleanField(default=False)
    details = models.JSONField(default=dict, blank=True)
    checked_at = models.DateTimeField(default=timezone.now)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["device", "capability_type", "name"]
        indexes = [
            models.Index(fields=["capability_type", "name", "is_available"]),
            models.Index(fields=["device", "is_available"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["device", "capability_type", "name"],
                name="unique_dynamic_device_capability",
            )
        ]

    def __str__(self) -> str:
        return f"{self.device_id}:{self.capability_type}:{self.name}"


class DynamicEmulatorSnapshot(models.Model):
    class SnapshotType(models.TextChoices):
        CLEAN_BASE = "CLEAN_BASE", "Clean base"
        INSTRUMENTED_BASE = "INSTRUMENTED_BASE", "Instrumented base"
        SESSION_TEMP = "SESSION_TEMP", "Session temporary"
        MANUAL = "MANUAL", "Manual"

    class ValidationStatus(models.TextChoices):
        UNKNOWN = "UNKNOWN", "Unknown"
        VALID = "VALID", "Valid"
        INVALID = "INVALID", "Invalid"
        STALE = "STALE", "Stale"

    device = models.ForeignKey(
        DynamicDevice,
        on_delete=models.CASCADE,
        related_name="snapshots",
    )
    name = models.CharField(max_length=128)
    snapshot_type = models.CharField(max_length=32, choices=SnapshotType.choices)
    description = models.TextField(blank=True)
    api_level = models.PositiveIntegerField()
    abi = models.CharField(max_length=64)
    contains_frida_binary = models.BooleanField(default=False)
    contains_public_ca = models.BooleanField(default=False)
    contains_target_apk = models.BooleanField(default=False)
    validation_status = models.CharField(
        max_length=32,
        choices=ValidationStatus.choices,
        default=ValidationStatus.UNKNOWN,
    )
    validated_at = models.DateTimeField(null=True, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["device", "name"]
        indexes = [
            models.Index(
                fields=["snapshot_type", "validation_status", "api_level", "abi"]
            ),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["device", "name"],
                name="unique_dynamic_snapshot_per_device",
            ),
            models.CheckConstraint(
                condition=(
                    Q(snapshot_type="SESSION_TEMP")
                    | Q(contains_target_apk=False)
                ),
                name="dynamic_snapshot_target_apk_temp_only",
            ),
        ]

    def clean(self):
        super().clean()
        if (
            self.snapshot_type != self.SnapshotType.SESSION_TEMP
            and self.contains_target_apk
        ):
            raise ValidationError(
                {
                    "contains_target_apk": (
                        "Only session temporary snapshots may contain target APKs."
                    )
                }
            )

    def __str__(self) -> str:
        return f"{self.device_id}:{self.name}"


class DynamicAnalysisJob(models.Model):
    class Mode(models.TextChoices):
        DYNAMIC_ONLY = "DYNAMIC_ONLY", "Dynamic only"
        COMBINED = "COMBINED", "Combined"

    class Status(models.TextChoices):
        QUEUED = "QUEUED", "Queued"
        RUNNING = "RUNNING", "Running"
        COMPLETED = "COMPLETED", "Completed"
        FAILED = "FAILED", "Failed"
        CANCELLED = "CANCELLED", "Cancelled"

    class ToolProfile(models.TextChoices):
        ADB_ONLY = "ADB_ONLY", "ADB only"
        NETWORK_CAPTURE = "NETWORK_CAPTURE", "Network capture"
        FRIDA_BASIC = "FRIDA_BASIC", "Frida basic"
        FRIDA_EXTENDED = "FRIDA_EXTENDED", "Frida extended"
        FULL = "FULL", "Full"

    class InteractionMode(models.TextChoices):
        PASSIVE = "PASSIVE", "Passive"
        BASIC_AUTOMATION = "BASIC_AUTOMATION", "Basic automation"
        SCRIPTED_SCENARIO = "SCRIPTED_SCENARIO", "Scripted scenario"
        AUTHORIZED_LOGIN_SCENARIO = (
            "AUTHORIZED_LOGIN_SCENARIO",
            "Authorized login scenario",
        )

    class FailureCategory(models.TextChoices):
        DEVICE_UNAVAILABLE = "DEVICE_UNAVAILABLE", "Device unavailable"
        SNAPSHOT_RESTORE_FAILED = (
            "SNAPSHOT_RESTORE_FAILED",
            "Snapshot restore failed",
        )
        APK_INSTALL_FAILED = "APK_INSTALL_FAILED", "APK install failed"
        APP_LAUNCH_FAILED = "APP_LAUNCH_FAILED", "App launch failed"
        PROXY_FAILED = "PROXY_FAILED", "Proxy failed"
        TLS_INTERCEPTION_FAILED = (
            "TLS_INTERCEPTION_FAILED",
            "TLS interception failed",
        )
        FRIDA_START_FAILED = "FRIDA_START_FAILED", "Frida start failed"
        FRIDA_SCRIPT_FAILED = "FRIDA_SCRIPT_FAILED", "Frida script failed"
        UI_AUTOMATION_FAILED = "UI_AUTOMATION_FAILED", "UI automation failed"
        EVIDENCE_COLLECTION_FAILED = (
            "EVIDENCE_COLLECTION_FAILED",
            "Evidence collection failed",
        )
        RULE_EVALUATION_FAILED = (
            "RULE_EVALUATION_FAILED",
            "Rule evaluation failed",
        )
        CLEANUP_FAILED = "CLEANUP_FAILED", "Cleanup failed"
        TIMEOUT = "TIMEOUT", "Timeout"
        OPERATOR_CANCELLED = "OPERATOR_CANCELLED", "Operator cancelled"
        UNKNOWN = "UNKNOWN", "Unknown"

    audit = models.ForeignKey(
        "audits.Audit",
        on_delete=models.CASCADE,
        related_name="dynamic_jobs",
    )
    apk = models.ForeignKey(
        "apk_files.APKFile",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="dynamic_jobs",
    )
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="requested_dynamic_jobs",
    )
    mode = models.CharField(max_length=32, choices=Mode.choices, default=Mode.COMBINED)
    status = models.CharField(
        max_length=32,
        choices=Status.choices,
        default=Status.QUEUED,
    )
    priority = models.PositiveIntegerField(default=100)
    requested_tool_profile = models.CharField(
        max_length=32,
        choices=ToolProfile.choices,
        default=ToolProfile.ADB_ONLY,
    )
    requested_interaction_mode = models.CharField(
        max_length=64,
        choices=InteractionMode.choices,
        default=InteractionMode.PASSIVE,
    )
    requested_device_pool = models.ForeignKey(
        DynamicDevicePool,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="dynamic_jobs",
    )
    timeout_seconds = models.PositiveIntegerField(default=1800)
    max_retries = models.PositiveIntegerField(default=0)
    retry_count = models.PositiveIntegerField(default=0)
    queued_at = models.DateTimeField(default=timezone.now)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    summary = models.JSONField(default=dict, blank=True)
    failure_category = models.CharField(
        max_length=64,
        choices=FailureCategory.choices,
        blank=True,
    )
    failure_message = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["audit", "status"]),
            models.Index(fields=["status", "priority", "queued_at"]),
            models.Index(fields=["requested_device_pool", "status"]),
        ]

    def __str__(self) -> str:
        return f"Dynamic job {self.id} for audit {self.audit_id}"


class DynamicDeviceLease(models.Model):
    class LeaseStatus(models.TextChoices):
        REQUESTED = "REQUESTED", "Requested"
        ACTIVE = "ACTIVE", "Active"
        EXPIRED = "EXPIRED", "Expired"
        RELEASED = "RELEASED", "Released"
        FAILED = "FAILED", "Failed"
        CANCELLED = "CANCELLED", "Cancelled"

    device = models.ForeignKey(
        DynamicDevice,
        on_delete=models.PROTECT,
        related_name="leases",
    )
    audit = models.ForeignKey(
        "audits.Audit",
        on_delete=models.CASCADE,
        related_name="dynamic_device_leases",
    )
    job = models.ForeignKey(
        DynamicAnalysisJob,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="device_leases",
    )
    leased_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="dynamic_device_leases",
    )
    lease_status = models.CharField(
        max_length=32,
        choices=LeaseStatus.choices,
        default=LeaseStatus.REQUESTED,
    )
    lease_token = models.CharField(max_length=128, unique=True)
    started_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField(null=True, blank=True)
    released_at = models.DateTimeField(null=True, blank=True)
    heartbeat_at = models.DateTimeField(null=True, blank=True)
    release_reason = models.CharField(max_length=255, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["lease_status", "expires_at"]),
            models.Index(fields=["audit", "job"]),
            models.Index(fields=["device", "lease_status"]),
            models.Index(fields=["heartbeat_at"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["device"],
                condition=Q(lease_status="ACTIVE"),
                name="unique_active_dynamic_lease_per_device",
            ),
            models.CheckConstraint(
                condition=~Q(lease_status="ACTIVE") | Q(expires_at__isnull=False),
                name="dynamic_active_lease_requires_expiry",
            ),
            models.CheckConstraint(
                condition=(
                    ~Q(lease_status="RELEASED")
                    | Q(released_at__isnull=False)
                ),
                name="dynamic_released_lease_requires_time",
            ),
        ]

    def clean(self):
        super().clean()
        errors = {}
        if self.lease_status == self.LeaseStatus.ACTIVE and self.expires_at is None:
            errors["expires_at"] = "Active leases require expires_at."
        if (
            self.lease_status == self.LeaseStatus.RELEASED
            and self.released_at is None
        ):
            errors["released_at"] = "Released leases require released_at."
        if errors:
            raise ValidationError(errors)

    def __str__(self) -> str:
        return f"{self.lease_status} lease {self.id} for device {self.device_id}"


class DynamicDeviceEvent(models.Model):
    class EventType(models.TextChoices):
        HEALTH_CHECK = "HEALTH_CHECK", "Health check"
        STATUS_CHANGE = "STATUS_CHANGE", "Status change"
        LEASE_CREATED = "LEASE_CREATED", "Lease created"
        LEASE_RELEASED = "LEASE_RELEASED", "Lease released"
        LEASE_EXPIRED = "LEASE_EXPIRED", "Lease expired"
        SNAPSHOT_RESTORED = "SNAPSHOT_RESTORED", "Snapshot restored"
        QUARANTINED = "QUARANTINED", "Quarantined"
        CLEANUP = "CLEANUP", "Cleanup"
        ERROR = "ERROR", "Error"
        OPERATOR_NOTE = "OPERATOR_NOTE", "Operator note"

    class Severity(models.TextChoices):
        DEBUG = "DEBUG", "Debug"
        INFO = "INFO", "Info"
        WARNING = "WARNING", "Warning"
        ERROR = "ERROR", "Error"
        CRITICAL = "CRITICAL", "Critical"

    device = models.ForeignKey(
        DynamicDevice,
        on_delete=models.CASCADE,
        related_name="events",
    )
    lease = models.ForeignKey(
        DynamicDeviceLease,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="events",
    )
    event_type = models.CharField(max_length=32, choices=EventType.choices)
    severity = models.CharField(
        max_length=16,
        choices=Severity.choices,
        default=Severity.INFO,
    )
    message = models.TextField(blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="dynamic_device_events",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["device", "created_at"]),
            models.Index(fields=["event_type", "severity"]),
            models.Index(fields=["lease"]),
        ]

    def __str__(self) -> str:
        return f"{self.event_type} for device {self.device_id}"


class DynamicSession(models.Model):
    class State(models.TextChoices):
        QUEUED = "QUEUED", "Queued"
        WAITING_FOR_DEVICE = "WAITING_FOR_DEVICE", "Waiting for device"
        LEASING_DEVICE = "LEASING_DEVICE", "Leasing device"
        RESTORING_BASELINE = "RESTORING_BASELINE", "Restoring baseline"
        PREPARING_DEVICE = "PREPARING_DEVICE", "Preparing device"
        INSTALLING_APK = "INSTALLING_APK", "Installing APK"
        STARTING_CAPTURE = "STARTING_CAPTURE", "Starting capture"
        STARTING_INSTRUMENTATION = (
            "STARTING_INSTRUMENTATION",
            "Starting instrumentation",
        )
        LAUNCHING_APP = "LAUNCHING_APP", "Launching app"
        EXERCISING_APP = "EXERCISING_APP", "Exercising app"
        COLLECTING_EVIDENCE = "COLLECTING_EVIDENCE", "Collecting evidence"
        EVALUATING = "EVALUATING", "Evaluating"
        REPORTING = "REPORTING", "Reporting"
        CLEANING_UP = "CLEANING_UP", "Cleaning up"
        COMPLETED = "COMPLETED", "Completed"
        FAILED = "FAILED", "Failed"
        CANCELLED = "CANCELLED", "Cancelled"
        QUARANTINED = "QUARANTINED", "Quarantined"

    class CleanupStatus(models.TextChoices):
        NOT_STARTED = "NOT_STARTED", "Not started"
        IN_PROGRESS = "IN_PROGRESS", "In progress"
        SUCCEEDED = "SUCCEEDED", "Succeeded"
        FAILED = "FAILED", "Failed"
        PARTIAL = "PARTIAL", "Partial"

    job = models.ForeignKey(
        DynamicAnalysisJob,
        on_delete=models.CASCADE,
        related_name="sessions",
    )
    audit = models.ForeignKey(
        "audits.Audit",
        on_delete=models.CASCADE,
        related_name="dynamic_sessions",
    )
    apk = models.ForeignKey(
        "apk_files.APKFile",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="dynamic_sessions",
    )
    device = models.ForeignKey(
        DynamicDevice,
        on_delete=models.PROTECT,
        related_name="sessions",
    )
    lease = models.ForeignKey(
        DynamicDeviceLease,
        on_delete=models.PROTECT,
        related_name="sessions",
    )
    snapshot = models.ForeignKey(
        DynamicEmulatorSnapshot,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="sessions",
    )
    state = models.CharField(
        max_length=64,
        choices=State.choices,
        default=State.QUEUED,
    )
    state_reason = models.TextField(blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    duration_seconds = models.PositiveIntegerField(null=True, blank=True)
    tool_versions = models.JSONField(default=dict, blank=True)
    network_capture_enabled = models.BooleanField(default=False)
    frida_enabled = models.BooleanField(default=False)
    runtime_ca_enabled = models.BooleanField(default=False)
    ui_automation_enabled = models.BooleanField(default=False)
    cleanup_status = models.CharField(
        max_length=32,
        choices=CleanupStatus.choices,
        default=CleanupStatus.NOT_STARTED,
    )
    quarantine_required = models.BooleanField(default=False)
    summary = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["audit", "state"]),
            models.Index(fields=["job", "state"]),
            models.Index(fields=["device", "state"]),
            models.Index(fields=["cleanup_status"]),
        ]
        constraints = [
            models.CheckConstraint(
                condition=(
                    ~Q(state="COMPLETED")
                    | Q(cleanup_status="SUCCEEDED")
                ),
                name="dynamic_completed_requires_cleanup",
            ),
        ]

    def clean(self):
        super().clean()
        if (
            self.state == self.State.COMPLETED
            and self.cleanup_status != self.CleanupStatus.SUCCEEDED
        ):
            raise ValidationError(
                {"cleanup_status": "Completed sessions require cleanup success."}
            )

    def save(self, *args, **kwargs):
        if (
            self.started_at is not None
            and self.finished_at is not None
            and self.duration_seconds is None
        ):
            duration = self.finished_at - self.started_at
            self.duration_seconds = max(0, int(duration.total_seconds()))
        super().save(*args, **kwargs)

    def __str__(self) -> str:
        return f"Dynamic session {self.id} for job {self.job_id}"


class DynamicSessionStage(models.Model):
    class StageStatus(models.TextChoices):
        PENDING = "PENDING", "Pending"
        RUNNING = "RUNNING", "Running"
        SUCCEEDED = "SUCCEEDED", "Succeeded"
        FAILED = "FAILED", "Failed"
        SKIPPED = "SKIPPED", "Skipped"
        CANCELLED = "CANCELLED", "Cancelled"

    session = models.ForeignKey(
        DynamicSession,
        on_delete=models.CASCADE,
        related_name="stages",
    )
    name = models.CharField(max_length=128)
    state = models.CharField(max_length=64, choices=DynamicSession.State.choices)
    status = models.CharField(
        max_length=32,
        choices=StageStatus.choices,
        default=StageStatus.PENDING,
    )
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    duration_seconds = models.PositiveIntegerField(null=True, blank=True)
    attempt = models.PositiveIntegerField(default=1)
    message = models.TextField(blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["session", "created_at", "attempt"]
        indexes = [
            models.Index(fields=["session", "status"]),
            models.Index(fields=["state", "status"]),
        ]

    def save(self, *args, **kwargs):
        if (
            self.started_at is not None
            and self.finished_at is not None
            and self.duration_seconds is None
        ):
            duration = self.finished_at - self.started_at
            self.duration_seconds = max(0, int(duration.total_seconds()))
        super().save(*args, **kwargs)

    def __str__(self) -> str:
        return f"{self.name} stage for session {self.session_id}"


class DynamicSessionEvent(models.Model):
    class EventType(models.TextChoices):
        STATE_TRANSITION = "STATE_TRANSITION", "State transition"
        INVALID_TRANSITION = "INVALID_TRANSITION", "Invalid transition"
        SESSION_FAILED = "SESSION_FAILED", "Session failed"
        SESSION_CANCELLED = "SESSION_CANCELLED", "Session cancelled"
        SESSION_COMPLETED = "SESSION_COMPLETED", "Session completed"
        CLEANUP = "CLEANUP", "Cleanup"
        HEARTBEAT = "HEARTBEAT", "Heartbeat"
        ARTIFACT = "ARTIFACT", "Artifact"
        ERROR = "ERROR", "Error"
        OPERATOR_NOTE = "OPERATOR_NOTE", "Operator note"

    class Severity(models.TextChoices):
        DEBUG = "DEBUG", "Debug"
        INFO = "INFO", "Info"
        WARNING = "WARNING", "Warning"
        ERROR = "ERROR", "Error"
        CRITICAL = "CRITICAL", "Critical"

    session = models.ForeignKey(
        DynamicSession,
        on_delete=models.CASCADE,
        related_name="events",
    )
    event_type = models.CharField(max_length=64, choices=EventType.choices)
    severity = models.CharField(
        max_length=16,
        choices=Severity.choices,
        default=Severity.INFO,
    )
    message = models.TextField(blank=True)
    sequence_number = models.PositiveIntegerField()
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["session", "sequence_number"]
        indexes = [
            models.Index(fields=["session", "sequence_number"]),
            models.Index(fields=["event_type", "severity"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["session", "sequence_number"],
                name="unique_dynamic_session_event_sequence",
            )
        ]

    def __str__(self) -> str:
        return f"{self.event_type} #{self.sequence_number}"


class DynamicSessionArtifact(models.Model):
    class ArtifactType(models.TextChoices):
        DEVICE_STATE = "DEVICE_STATE", "Device state"
        DYNAMIC_SESSION = "DYNAMIC_SESSION", "Dynamic session"
        LOGCAT_EVENT = "LOGCAT_EVENT", "Logcat event"
        PROCESS_EVENT = "PROCESS_EVENT", "Process event"
        COMPONENT_EVENT = "COMPONENT_EVENT", "Component event"
        ACTIVITY_EVENT = "ACTIVITY_EVENT", "Activity event"
        SERVICE_EVENT = "SERVICE_EVENT", "Service event"
        BROADCAST_EVENT = "BROADCAST_EVENT", "Broadcast event"
        RUNTIME_API_CALL = "RUNTIME_API_CALL", "Runtime API call"
        FRIDA_EVENT = "FRIDA_EVENT", "Frida event"
        NETWORK_FLOW = "NETWORK_FLOW", "Network flow"
        DNS_EVENT = "DNS_EVENT", "DNS event"
        TLS_EVENT = "TLS_EVENT", "TLS event"
        FILE_SYSTEM_EVENT = "FILE_SYSTEM_EVENT", "File system event"
        DATABASE_EVENT = "DATABASE_EVENT", "Database event"
        SHARED_PREFERENCE_EVENT = (
            "SHARED_PREFERENCE_EVENT",
            "Shared preference event",
        )
        CLIPBOARD_EVENT = "CLIPBOARD_EVENT", "Clipboard event"
        PERMISSION_EVENT = "PERMISSION_EVENT", "Permission event"
        WEBVIEW_EVENT = "WEBVIEW_EVENT", "WebView event"
        SCREENSHOT = "SCREENSHOT", "Screenshot"
        SCREEN_RECORDING = "SCREEN_RECORDING", "Screen recording"
        CRASH_EVENT = "CRASH_EVENT", "Crash event"
        ANR_EVENT = "ANR_EVENT", "ANR event"
        BEHAVIOR_TIMELINE = "BEHAVIOR_TIMELINE", "Behavior timeline"

    class RedactionState(models.TextChoices):
        NOT_REQUIRED = "NOT_REQUIRED", "Not required"
        REDACTED = "REDACTED", "Redacted"
        PARTIAL = "PARTIAL", "Partial"
        REDACTION_FAILED = "REDACTION_FAILED", "Redaction failed"
        UNKNOWN = "UNKNOWN", "Unknown"

    class Confidence(models.TextChoices):
        LOW = "LOW", "Low"
        MEDIUM = "MEDIUM", "Medium"
        HIGH = "HIGH", "High"
        CONFIRMED = "CONFIRMED", "Confirmed"

    session = models.ForeignKey(
        DynamicSession,
        on_delete=models.CASCADE,
        related_name="artifacts",
    )
    artifact_type = models.CharField(max_length=64, choices=ArtifactType.choices)
    category = models.CharField(max_length=128)
    name = models.CharField(max_length=255)
    summary = models.TextField(blank=True)
    raw_reference = models.ForeignKey(
        "storage.ObjectStorageReference",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="dynamic_session_artifacts",
    )
    normalized = models.JSONField(default=dict, blank=True)
    redaction_state = models.CharField(
        max_length=32,
        choices=RedactionState.choices,
        default=RedactionState.UNKNOWN,
    )
    confidence = models.CharField(
        max_length=32,
        choices=Confidence.choices,
        default=Confidence.MEDIUM,
    )
    manual_validation_required = models.BooleanField(default=True)
    correlation_keys = models.JSONField(default=list, blank=True)
    sequence_number = models.PositiveIntegerField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["session", "sequence_number"]
        indexes = [
            models.Index(fields=["session", "artifact_type"]),
            models.Index(fields=["category"]),
            models.Index(fields=["redaction_state"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["session", "sequence_number"],
                name="unique_dynamic_session_artifact_sequence",
            )
        ]

    def __str__(self) -> str:
        return f"{self.artifact_type} artifact #{self.sequence_number}"
