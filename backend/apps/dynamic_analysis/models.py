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


def default_agent_runtime_capabilities() -> dict:
    return {
        "objectives": [
            "DEVICE_READINESS_CHECK",
            "BASIC_APP_INTERACTION_CHECK",
            "FRIDA_RUNTIME_ACTION",
            "FRIDA_RUNTIME_UI_MODIFICATION_PROOF",
            "FRIDA_CUSTOM_SCRIPT",
        ],
        "tools": [
            "get_device_status",
            "list_packages",
            "install_verified_apk",
            "launch_package",
            "reset_root_detection_demo",
            "force_stop_package",
            "clear_package_data",
            "take_screenshot",
            "start_logcat",
            "stop_logcat",
            "get_logcat_excerpt",
            "dump_ui",
            "tap_coordinates",
            "type_text",
            "frida_status",
            "frida_ps",
            "frida_setup",
            "frida_attach",
            "frida_run_js",
        ],
    }


class AgentRuntime(models.Model):
    class RuntimeType(models.TextChoices):
        INTERNAL_CONTROLLER = "INTERNAL_CONTROLLER", "Internal controller"
        CONTAINER_SANDBOX = "CONTAINER_SANDBOX", "Container sandbox"

    class Status(models.TextChoices):
        AVAILABLE = "AVAILABLE", "Available"
        UNAVAILABLE = "UNAVAILABLE", "Unavailable"
        DEGRADED = "DEGRADED", "Degraded"
        DISABLED = "DISABLED", "Disabled"

    class IsolationLevel(models.TextChoices):
        INTERNAL_ONLY = "INTERNAL_ONLY", "Internal only"
        CONTAINER_PLANNED = "CONTAINER_PLANNED", "Container planned"
        CONTAINER_ISOLATED = "CONTAINER_ISOLATED", "Container isolated"

    name = models.CharField(max_length=255, unique=True)
    runtime_type = models.CharField(
        max_length=32,
        choices=RuntimeType.choices,
        default=RuntimeType.INTERNAL_CONTROLLER,
    )
    status = models.CharField(
        max_length=32,
        choices=Status.choices,
        default=Status.AVAILABLE,
    )
    description = models.TextField(blank=True)
    capabilities = models.JSONField(
        default=default_agent_runtime_capabilities,
        blank=True,
    )
    isolation_level = models.CharField(
        max_length=32,
        choices=IsolationLevel.choices,
        default=IsolationLevel.INTERNAL_ONLY,
    )
    endpoint_url = models.URLField(blank=True)
    enabled = models.BooleanField(default=True)
    last_seen_at = models.DateTimeField(null=True, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]
        indexes = [
            models.Index(fields=["enabled", "status", "runtime_type"]),
        ]

    def __str__(self) -> str:
        return self.name


class AgentRun(models.Model):
    class ExecutionMode(models.TextChoices):
        SEQUENTIAL_PLAN = "SEQUENTIAL_PLAN", "Sequential approved plan"
        ADAPTIVE_AGENT = "ADAPTIVE_AGENT", "Adaptive assessment agent"

    class Objective(models.TextChoices):
        DEVICE_READINESS_CHECK = (
            "DEVICE_READINESS_CHECK",
            "Device readiness check",
        )
        BASIC_APP_INTERACTION_CHECK = (
            "BASIC_APP_INTERACTION_CHECK",
            "Basic app interaction check",
        )
        FRIDA_RUNTIME_ACTION = (
            "FRIDA_RUNTIME_ACTION",
            "Frida runtime action",
        )
        FRIDA_RUNTIME_UI_MODIFICATION_PROOF = (
            "FRIDA_RUNTIME_UI_MODIFICATION_PROOF",
            "Frida runtime UI modification proof",
        )
        FRIDA_CUSTOM_SCRIPT = (
            "FRIDA_CUSTOM_SCRIPT",
            "Frida custom script",
        )
        ASSESSMENT_PLAN_EXECUTION = (
            "ASSESSMENT_PLAN_EXECUTION",
            "Approved assessment plan execution",
        )

    class Status(models.TextChoices):
        QUEUED = "QUEUED", "Queued"
        RUNNING = "RUNNING", "Running"
        PAUSED = "PAUSED", "Paused for auditor"
        SUCCEEDED = "SUCCEEDED", "Succeeded"
        FAILED = "FAILED", "Failed"
        CANCELLED = "CANCELLED", "Cancelled"
        TIMEOUT = "TIMEOUT", "Timeout"

    class FailureCategory(models.TextChoices):
        HOST_AGENT_UNAVAILABLE = (
            "HOST_AGENT_UNAVAILABLE",
            "Host agent unavailable",
        )
        RUNTIME_UNAVAILABLE = "RUNTIME_UNAVAILABLE", "Runtime unavailable"
        AI_PROVIDER_FAILURE = "AI_PROVIDER_FAILURE", "AI provider failure"
        AI_DECISION_REJECTED = "AI_DECISION_REJECTED", "AI decision rejected"
        TOOL_EXECUTION_FAILED = (
            "TOOL_EXECUTION_FAILED",
            "Tool execution failed",
        )
        TIMEOUT = "TIMEOUT", "Timeout"
        INTERNAL_ERROR = "INTERNAL_ERROR", "Internal error"

    audit = models.ForeignKey(
        "audits.Audit",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="agent_runs",
    )
    device = models.ForeignKey(
        DynamicDevice,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="agent_runs",
    )
    runtime = models.ForeignKey(
        AgentRuntime,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="runs",
    )
    assessment_plan = models.ForeignKey(
        "dynamic_analysis.AssessmentPlan",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="execution_runs",
    )
    approved_plan_hash = models.CharField(max_length=64, blank=True)
    target_package = models.CharField(max_length=255, blank=True)
    execution_contract = models.JSONField(default=dict, blank=True)
    execution_mode = models.CharField(
        max_length=32,
        choices=ExecutionMode.choices,
        default=ExecutionMode.SEQUENTIAL_PLAN,
    )
    capability_envelope = models.JSONField(default=dict, blank=True)
    capability_envelope_hash = models.CharField(max_length=64, blank=True)
    decision_provider = models.CharField(max_length=32, blank=True)
    decision_model = models.CharField(max_length=128, blank=True)
    decision_count = models.PositiveIntegerField(default=0)
    model_call_count = models.PositiveIntegerField(default=0)
    consecutive_failure_count = models.PositiveIntegerField(default=0)
    coverage_state = models.JSONField(default=dict, blank=True)
    termination_reason = models.CharField(max_length=64, blank=True)
    objective = models.CharField(max_length=64, choices=Objective.choices)
    objective_input = models.JSONField(default=dict, blank=True)
    status = models.CharField(
        max_length=32,
        choices=Status.choices,
        default=Status.QUEUED,
    )
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="requested_agent_runs",
    )
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    duration_seconds = models.FloatField(null=True, blank=True)
    result_summary = models.JSONField(default=dict, blank=True)
    failure_category = models.CharField(
        max_length=64,
        choices=FailureCategory.choices,
        blank=True,
    )
    failure_message = models.TextField(blank=True)
    tool_call_count = models.PositiveIntegerField(default=0)
    cancellation_requested_at = models.DateTimeField(null=True, blank=True)
    cancelled_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="cancelled_agent_runs",
    )
    # The plaintext credential is returned only to the controller that launches
    # the sandbox. Django persists a one-way digest and a short expiry so a
    # database read cannot recover an active run credential.
    run_token_hash = models.CharField(max_length=64, blank=True, editable=False)
    run_token_expires_at = models.DateTimeField(
        null=True,
        blank=True,
        editable=False,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["status", "created_at"]),
            models.Index(fields=["requested_by", "created_at"]),
            models.Index(fields=["audit", "created_at"]),
        ]

    def save(self, *args, **kwargs):
        if self.started_at is not None and self.finished_at is not None:
            duration = self.finished_at - self.started_at
            self.duration_seconds = max(0.0, round(duration.total_seconds(), 3))
        super().save(*args, **kwargs)

    def __str__(self) -> str:
        return f"Agent run {self.id}: {self.objective}"


class AgentRunStep(models.Model):
    class Status(models.TextChoices):
        PENDING = "PENDING", "Pending"
        RUNNING = "RUNNING", "Running"
        SUCCEEDED = "SUCCEEDED", "Succeeded"
        FAILED = "FAILED", "Failed"
        SKIPPED = "SKIPPED", "Skipped"
        TIMEOUT = "TIMEOUT", "Timeout"
        CANCELLED = "CANCELLED", "Cancelled"

    run = models.ForeignKey(
        AgentRun,
        on_delete=models.CASCADE,
        related_name="steps",
    )
    sequence_number = models.PositiveIntegerField()
    tool_name = models.CharField(max_length=128)
    plan_step_identifier = models.CharField(max_length=64, blank=True)
    plan_step_sequence = models.PositiveIntegerField(null=True, blank=True)
    tool_call_index = models.PositiveIntegerField(default=1)
    is_control_step = models.BooleanField(default=False)
    dependencies = models.JSONField(default=list, blank=True)
    evidence_requirements = models.JSONField(default=list, blank=True)
    status = models.CharField(
        max_length=32,
        choices=Status.choices,
        default=Status.PENDING,
    )
    input_summary = models.JSONField(default=dict, blank=True)
    output_summary = models.JSONField(default=dict, blank=True)
    observation = models.JSONField(default=dict, blank=True)
    retry_count = models.PositiveIntegerField(default=0)
    max_retries = models.PositiveIntegerField(default=0)
    timeout_seconds = models.PositiveIntegerField(default=0)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    duration_seconds = models.FloatField(null=True, blank=True)
    failure_message = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["run", "sequence_number"]
        indexes = [models.Index(fields=["run", "status"])]
        constraints = [
            models.UniqueConstraint(
                fields=["run", "sequence_number"],
                name="unique_agent_run_step_sequence",
            ),
            models.CheckConstraint(
                condition=Q(sequence_number__gte=1),
                name="agent_run_step_sequence_gte_1",
            ),
        ]

    def save(self, *args, **kwargs):
        if self.started_at is not None and self.finished_at is not None:
            duration = self.finished_at - self.started_at
            self.duration_seconds = max(0.0, round(duration.total_seconds(), 3))
        super().save(*args, **kwargs)

    def __str__(self) -> str:
        return f"{self.tool_name} step #{self.sequence_number} for run {self.run_id}"


class AgentRunArtifact(models.Model):
    class ArtifactType(models.TextChoices):
        SCREENSHOT = "SCREENSHOT", "Screenshot"
        TOOL_OUTPUT = "TOOL_OUTPUT", "Tool output"
        LOG = "LOG", "Log"
        JSON_RESULT = "JSON_RESULT", "JSON result"
        OTHER = "OTHER", "Other"

    run = models.ForeignKey(
        AgentRun,
        on_delete=models.CASCADE,
        related_name="artifacts",
    )
    step = models.ForeignKey(
        AgentRunStep,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="artifacts",
    )
    artifact_type = models.CharField(max_length=32, choices=ArtifactType.choices)
    name = models.CharField(max_length=255)
    content_type = models.CharField(max_length=128)
    object_reference = models.ForeignKey(
        "storage.ObjectStorageReference",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="agent_run_artifacts",
    )
    metadata = models.JSONField(default=dict, blank=True)
    size_bytes = models.PositiveBigIntegerField(null=True, blank=True)
    sha256 = models.CharField(max_length=64, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["run", "created_at", "id"]
        indexes = [
            models.Index(fields=["run", "artifact_type"]),
            models.Index(fields=["step", "artifact_type"]),
        ]

    def __str__(self) -> str:
        return f"{self.artifact_type} artifact for run {self.run_id}"


class AgentHypothesis(models.Model):
    class Family(models.TextChoices):
        SENSITIVE_LOG_EXPOSURE = "SENSITIVE_LOG_EXPOSURE", "Sensitive log exposure"
        UI_SENSITIVE_DATA_EXPOSURE = (
            "UI_SENSITIVE_DATA_EXPOSURE",
            "UI sensitive data exposure",
        )
        RUNTIME_TAMPERING_RESILIENCE = (
            "RUNTIME_TAMPERING_RESILIENCE",
            "Runtime tampering resilience",
        )
        APPLICATION_RUNTIME_STABILITY = (
            "APPLICATION_RUNTIME_STABILITY",
            "Application runtime stability",
        )
        EXPLORATORY = "EXPLORATORY", "Exploratory"

    class Status(models.TextChoices):
        UNTESTED = "UNTESTED", "Untested"
        ACTIVE = "ACTIVE", "Active"
        SUPPORTED = "SUPPORTED", "Supported"
        REJECTED = "REJECTED", "Rejected"
        INCONCLUSIVE = "INCONCLUSIVE", "Inconclusive"
        BLOCKED = "BLOCKED", "Blocked"

    run = models.ForeignKey(
        AgentRun,
        on_delete=models.CASCADE,
        related_name="hypotheses",
    )
    hypothesis_id = models.CharField(max_length=64)
    family = models.CharField(max_length=64, choices=Family.choices)
    title = models.CharField(max_length=200)
    description = models.TextField()
    evidence_requirements = models.JSONField(default=list, blank=True)
    status = models.CharField(
        max_length=32,
        choices=Status.choices,
        default=Status.UNTESTED,
    )
    confidence = models.FloatField(default=0.0)
    oracle_result = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["run", "id"]
        constraints = [
            models.UniqueConstraint(
                fields=["run", "hypothesis_id"],
                name="unique_agent_hypothesis_identifier",
            ),
            models.CheckConstraint(
                condition=Q(confidence__gte=0.0) & Q(confidence__lte=1.0),
                name="agent_hypothesis_confidence_range",
            ),
        ]


class AgentActionDecision(models.Model):
    class DecisionType(models.TextChoices):
        TOOL_ACTION = "TOOL_ACTION", "Tool action"
        COMPLETE = "COMPLETE", "Complete"
        NEEDS_AUDITOR = "NEEDS_AUDITOR", "Needs auditor"

    class CheckStatus(models.TextChoices):
        PENDING = "PENDING", "Pending"
        PASSED = "PASSED", "Passed"
        FAILED = "FAILED", "Failed"

    class ExecutionStatus(models.TextChoices):
        NOT_EXECUTED = "NOT_EXECUTED", "Not executed"
        RUNNING = "RUNNING", "Running"
        SUCCEEDED = "SUCCEEDED", "Succeeded"
        FAILED = "FAILED", "Failed"
        REJECTED = "REJECTED", "Rejected"

    run = models.ForeignKey(
        AgentRun,
        on_delete=models.CASCADE,
        related_name="action_decisions",
    )
    hypothesis = models.ForeignKey(
        AgentHypothesis,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="decisions",
    )
    run_step = models.OneToOneField(
        AgentRunStep,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="action_decision",
    )
    sequence = models.PositiveIntegerField()
    contract_version = models.CharField(max_length=64)
    decision_type = models.CharField(max_length=32, choices=DecisionType.choices)
    tool_name = models.CharField(max_length=128, blank=True)
    arguments = models.JSONField(default=dict, blank=True)
    rationale_summary = models.CharField(max_length=1000)
    expected_observation = models.CharField(max_length=1000, blank=True)
    evidence_goals = models.JSONField(default=list, blank=True)
    confidence = models.FloatField(default=0.0)
    provider = models.CharField(max_length=32)
    model = models.CharField(max_length=128)
    provider_metadata = models.JSONField(default=dict, blank=True)
    decision_input_hash = models.CharField(max_length=64)
    decision_output_hash = models.CharField(max_length=64)
    validation_status = models.CharField(
        max_length=16,
        choices=CheckStatus.choices,
        default=CheckStatus.PENDING,
    )
    policy_status = models.CharField(
        max_length=16,
        choices=CheckStatus.choices,
        default=CheckStatus.PENDING,
    )
    execution_status = models.CharField(
        max_length=16,
        choices=ExecutionStatus.choices,
        default=ExecutionStatus.NOT_EXECUTED,
    )
    observation_hash = models.CharField(max_length=64, blank=True)
    failure_code = models.CharField(max_length=64, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    validated_at = models.DateTimeField(null=True, blank=True)
    executed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["run", "sequence"]
        constraints = [
            models.UniqueConstraint(
                fields=["run", "sequence"],
                name="unique_agent_action_decision_sequence",
            ),
            models.CheckConstraint(
                condition=Q(sequence__gte=1),
                name="agent_action_decision_sequence_gte_1",
            ),
            models.CheckConstraint(
                condition=Q(confidence__gte=0.0) & Q(confidence__lte=1.0),
                name="agent_action_decision_confidence_range",
            ),
        ]


class DynamicValidationResult(models.Model):
    class ValidationStatus(models.TextChoices):
        NOT_STARTED = "NOT_STARTED", "Not started"
        SCENARIO_GENERATED = "SCENARIO_GENERATED", "Scenario generated"
        SCENARIO_VALIDATED = "SCENARIO_VALIDATED", "Scenario validated"
        APPROVED = "APPROVED", "Approved"
        RUNNING = "RUNNING", "Running"
        SUPPORTED = "SUPPORTED", "Supported"
        REJECTED = "REJECTED", "Rejected"
        CONFIRMED = "CONFIRMED", "Confirmed"
        REFUTED = "REFUTED", "Refuted"
        INCONCLUSIVE = "INCONCLUSIVE", "Inconclusive"
        NOT_ASSESSABLE = "NOT_ASSESSABLE", "Not assessable"
        FAILED = "FAILED", "Failed"
        STATIC_ONLY = "STATIC_ONLY", "Static only"

    audit = models.ForeignKey("audits.Audit", on_delete=models.CASCADE, related_name="dynamic_validation_results")
    finding = models.ForeignKey("findings.Finding", on_delete=models.CASCADE, null=True, blank=True, related_name="dynamic_validation_results")
    rule_id = models.CharField(max_length=128)
    scenario_id = models.CharField(max_length=128, blank=True)
    playbook_id = models.CharField(max_length=128)
    hypothesis = models.ForeignKey("dynamic_analysis.AgentHypothesis", on_delete=models.SET_NULL, null=True, blank=True, related_name="dynamic_validation_results")
    agent_run = models.ForeignKey("dynamic_analysis.AgentRun", on_delete=models.SET_NULL, null=True, blank=True, related_name="dynamic_validation_results")
    action_decision = models.ForeignKey("dynamic_analysis.AgentActionDecision", on_delete=models.SET_NULL, null=True, blank=True, related_name="dynamic_validation_results")
    evidence = models.ManyToManyField("evidence.Evidence", blank=True, related_name="dynamic_validation_results")
    oracle_id = models.CharField(max_length=128)
    oracle_result = models.JSONField(default=dict, blank=True)
    validation_status = models.CharField(max_length=32, choices=ValidationStatus.choices)
    confidence = models.FloatField(default=0.0)
    safe_summary = models.CharField(max_length=1000)
    limitations = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["audit", "validation_status"]), models.Index(fields=["finding", "playbook_id"])]


class FindingValidationMission(models.Model):
    """One bounded dynamic validation attempt for one static finding."""

    class Status(models.TextChoices):
        DRAFT = "DRAFT", "Draft"
        GENERATED = "GENERATED", "Generated"
        VALIDATED = "VALIDATED", "Validated"
        APPROVED = "APPROVED", "Approved"
        RUNNING = "RUNNING", "Running"
        CONFIRMED = "CONFIRMED", "Confirmed"
        NOT_REPRODUCED = "NOT_REPRODUCED", "Not reproduced"
        INCONCLUSIVE = "INCONCLUSIVE", "Inconclusive"
        BLOCKED = "BLOCKED", "Blocked"
        NOT_DYNAMICALLY_TESTABLE = (
            "NOT_DYNAMICALLY_TESTABLE",
            "Not dynamically testable",
        )
        FAILED = "FAILED", "Failed"

    audit = models.ForeignKey(
        "audits.Audit",
        on_delete=models.CASCADE,
        related_name="finding_validation_missions",
    )
    apk = models.ForeignKey(
        "apk_files.APKFile",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="finding_validation_missions",
    )
    finding = models.ForeignKey(
        "findings.Finding",
        on_delete=models.CASCADE,
        related_name="validation_missions",
    )
    assessment_plan = models.OneToOneField(
        "dynamic_analysis.AssessmentPlan",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="finding_validation_mission",
    )
    agent_run = models.OneToOneField(
        "dynamic_analysis.AgentRun",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="finding_validation_mission",
    )
    dynamic_validation_result = models.ForeignKey(
        "dynamic_analysis.DynamicValidationResult",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="missions",
    )
    evidence = models.ManyToManyField(
        "evidence.Evidence",
        blank=True,
        related_name="finding_validation_missions",
    )
    target_package = models.CharField(max_length=255)
    status = models.CharField(
        max_length=32,
        choices=Status.choices,
        default=Status.DRAFT,
    )
    scenario_contract = models.JSONField(default=dict, blank=True)
    scenario_hash = models.CharField(max_length=64, blank=True)
    mission_hash = models.CharField(max_length=64, blank=True)
    validation_family = models.CharField(max_length=64, blank=True)
    playbook_id = models.CharField(max_length=128, blank=True)
    hypothesis = models.TextField(blank=True)
    final_conclusion = models.TextField(blank=True)
    limitations = models.TextField(blank=True)
    oracle_result = models.JSONField(default=dict, blank=True)
    provider = models.CharField(max_length=32, blank=True)
    model = models.CharField(max_length=128, blank=True)
    provider_metadata = models.JSONField(default=dict, blank=True)
    allowed_capabilities = models.JSONField(default=list, blank=True)
    budgets = models.JSONField(default=dict, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="created_finding_validation_missions",
    )
    approved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="approved_finding_validation_missions",
    )
    approved_at = models.DateTimeField(null=True, blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["audit", "status"], name="dynamic_ana_audit_i_d96ca1_idx"),
            models.Index(fields=["finding", "created_at"], name="dynamic_ana_finding_33e5d7_idx"),
            models.Index(fields=["target_package", "status"], name="dynamic_ana_target__bc5c3a_idx"),
            models.Index(fields=["scenario_hash"], name="dynamic_ana_scenari_7cf5b0_idx"),
        ]

    def __str__(self) -> str:
        return f"Mission {self.id} validating finding {self.finding_id}"


class AssessmentPlan(models.Model):
    class PlanKind(models.TextChoices):
        INITIAL = "INITIAL", "Initial assessment"
        ADAPTIVE = "ADAPTIVE", "Adaptive recommendation"

    class PlannerProvider(models.TextChoices):
        DETERMINISTIC = "DETERMINISTIC", "Deterministic"
        OPENAI = "OPENAI", "OpenAI"

    class Status(models.TextChoices):
        DRAFT = "DRAFT", "Draft"
        GENERATED = "GENERATED", "Generated"
        VALIDATED = "VALIDATED", "Validated"
        APPROVED = "APPROVED", "Approved"
        REJECTED = "REJECTED", "Rejected"
        EXECUTING = "EXECUTING", "Executing"
        COMPLETED = "COMPLETED", "Completed"
        FAILED = "FAILED", "Failed"
        CANCELLED = "CANCELLED", "Cancelled"

    class ValidationStatus(models.TextChoices):
        PENDING = "PENDING", "Pending"
        PASSED = "PASSED", "Passed"
        FAILED = "FAILED", "Failed"

    class PolicyStatus(models.TextChoices):
        PENDING = "PENDING", "Pending"
        PASSED = "PASSED", "Passed"
        FAILED = "FAILED", "Failed"

    audit = models.ForeignKey(
        "audits.Audit",
        on_delete=models.CASCADE,
        related_name="assessment_plans",
    )
    source_finding = models.ForeignKey(
        "findings.Finding",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="dynamic_validation_plans",
    )
    plan_kind = models.CharField(
        max_length=16,
        choices=PlanKind.choices,
        default=PlanKind.INITIAL,
    )
    parent_plan = models.ForeignKey(
        "self",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="adaptive_plans",
    )
    source_run = models.OneToOneField(
        "dynamic_analysis.AgentRun",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="adaptive_recommendation",
    )
    adaptive_cycle = models.PositiveSmallIntegerField(default=0)
    target_package = models.CharField(max_length=255)
    planner_provider = models.CharField(
        max_length=32,
        choices=PlannerProvider.choices,
    )
    planner_model = models.CharField(max_length=128)
    objective = models.CharField(max_length=500)
    scope = models.TextField()
    status = models.CharField(
        max_length=32,
        choices=Status.choices,
        default=Status.DRAFT,
    )
    validation_status = models.CharField(
        max_length=32,
        choices=ValidationStatus.choices,
        default=ValidationStatus.PENDING,
    )
    policy_status = models.CharField(
        max_length=32,
        choices=PolicyStatus.choices,
        default=PolicyStatus.PENDING,
    )
    generated_plan = models.JSONField(default=dict, blank=True)
    normalized_plan = models.JSONField(default=dict, blank=True)
    provider_metadata = models.JSONField(default=dict, blank=True)
    validation_errors = models.JSONField(default=list, blank=True)
    planner_input_hash = models.CharField(max_length=64, blank=True)
    plan_hash = models.CharField(max_length=64, blank=True)
    scenario_contract = models.JSONField(default=dict, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="created_assessment_plans",
    )
    approved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="approved_assessment_plans",
    )
    validated_at = models.DateTimeField(null=True, blank=True)
    approved_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["audit", "status"]),
            models.Index(fields=["target_package", "status"]),
            models.Index(fields=["validation_status", "created_at"]),
            models.Index(fields=["audit", "plan_kind", "adaptive_cycle"]),
        ]
        constraints = [
            models.CheckConstraint(
                condition=Q(adaptive_cycle__lte=2),
                name="assessment_plan_adaptive_cycle_lte_2",
            ),
            models.CheckConstraint(
                condition=(
                    Q(
                        plan_kind="INITIAL",
                        adaptive_cycle=0,
                        parent_plan__isnull=True,
                        source_run__isnull=True,
                    )
                    | Q(
                        plan_kind="ADAPTIVE",
                        adaptive_cycle__gte=1,
                        parent_plan__isnull=False,
                        source_run__isnull=False,
                    )
                ),
                name="assessment_plan_adaptive_lineage_valid",
            ),
        ]

    def __str__(self) -> str:
        return f"Assessment plan {self.id} for {self.target_package}"


class AssessmentPlanStep(models.Model):
    class Status(models.TextChoices):
        PROPOSED = "PROPOSED", "Proposed"
        VALIDATED = "VALIDATED", "Validated"
        APPROVED = "APPROVED", "Approved"
        EXECUTING = "EXECUTING", "Executing"
        COMPLETED = "COMPLETED", "Completed"
        FAILED = "FAILED", "Failed"
        SKIPPED = "SKIPPED", "Skipped"
        CANCELLED = "CANCELLED", "Cancelled"

    plan = models.ForeignKey(
        AssessmentPlan,
        on_delete=models.CASCADE,
        related_name="steps",
    )
    sequence = models.PositiveIntegerField()
    step_identifier = models.CharField(max_length=64)
    objective = models.CharField(max_length=500)
    rationale = models.TextField()
    required_tools = models.JSONField(default=list)
    tool_arguments = models.JSONField(default=dict, blank=True)
    expected_observation = models.TextField()
    success_condition = models.TextField()
    evidence_requirements = models.JSONField(default=list)
    dependencies = models.JSONField(default=list)
    status = models.CharField(
        max_length=32,
        choices=Status.choices,
        default=Status.PROPOSED,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["plan", "sequence"]
        indexes = [
            models.Index(fields=["plan", "status"]),
            models.Index(fields=["plan", "sequence"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["plan", "sequence"],
                name="unique_assessment_plan_step_sequence",
            ),
            models.UniqueConstraint(
                fields=["plan", "step_identifier"],
                name="unique_assessment_plan_step_identifier",
            ),
            models.CheckConstraint(
                condition=Q(sequence__gte=1),
                name="assessment_plan_step_sequence_gte_1",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.step_identifier} for assessment plan {self.plan_id}"
