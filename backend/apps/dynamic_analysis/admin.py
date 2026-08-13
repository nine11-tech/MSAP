from django.contrib import admin

from apps.dynamic_analysis.models import (
    AgentRun,
    AgentRunArtifact,
    AgentRuntime,
    AgentRunStep,
    AssessmentPlan,
    AssessmentPlanStep,
    DynamicAnalysisJob,
    DynamicDevice,
    DynamicDeviceCapability,
    DynamicDeviceEvent,
    DynamicDeviceLease,
    DynamicDevicePool,
    DynamicEmulatorSnapshot,
    DynamicSession,
    DynamicSessionArtifact,
    DynamicSessionEvent,
    DynamicSessionStage,
)


@admin.register(AssessmentPlan)
class AssessmentPlanAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "audit",
        "target_package",
        "planner_provider",
        "planner_model",
        "status",
        "validation_status",
        "policy_status",
        "created_at",
    )
    list_filter = (
        "planner_provider",
        "status",
        "validation_status",
        "policy_status",
    )
    search_fields = ("target_package", "objective", "audit__name")
    readonly_fields = ("planner_input_hash", "plan_hash", "provider_metadata")


@admin.register(AssessmentPlanStep)
class AssessmentPlanStepAdmin(admin.ModelAdmin):
    list_display = ("plan", "sequence", "step_identifier", "status")
    list_filter = ("status",)
    search_fields = ("step_identifier", "objective", "rationale")


@admin.register(AgentRuntime)
class AgentRuntimeAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "runtime_type",
        "status",
        "isolation_level",
        "enabled",
        "last_seen_at",
    )
    list_filter = ("runtime_type", "status", "isolation_level", "enabled")
    search_fields = ("name", "description")


@admin.register(AgentRun)
class AgentRunAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "objective",
        "status",
        "runtime",
        "device",
        "requested_by",
        "created_at",
    )
    list_filter = ("objective", "status", "failure_category")
    search_fields = ("requested_by__username", "failure_message")


@admin.register(AgentRunStep)
class AgentRunStepAdmin(admin.ModelAdmin):
    list_display = ("run", "sequence_number", "tool_name", "status")
    list_filter = ("tool_name", "status")
    search_fields = ("failure_message",)


@admin.register(AgentRunArtifact)
class AgentRunArtifactAdmin(admin.ModelAdmin):
    list_display = ("run", "step", "artifact_type", "name", "created_at")
    list_filter = ("artifact_type", "content_type")
    search_fields = ("name",)


@admin.register(DynamicDevicePool)
class DynamicDevicePoolAdmin(admin.ModelAdmin):
    list_display = ("name", "slug", "is_active", "max_concurrent_leases")
    list_filter = ("is_active",)
    search_fields = ("name", "slug")


@admin.register(DynamicDevice)
class DynamicDeviceAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "serial",
        "pool",
        "status",
        "api_level",
        "abi",
        "has_frida",
        "has_mitm_ready",
    )
    list_filter = ("status", "kind", "host_type", "pool", "abi")
    search_fields = ("name", "serial", "host_identifier", "avd_name")


@admin.register(DynamicDeviceCapability)
class DynamicDeviceCapabilityAdmin(admin.ModelAdmin):
    list_display = ("device", "capability_type", "name", "version", "is_available")
    list_filter = ("capability_type", "is_available")
    search_fields = ("device__name", "device__serial", "name", "version")


@admin.register(DynamicEmulatorSnapshot)
class DynamicEmulatorSnapshotAdmin(admin.ModelAdmin):
    list_display = (
        "device",
        "name",
        "snapshot_type",
        "validation_status",
        "api_level",
        "abi",
    )
    list_filter = ("snapshot_type", "validation_status", "api_level", "abi")
    search_fields = ("device__name", "device__serial", "name")


@admin.register(DynamicDeviceLease)
class DynamicDeviceLeaseAdmin(admin.ModelAdmin):
    list_display = ("device", "audit", "job", "lease_status", "started_at", "expires_at")
    list_filter = ("lease_status",)
    search_fields = ("device__name", "device__serial", "audit__name")
    exclude = ("lease_token",)


@admin.register(DynamicDeviceEvent)
class DynamicDeviceEventAdmin(admin.ModelAdmin):
    list_display = ("device", "lease", "event_type", "severity", "created_at")
    list_filter = ("event_type", "severity")
    search_fields = ("device__name", "device__serial", "message")


@admin.register(DynamicAnalysisJob)
class DynamicAnalysisJobAdmin(admin.ModelAdmin):
    list_display = ("id", "audit", "apk", "status", "mode", "queued_at", "finished_at")
    list_filter = ("status", "mode", "requested_tool_profile")
    search_fields = ("audit__name", "apk__package_name", "failure_message")


@admin.register(DynamicSession)
class DynamicSessionAdmin(admin.ModelAdmin):
    list_display = ("id", "job", "audit", "device", "state", "cleanup_status")
    list_filter = ("state", "cleanup_status", "quarantine_required")
    search_fields = ("audit__name", "device__name", "device__serial")


@admin.register(DynamicSessionStage)
class DynamicSessionStageAdmin(admin.ModelAdmin):
    list_display = ("session", "name", "state", "status", "attempt")
    list_filter = ("state", "status")
    search_fields = ("name", "message")


@admin.register(DynamicSessionEvent)
class DynamicSessionEventAdmin(admin.ModelAdmin):
    list_display = ("session", "sequence_number", "event_type", "severity")
    list_filter = ("event_type", "severity")
    search_fields = ("message",)


@admin.register(DynamicSessionArtifact)
class DynamicSessionArtifactAdmin(admin.ModelAdmin):
    list_display = (
        "session",
        "sequence_number",
        "artifact_type",
        "category",
        "redaction_state",
        "confidence",
    )
    list_filter = ("artifact_type", "category", "redaction_state", "confidence")
    search_fields = ("name", "summary")
