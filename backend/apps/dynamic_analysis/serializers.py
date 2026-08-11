import re

from rest_framework import serializers

from apps.apk_files.models import APKFile
from apps.audits.models import Audit
from apps.dynamic_analysis.models import (
    AgentRun,
    AgentRunArtifact,
    AgentRuntime,
    AgentRunStep,
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


ANDROID_PACKAGE_NAME_RE = re.compile(
    r"^[a-zA-Z][a-zA-Z0-9_]*(?:\.[a-zA-Z0-9_]+)+$"
)


class DynamicHostAgentPackageActionSerializer(serializers.Serializer):
    package_name = serializers.CharField(max_length=255)

    def validate_package_name(self, value):
        if not ANDROID_PACKAGE_NAME_RE.fullmatch(value):
            raise serializers.ValidationError("Invalid Android package name.")
        return value


class DynamicHostAgentInstallSerializer(serializers.Serializer):
    audit = serializers.IntegerField(min_value=1)
    apk_file = serializers.IntegerField(required=False, min_value=1)


class AgentRunCreateSerializer(serializers.Serializer):
    objective = serializers.ChoiceField(choices=AgentRun.Objective.choices)
    audit = serializers.PrimaryKeyRelatedField(
        queryset=Audit.objects.all(),
        required=False,
        allow_null=True,
    )

    def to_internal_value(self, data):
        if not isinstance(data, dict):
            raise serializers.ValidationError("Request body must be a JSON object.")
        unexpected = sorted(set(data) - {"objective", "audit"})
        if unexpected:
            raise serializers.ValidationError(
                {key: "This field is not permitted." for key in unexpected}
            )
        return super().to_internal_value(data)


class AgentRuntimeSerializer(serializers.ModelSerializer):
    class Meta:
        model = AgentRuntime
        fields = [
            "id",
            "name",
            "runtime_type",
            "status",
            "description",
            "capabilities",
            "isolation_level",
            "enabled",
            "last_seen_at",
            "created_at",
            "updated_at",
        ]
        read_only_fields = fields


class AgentRunSerializer(serializers.ModelSerializer):
    requested_by_username = serializers.CharField(
        source="requested_by.username",
        read_only=True,
        allow_null=True,
    )
    device_serial = serializers.CharField(
        source="device.serial",
        read_only=True,
        allow_null=True,
    )
    runtime_name = serializers.CharField(
        source="runtime.name",
        read_only=True,
        allow_null=True,
    )

    class Meta:
        model = AgentRun
        fields = [
            "id",
            "audit",
            "device",
            "device_serial",
            "runtime",
            "runtime_name",
            "objective",
            "status",
            "requested_by",
            "requested_by_username",
            "started_at",
            "finished_at",
            "duration_seconds",
            "result_summary",
            "failure_category",
            "failure_message",
            "created_at",
            "updated_at",
        ]
        read_only_fields = fields


class AgentRunStepSerializer(serializers.ModelSerializer):
    class Meta:
        model = AgentRunStep
        fields = [
            "id",
            "run",
            "sequence_number",
            "tool_name",
            "status",
            "input_summary",
            "output_summary",
            "started_at",
            "finished_at",
            "duration_seconds",
            "failure_message",
            "created_at",
        ]
        read_only_fields = fields


class AgentRunArtifactSerializer(serializers.ModelSerializer):
    class Meta:
        model = AgentRunArtifact
        fields = [
            "id",
            "run",
            "step",
            "artifact_type",
            "name",
            "content_type",
            "object_reference",
            "metadata",
            "created_at",
        ]
        read_only_fields = fields


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


class DynamicDevicePoolSerializer(serializers.ModelSerializer):
    class Meta:
        model = DynamicDevicePool
        fields = [
            "id",
            "name",
            "slug",
            "description",
            "is_active",
            "max_concurrent_leases",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]

    def validate_max_concurrent_leases(self, value):
        if value < 1:
            raise serializers.ValidationError("Must be at least 1.")
        return value


class DynamicDeviceSerializer(serializers.ModelSerializer):
    pool_name = serializers.CharField(source="pool.name", read_only=True)

    class Meta:
        model = DynamicDevice
        fields = [
            "id",
            "pool",
            "pool_name",
            "name",
            "serial",
            "kind",
            "host_type",
            "host_identifier",
            "status",
            "api_level",
            "android_version",
            "abi",
            "avd_name",
            "is_rooted",
            "selinux_mode",
            "has_frida",
            "has_mitm_ready",
            "current_snapshot",
            "last_seen_at",
            "last_health_check_at",
            "quarantine_reason",
            "notes",
            "metadata",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]

    def validate(self, attrs):
        status_value = attrs.get("status", getattr(self.instance, "status", None))
        quarantine_reason = attrs.get(
            "quarantine_reason",
            getattr(self.instance, "quarantine_reason", ""),
        )
        if status_value == DynamicDevice.Status.QUARANTINED and not quarantine_reason:
            raise serializers.ValidationError(
                {"quarantine_reason": "Quarantined devices require a reason."}
            )
        return attrs


class DynamicDeviceCapabilitySerializer(serializers.ModelSerializer):
    device_serial = serializers.CharField(source="device.serial", read_only=True)

    class Meta:
        model = DynamicDeviceCapability
        fields = [
            "id",
            "device",
            "device_serial",
            "capability_type",
            "name",
            "version",
            "is_available",
            "details",
            "checked_at",
            "created_at",
            "updated_at",
        ]
        read_only_fields = fields


class DynamicEmulatorSnapshotSerializer(serializers.ModelSerializer):
    device_serial = serializers.CharField(source="device.serial", read_only=True)

    class Meta:
        model = DynamicEmulatorSnapshot
        fields = [
            "id",
            "device",
            "device_serial",
            "name",
            "snapshot_type",
            "description",
            "api_level",
            "abi",
            "contains_frida_binary",
            "contains_public_ca",
            "contains_target_apk",
            "validation_status",
            "validated_at",
            "metadata",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]

    def validate(self, attrs):
        snapshot_type = attrs.get(
            "snapshot_type",
            getattr(self.instance, "snapshot_type", None),
        )
        contains_target_apk = attrs.get(
            "contains_target_apk",
            getattr(self.instance, "contains_target_apk", False),
        )
        if (
            snapshot_type != DynamicEmulatorSnapshot.SnapshotType.SESSION_TEMP
            and contains_target_apk
        ):
            raise serializers.ValidationError(
                {
                    "contains_target_apk": (
                        "Only session temporary snapshots may contain target APKs."
                    )
                }
            )
        return attrs


class DynamicDeviceLeaseSerializer(serializers.ModelSerializer):
    device_serial = serializers.CharField(source="device.serial", read_only=True)

    class Meta:
        model = DynamicDeviceLease
        fields = [
            "id",
            "device",
            "device_serial",
            "audit",
            "job",
            "leased_by",
            "lease_status",
            "started_at",
            "expires_at",
            "released_at",
            "heartbeat_at",
            "release_reason",
            "metadata",
            "created_at",
            "updated_at",
        ]
        read_only_fields = fields


class DynamicDeviceLeaseCreateSerializer(serializers.Serializer):
    device = serializers.PrimaryKeyRelatedField(
        queryset=DynamicDevice.objects.all(),
        required=False,
    )
    audit = serializers.PrimaryKeyRelatedField(
        queryset=Audit.objects.all(),
    )
    job = serializers.PrimaryKeyRelatedField(
        queryset=DynamicAnalysisJob.objects.all(),
        required=False,
        allow_null=True,
    )
    pool = serializers.PrimaryKeyRelatedField(
        queryset=DynamicDevicePool.objects.all(),
        required=False,
        allow_null=True,
    )
    api_level = serializers.IntegerField(required=False, min_value=1)
    abi = serializers.CharField(required=False, allow_blank=False)
    capabilities = serializers.ListField(
        child=serializers.JSONField(),
        required=False,
    )
    ttl_minutes = serializers.IntegerField(required=False, min_value=1, max_value=1440)

    def validate(self, attrs):
        job = attrs.get("job")
        audit = attrs["audit"]
        if job is not None and job.audit_id != audit.id:
            raise serializers.ValidationError(
                {"job": "Job must belong to the selected audit."}
            )
        if not any(
            key in attrs
            for key in ("device", "pool", "api_level", "abi", "capabilities")
        ):
            raise serializers.ValidationError(
                "A device or scheduling criteria are required."
            )
        return attrs


class DynamicDeviceLeaseReleaseSerializer(serializers.Serializer):
    reason = serializers.CharField(max_length=255)


class DynamicDeviceHealthUpdateSerializer(serializers.Serializer):
    status = serializers.ChoiceField(
        choices=DynamicDevice.Status.choices,
        required=False,
    )
    quarantine_reason = serializers.CharField(required=False, allow_blank=True)
    api_level = serializers.IntegerField(required=False, min_value=1)
    android_version = serializers.CharField(required=False, allow_blank=True)
    abi = serializers.CharField(required=False, allow_blank=True)
    avd_name = serializers.CharField(required=False, allow_blank=True)
    is_rooted = serializers.BooleanField(required=False)
    selinux_mode = serializers.CharField(required=False, allow_blank=True)
    has_frida = serializers.BooleanField(required=False)
    has_mitm_ready = serializers.BooleanField(required=False)
    current_snapshot = serializers.CharField(required=False, allow_blank=True)
    last_seen_at = serializers.DateTimeField(required=False)
    metadata = serializers.DictField(required=False)
    capabilities = serializers.ListField(
        child=serializers.DictField(),
        required=False,
    )


class DynamicDeviceQuarantineSerializer(serializers.Serializer):
    reason = serializers.CharField()


class DynamicAnalysisJobSerializer(serializers.ModelSerializer):
    requested_by_username = serializers.CharField(
        source="requested_by.username",
        read_only=True,
        allow_null=True,
    )

    class Meta:
        model = DynamicAnalysisJob
        fields = [
            "id",
            "audit",
            "apk",
            "requested_by",
            "requested_by_username",
            "mode",
            "status",
            "priority",
            "requested_tool_profile",
            "requested_interaction_mode",
            "requested_device_pool",
            "timeout_seconds",
            "max_retries",
            "retry_count",
            "queued_at",
            "started_at",
            "finished_at",
            "summary",
            "failure_category",
            "failure_message",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "requested_by",
            "requested_by_username",
            "status",
            "retry_count",
            "queued_at",
            "started_at",
            "finished_at",
            "summary",
            "failure_category",
            "failure_message",
            "created_at",
            "updated_at",
        ]

    def validate(self, attrs):
        audit = attrs.get("audit", getattr(self.instance, "audit", None))
        apk = attrs.get("apk", getattr(self.instance, "apk", None))
        if apk is not None and audit is not None and apk.audit_id != audit.id:
            raise serializers.ValidationError(
                {"apk": "APK file must belong to the selected audit."}
            )
        return attrs

    def create(self, validated_data):
        if validated_data.get("apk") is None:
            audit = validated_data["audit"]
            apk = (
                APKFile.objects.filter(audit=audit)
                .order_by("-created_at", "-id")
                .first()
            )
            if apk is None:
                raise serializers.ValidationError(
                    {"apk": "Audit must have an APK file for dynamic analysis."}
                )
            validated_data["apk"] = apk

        request = self.context.get("request")
        if request is not None and getattr(request.user, "is_authenticated", False):
            validated_data["requested_by"] = request.user
        return super().create(validated_data)


class DynamicSessionSerializer(serializers.ModelSerializer):
    device_serial = serializers.CharField(source="device.serial", read_only=True)

    class Meta:
        model = DynamicSession
        fields = [
            "id",
            "job",
            "audit",
            "apk",
            "device",
            "device_serial",
            "lease",
            "snapshot",
            "state",
            "state_reason",
            "started_at",
            "finished_at",
            "duration_seconds",
            "tool_versions",
            "network_capture_enabled",
            "frida_enabled",
            "runtime_ca_enabled",
            "ui_automation_enabled",
            "cleanup_status",
            "quarantine_required",
            "summary",
            "created_at",
            "updated_at",
        ]
        read_only_fields = fields


class DynamicSessionTransitionSerializer(serializers.Serializer):
    new_state = serializers.ChoiceField(choices=DynamicSession.State.choices)
    reason = serializers.CharField(required=False, allow_blank=True)


class DynamicSessionStageSerializer(serializers.ModelSerializer):
    class Meta:
        model = DynamicSessionStage
        fields = [
            "id",
            "session",
            "name",
            "state",
            "status",
            "started_at",
            "finished_at",
            "duration_seconds",
            "attempt",
            "message",
            "metadata",
            "created_at",
            "updated_at",
        ]
        read_only_fields = fields


class DynamicDeviceEventSerializer(serializers.ModelSerializer):
    class Meta:
        model = DynamicDeviceEvent
        fields = [
            "id",
            "device",
            "lease",
            "event_type",
            "severity",
            "message",
            "metadata",
            "created_by",
            "created_at",
        ]
        read_only_fields = fields


class DynamicSessionEventSerializer(serializers.ModelSerializer):
    class Meta:
        model = DynamicSessionEvent
        fields = [
            "id",
            "session",
            "event_type",
            "severity",
            "message",
            "sequence_number",
            "metadata",
            "created_at",
        ]
        read_only_fields = fields


class DynamicSessionArtifactSerializer(serializers.ModelSerializer):
    class Meta:
        model = DynamicSessionArtifact
        fields = [
            "id",
            "session",
            "artifact_type",
            "category",
            "name",
            "summary",
            "raw_reference",
            "normalized",
            "redaction_state",
            "confidence",
            "manual_validation_required",
            "correlation_keys",
            "sequence_number",
            "created_at",
        ]
        read_only_fields = fields

    def validate_normalized(self, value):
        _reject_secret_keys(value)
        return value


def _reject_secret_keys(value, path: str = "") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized_key = str(key).lower()
            if any(fragment in normalized_key for fragment in SECRET_KEY_FRAGMENTS):
                raise serializers.ValidationError(
                    f"Normalized artifact contains sensitive key: {path}{key}"
                )
            _reject_secret_keys(child, f"{path}{key}.")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_secret_keys(child, f"{path}{index}.")
