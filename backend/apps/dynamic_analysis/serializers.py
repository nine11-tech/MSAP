import re

from rest_framework import serializers

from apps.api.serializers import EvidenceSerializer
from apps.apk_files.models import APKFile
from apps.audits.models import Audit
from apps.storage.models import ObjectStorageReference
from apps.findings.models import Finding
from apps.dynamic_analysis.models import (
    AgentActionDecision,
    AgentHypothesis,
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
    DynamicValidationResult,
    FindingValidationMission,
    FridaScriptProposal,
)
from apps.dynamic_analysis.services.assessment_planner import (
    OPENAI_MODEL_PROFILE_CHOICES,
)
from apps.dynamic_analysis.services.static_dynamic_correlation import (
    evidence_preview_type,
    evidence_title,
    result_explanation,
    result_label,
    scenario_summary_for_mission,
)


ANDROID_PACKAGE_NAME_RE = re.compile(
    r"^[a-zA-Z][a-zA-Z0-9_]*(?:\.[a-zA-Z0-9_]+)+$"
)
SAFE_AGENT_TEXT_RE = re.compile(r"^[A-Za-z0-9 @._,:+!?/\-]{1,128}$")
MAX_FRIDA_SCRIPT_BYTES = 32 * 1024


class AssessmentPlanCreateSerializer(serializers.Serializer):
    audit = serializers.PrimaryKeyRelatedField(queryset=Audit.objects.all())
    source_finding = serializers.PrimaryKeyRelatedField(queryset=Finding.objects.all(), required=False, allow_null=True)
    target_package = serializers.CharField(max_length=255)
    objective = serializers.CharField(max_length=500, trim_whitespace=True)
    scope = serializers.CharField(max_length=2000, trim_whitespace=True)
    planner_provider = serializers.ChoiceField(
        choices=AssessmentPlan.PlannerProvider.choices,
        required=False,
    )
    model_profile = serializers.ChoiceField(
        choices=OPENAI_MODEL_PROFILE_CHOICES,
        required=False,
        default="ECONOMY",
    )

    def to_internal_value(self, data):
        if not isinstance(data, dict):
            raise serializers.ValidationError("Request body must be a JSON object.")
        unexpected = sorted(
            set(data)
            - {
                "audit",
                "source_finding",
                "target_package",
                "objective",
                "scope",
                "planner_provider",
                "model_profile",
            }
        )
        if unexpected:
            raise serializers.ValidationError(
                {key: "This field is not permitted." for key in unexpected}
            )
        return super().to_internal_value(data)

    def validate(self, attrs):
        finding = attrs.get("source_finding")
        if finding is not None and finding.audit_id != attrs["audit"].pk:
            raise serializers.ValidationError({"source_finding": "Finding must belong to the selected audit."})
        return attrs

    def validate_target_package(self, value):
        if not ANDROID_PACKAGE_NAME_RE.fullmatch(value):
            raise serializers.ValidationError("Invalid Android package name.")
        return value


class StrictEmptySerializer(serializers.Serializer):
    def to_internal_value(self, data):
        if not isinstance(data, dict):
            raise serializers.ValidationError("Request body must be a JSON object.")
        if data:
            raise serializers.ValidationError(
                {key: "This field is not permitted." for key in sorted(data)}
            )
        return {}


class OpenAIBudgetStatusSerializer(serializers.Serializer):
    """Serializable OpenAI call budget snapshot (no secrets)."""

    scope = serializers.CharField()
    max_mission_generation_calls = serializers.IntegerField()
    max_adaptive_decision_calls = serializers.IntegerField()
    max_evidence_explanation_calls = serializers.IntegerField()
    max_total_openai_calls = serializers.IntegerField()
    mission_generation_call_count = serializers.IntegerField()
    adaptive_decision_call_count = serializers.IntegerField()
    evidence_explanation_call_count = serializers.IntegerField()
    current_openai_call_count = serializers.IntegerField()
    remaining_total_calls = serializers.IntegerField()
    provider_response_ids = serializers.ListField(child=serializers.CharField())
    budget_exhausted_reason = serializers.CharField()
    exhausted = serializers.BooleanField()


class AdaptiveAssessmentRecommendationSerializer(serializers.Serializer):
    planner_provider = serializers.ChoiceField(
        choices=AssessmentPlan.PlannerProvider.choices,
        required=False,
    )

    def to_internal_value(self, data):
        if not isinstance(data, dict):
            raise serializers.ValidationError("Request body must be a JSON object.")
        unexpected = sorted(set(data) - {"planner_provider"})
        if unexpected:
            raise serializers.ValidationError(
                {key: "This field is not permitted." for key in unexpected}
            )
        return super().to_internal_value(data)


class AdaptiveAssessmentExecutionSerializer(serializers.Serializer):
    decision_provider = serializers.ChoiceField(
        choices=AssessmentPlan.PlannerProvider.choices,
        required=False,
    )

    def to_internal_value(self, data):
        if not isinstance(data, dict):
            raise serializers.ValidationError("Request body must be a JSON object.")
        unexpected = sorted(set(data) - {"decision_provider"})
        if unexpected:
            raise serializers.ValidationError(
                {key: "This field is not permitted." for key in unexpected}
            )
        return super().to_internal_value(data)


class FridaScriptProposalGenerateSerializer(serializers.Serializer):
    hypothesis = serializers.PrimaryKeyRelatedField(
        queryset=AgentHypothesis.objects.all(),
        required=False,
        allow_null=True,
    )

    def to_internal_value(self, data):
        if not isinstance(data, dict):
            raise serializers.ValidationError("Request body must be a JSON object.")
        unexpected = sorted(set(data) - {"hypothesis"})
        if unexpected:
            raise serializers.ValidationError(
                {key: "This field is not permitted." for key in unexpected}
            )
        return super().to_internal_value(data)

    def validate_hypothesis(self, value):
        run = self.context.get("run")
        if value is not None and run is not None and value.run_id != run.id:
            raise serializers.ValidationError("Hypothesis does not belong to this AgentRun.")
        return value


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
    runtime_type = serializers.ChoiceField(
        choices=AgentRuntime.RuntimeType.choices,
        default=AgentRuntime.RuntimeType.INTERNAL_CONTROLLER,
    )
    audit = serializers.PrimaryKeyRelatedField(
        queryset=Audit.objects.all(),
        required=False,
        allow_null=True,
    )
    objective_input = serializers.JSONField(required=False, default=dict)

    def to_internal_value(self, data):
        if not isinstance(data, dict):
            raise serializers.ValidationError("Request body must be a JSON object.")
        unexpected = sorted(
            set(data) - {"objective", "runtime_type", "audit", "objective_input"}
        )
        if unexpected:
            raise serializers.ValidationError(
                {key: "This field is not permitted." for key in unexpected}
            )
        return super().to_internal_value(data)

    def validate(self, attrs):
        objective = attrs["objective"]
        objective_input = attrs.get("objective_input", {})
        if not isinstance(objective_input, dict):
            raise serializers.ValidationError(
                {"objective_input": "This field must be a JSON object."}
            )
        if objective == AgentRun.Objective.ASSESSMENT_PLAN_EXECUTION:
            raise serializers.ValidationError(
                {
                    "objective": (
                        "Approved assessment execution can start only from the "
                        "AssessmentPlan execute endpoint."
                    )
                }
            )
        if objective == AgentRun.Objective.DEVICE_READINESS_CHECK:
            if objective_input:
                raise serializers.ValidationError(
                    {"objective_input": "Device readiness does not accept objective input."}
                )
            return attrs
        if objective in {
            AgentRun.Objective.FRIDA_RUNTIME_ACTION,
            AgentRun.Objective.FRIDA_RUNTIME_UI_MODIFICATION_PROOF,
            AgentRun.Objective.FRIDA_CUSTOM_SCRIPT,
        }:
            return _validate_frida_objective(attrs, objective, objective_input)

        allowed = {"audit_id", "apk_file_id", "package_name", "tap", "text"}
        unexpected = sorted(set(objective_input) - allowed)
        if unexpected:
            raise serializers.ValidationError(
                {
                    "objective_input": {
                        key: "This field is not permitted." for key in unexpected
                    }
                }
            )
        audit_id = objective_input.get("audit_id")
        if isinstance(audit_id, bool) or not isinstance(audit_id, int) or audit_id < 1:
            raise serializers.ValidationError(
                {"objective_input": {"audit_id": "A positive audit_id is required."}}
            )
        audit = Audit.objects.filter(pk=audit_id).first()
        if audit is None:
            raise serializers.ValidationError(
                {"objective_input": {"audit_id": "Audit does not exist."}}
            )
        top_level_audit = attrs.get("audit")
        if top_level_audit is not None and top_level_audit.pk != audit.pk:
            raise serializers.ValidationError(
                {"audit": "Audit must match objective_input.audit_id."}
            )

        apk_file_id = objective_input.get("apk_file_id")
        package_name = objective_input.get("package_name")
        if (apk_file_id is None) == (package_name is None):
            raise serializers.ValidationError(
                {
                    "objective_input": (
                        "Provide exactly one of apk_file_id or package_name."
                    )
                }
            )
        normalized = {"audit_id": audit.pk}
        if apk_file_id is not None:
            if (
                isinstance(apk_file_id, bool)
                or not isinstance(apk_file_id, int)
                or apk_file_id < 1
            ):
                raise serializers.ValidationError(
                    {"objective_input": {"apk_file_id": "Must be a positive integer."}}
                )
            apk_file = APKFile.objects.filter(pk=apk_file_id, audit=audit).first()
            if apk_file is None:
                raise serializers.ValidationError(
                    {
                        "objective_input": {
                            "apk_file_id": "APK file must belong to the selected audit."
                        }
                    }
                )
            normalized["apk_file_id"] = apk_file.pk
        else:
            if not isinstance(package_name, str) or not ANDROID_PACKAGE_NAME_RE.fullmatch(
                package_name
            ):
                raise serializers.ValidationError(
                    {
                        "objective_input": {
                            "package_name": "Invalid Android package name."
                        }
                    }
                )
            normalized["package_name"] = package_name

        tap = objective_input.get("tap")
        if tap is not None:
            if not isinstance(tap, dict) or set(tap) != {"x", "y"}:
                raise serializers.ValidationError(
                    {"objective_input": {"tap": "Tap requires only integer x and y."}}
                )
            for coordinate in ("x", "y"):
                value = tap.get(coordinate)
                if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 10000:
                    raise serializers.ValidationError(
                        {
                            "objective_input": {
                                "tap": f"{coordinate} must be an integer from 0 to 10000."
                            }
                        }
                    )
            normalized["tap"] = {"x": tap["x"], "y": tap["y"]}

        text = objective_input.get("text")
        if text is not None:
            if not isinstance(text, str) or not 1 <= len(text) <= 128:
                raise serializers.ValidationError(
                    {"objective_input": {"text": "Text must contain 1 to 128 characters."}}
                )
            if any(ord(character) < 32 or ord(character) == 127 for character in text):
                raise serializers.ValidationError(
                    {"objective_input": {"text": "Text cannot contain control characters."}}
                )
            if not SAFE_AGENT_TEXT_RE.fullmatch(text):
                raise serializers.ValidationError(
                    {
                        "objective_input": {
                            "text": "Text contains characters that cannot be typed safely."
                        }
                    }
                )
            normalized["text"] = text

        attrs["audit"] = audit
        attrs["objective_input"] = normalized
        return attrs


def _validate_frida_objective(attrs, objective: str, objective_input: dict):
    common = {"audit_id", "package_name"}
    allowed_by_objective = {
        AgentRun.Objective.FRIDA_RUNTIME_ACTION: common
        | {"operation", "mode", "timeout"},
        AgentRun.Objective.FRIDA_RUNTIME_UI_MODIFICATION_PROOF: common,
        AgentRun.Objective.FRIDA_CUSTOM_SCRIPT: common
        | {"mode", "source", "timeout", "capture_logcat", "confirm"},
    }
    unexpected = sorted(set(objective_input) - allowed_by_objective[objective])
    if unexpected:
        raise serializers.ValidationError(
            {
                "objective_input": {
                    key: "This field is not permitted." for key in unexpected
                }
            }
        )
    audit_id = objective_input.get("audit_id")
    if isinstance(audit_id, bool) or not isinstance(audit_id, int) or audit_id < 1:
        raise serializers.ValidationError(
            {"objective_input": {"audit_id": "A positive audit_id is required."}}
        )
    audit = Audit.objects.filter(pk=audit_id).first()
    if audit is None:
        raise serializers.ValidationError(
            {"objective_input": {"audit_id": "Audit does not exist."}}
        )
    if attrs.get("audit") is not None and attrs["audit"].pk != audit.pk:
        raise serializers.ValidationError(
            {"audit": "Audit must match objective_input.audit_id."}
        )
    package_name = objective_input.get("package_name")
    if not isinstance(package_name, str) or not ANDROID_PACKAGE_NAME_RE.fullmatch(
        package_name
    ):
        raise serializers.ValidationError(
            {"objective_input": {"package_name": "Invalid Android package name."}}
        )
    # Installed-package objectives are explicitly authorized by an
    # Analyst/Admin for this audit and the host agent independently requires
    # the exact package to exist on the managed emulator. APK installation
    # remains separately audit-owned and VERIFIED-only.
    normalized = {"audit_id": audit.pk, "package_name": package_name}
    if objective == AgentRun.Objective.FRIDA_RUNTIME_ACTION:
        operation = objective_input.get("operation")
        if operation not in {"status", "setup", "ps", "attach"}:
            raise serializers.ValidationError(
                {
                    "objective_input": {
                        "operation": "Use status, setup, ps, or attach."
                    }
                }
            )
        normalized["operation"] = operation
        mode = objective_input.get("mode", "attach")
        timeout = objective_input.get("timeout", 10)
        if mode not in {"attach", "spawn"}:
            raise serializers.ValidationError(
                {"objective_input": {"mode": "Use attach or spawn."}}
            )
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 30:
            raise serializers.ValidationError(
                {"objective_input": {"timeout": "Must be an integer from 1 to 30."}}
            )
        normalized.update({"mode": mode, "timeout": timeout})
    elif objective == AgentRun.Objective.FRIDA_CUSTOM_SCRIPT:
        if objective_input.get("confirm") is not True:
            raise serializers.ValidationError(
                {"objective_input": {"confirm": "Custom script execution requires confirm=true."}}
            )
        source = objective_input.get("source")
        if not isinstance(source, str) or not source.strip():
            raise serializers.ValidationError(
                {"objective_input": {"source": "JavaScript source cannot be empty."}}
            )
        if "\x00" in source or len(source.encode("utf-8")) > MAX_FRIDA_SCRIPT_BYTES:
            raise serializers.ValidationError(
                {
                    "objective_input": {
                        "source": f"JavaScript must be at most {MAX_FRIDA_SCRIPT_BYTES} bytes with no NUL characters."
                    }
                }
            )
        mode = objective_input.get("mode", "attach")
        timeout = objective_input.get("timeout", 12)
        capture_logcat = objective_input.get("capture_logcat", True)
        if mode not in {"attach", "spawn"}:
            raise serializers.ValidationError(
                {"objective_input": {"mode": "Use attach or spawn."}}
            )
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 30:
            raise serializers.ValidationError(
                {"objective_input": {"timeout": "Must be an integer from 1 to 30."}}
            )
        if not isinstance(capture_logcat, bool):
            raise serializers.ValidationError(
                {"objective_input": {"capture_logcat": "Must be a boolean."}}
            )
        normalized.update(
            {
                "mode": mode,
                "source": source,
                "timeout": timeout,
                "capture_logcat": capture_logcat,
                "confirm": True,
            }
        )
    attrs["audit"] = audit
    attrs["objective_input"] = normalized
    return attrs


class AgentToolCallSerializer(serializers.Serializer):
    tool_name = serializers.CharField(max_length=128)
    arguments = serializers.JSONField()

    def to_internal_value(self, data):
        if not isinstance(data, dict):
            raise serializers.ValidationError("Request body must be a JSON object.")
        unexpected = sorted(set(data) - {"tool_name", "arguments"})
        if unexpected:
            raise serializers.ValidationError(
                {key: "This field is not permitted." for key in unexpected}
            )
        return super().to_internal_value(data)


class AgentRuntimeSerializer(serializers.ModelSerializer):
    configuration_enabled = serializers.SerializerMethodField()
    available = serializers.SerializerMethodField()

    @staticmethod
    def get_configuration_enabled(runtime):
        if runtime.runtime_type == AgentRuntime.RuntimeType.CONTAINER_SANDBOX:
            from django.conf import settings

            return bool(settings.MSAP_AGENT_CONTAINER_ENABLED)
        return True

    def get_available(self, runtime):
        return bool(
            runtime.enabled
            and runtime.status == AgentRuntime.Status.AVAILABLE
            and self.get_configuration_enabled(runtime)
        )

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
            "configuration_enabled",
            "available",
            "last_seen_at",
            "created_at",
            "updated_at",
        ]
        read_only_fields = fields


class AgentRunSerializer(serializers.ModelSerializer):
    adaptive_retryable = serializers.SerializerMethodField()
    adaptive_retry_block_reason = serializers.SerializerMethodField()
    pre_execution_failure = serializers.SerializerMethodField()
    plan_approval_preserved = serializers.SerializerMethodField()
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
    runtime_type = serializers.CharField(
        source="runtime.runtime_type",
        read_only=True,
        allow_null=True,
    )
    isolation_level = serializers.CharField(
        source="runtime.isolation_level",
        read_only=True,
        allow_null=True,
    )

    def _adaptive_retryability(self, run):
        request = self.context.get("request")
        requested_by = getattr(request, "user", None)
        cache_key = (run.pk, getattr(requested_by, "pk", None))
        cache = getattr(self, "_adaptive_retryability_cache", {})
        if cache_key not in cache:
            from apps.dynamic_analysis.services.agent_retry import (
                adaptive_retryability,
            )

            cache[cache_key] = adaptive_retryability(
                run,
                requested_by=requested_by,
            )
            self._adaptive_retryability_cache = cache
        return cache[cache_key]

    def get_adaptive_retryable(self, run):
        return self._adaptive_retryability(run).retryable

    def get_adaptive_retry_block_reason(self, run):
        return self._adaptive_retryability(run).reason

    def get_pre_execution_failure(self, run):
        return self._adaptive_retryability(run).pre_execution_failure

    def get_plan_approval_preserved(self, run):
        return self._adaptive_retryability(run).plan_approval_preserved

    class Meta:
        model = AgentRun
        fields = [
            "id",
            "audit",
            "device",
            "device_serial",
            "runtime",
            "runtime_name",
            "runtime_type",
            "isolation_level",
            "assessment_plan",
            "approved_plan_hash",
            "target_package",
            "execution_mode",
            "capability_envelope",
            "capability_envelope_hash",
            "decision_provider",
            "decision_model",
            "decision_count",
            "model_call_count",
            "consecutive_failure_count",
            "coverage_state",
            "termination_reason",
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
            "pre_execution_failure",
            "plan_approval_preserved",
            "adaptive_retryable",
            "adaptive_retry_block_reason",
            "tool_call_count",
            "cancellation_requested_at",
            "cancelled_by",
            "created_at",
            "updated_at",
        ]
        read_only_fields = fields


class AgentHypothesisSerializer(serializers.ModelSerializer):
    class Meta:
        model = AgentHypothesis
        fields = [
            "id",
            "run",
            "hypothesis_id",
            "family",
            "title",
            "description",
            "evidence_requirements",
            "status",
            "confidence",
            "oracle_result",
            "created_at",
            "updated_at",
        ]
        read_only_fields = fields


class AgentActionDecisionSerializer(serializers.ModelSerializer):
    hypothesis_identifier = serializers.CharField(
        source="hypothesis.hypothesis_id",
        read_only=True,
        allow_null=True,
    )

    class Meta:
        model = AgentActionDecision
        fields = [
            "id",
            "run",
            "sequence",
            "contract_version",
            "hypothesis",
            "hypothesis_identifier",
            "run_step",
            "decision_type",
            "tool_name",
            "arguments",
            "rationale_summary",
            "expected_observation",
            "evidence_goals",
            "confidence",
            "provider",
            "model",
            "provider_metadata",
            "decision_input_hash",
            "decision_output_hash",
            "validation_status",
            "policy_status",
            "execution_status",
            "observation_hash",
            "failure_code",
            "created_at",
            "validated_at",
            "executed_at",
        ]
        read_only_fields = fields


class FridaScriptProposalSerializer(serializers.ModelSerializer):
    created_by_username = serializers.CharField(
        source="created_by.username",
        read_only=True,
        allow_null=True,
    )
    approved_by_username = serializers.CharField(
        source="approved_by.username",
        read_only=True,
        allow_null=True,
    )
    hypothesis_identifier = serializers.CharField(
        source="hypothesis.hypothesis_id",
        read_only=True,
        allow_null=True,
    )

    class Meta:
        model = FridaScriptProposal
        fields = [
            "id",
            "run",
            "audit",
            "finding",
            "mission",
            "hypothesis",
            "hypothesis_identifier",
            "title",
            "rationale",
            "expected_evidence",
            "source_identifier",
            "source_sha256",
            "source_code",
            "source_size_bytes",
            "generator_provider",
            "generator_model",
            "provider_metadata",
            "validation_warnings",
            "status",
            "created_by",
            "created_by_username",
            "approved_by",
            "approved_by_username",
            "approved_at",
            "executed_at",
            "last_error",
            "suggested_fix",
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
            "plan_step_identifier",
            "plan_step_sequence",
            "tool_call_index",
            "is_control_step",
            "dependencies",
            "evidence_requirements",
            "status",
            "input_summary",
            "output_summary",
            "observation",
            "retry_count",
            "max_retries",
            "timeout_seconds",
            "started_at",
            "finished_at",
            "duration_seconds",
            "failure_message",
            "created_at",
        ]
        read_only_fields = fields


class AgentRunArtifactSerializer(serializers.ModelSerializer):
    download_url = serializers.SerializerMethodField()

    @staticmethod
    def get_download_url(artifact):
        reference = artifact.object_reference
        if reference is None or reference.storage_status != ObjectStorageReference.StorageStatus.VERIFIED:
            return ""
        from apps.storage.services.minio_storage import MinIOStorageService

        return MinIOStorageService().generate_presigned_download_url(
            reference.bucket,
            reference.object_key,
            expires_in=300,
        )

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
            "download_url",
            "metadata",
            "size_bytes",
            "sha256",
            "created_at",
        ]
        read_only_fields = fields


class AssessmentPlanStepSerializer(serializers.ModelSerializer):
    class Meta:
        model = AssessmentPlanStep
        fields = [
            "id",
            "plan",
            "sequence",
            "step_identifier",
            "objective",
            "rationale",
            "required_tools",
            "tool_arguments",
            "expected_observation",
            "success_condition",
            "evidence_requirements",
            "dependencies",
            "status",
            "created_at",
            "updated_at",
        ]
        read_only_fields = fields


class AssessmentPlanSerializer(serializers.ModelSerializer):
    steps = AssessmentPlanStepSerializer(many=True, read_only=True)
    created_by_username = serializers.CharField(
        source="created_by.username",
        read_only=True,
        allow_null=True,
    )
    approved_by_username = serializers.CharField(
        source="approved_by.username",
        read_only=True,
        allow_null=True,
    )
    agentic_capability_preview = serializers.SerializerMethodField()

    @staticmethod
    def get_agentic_capability_preview(plan):
        try:
            from apps.dynamic_analysis.services.agent_capability_envelope import (
                build_capability_envelope,
                build_capability_preview,
            )

            if plan.status in {
                AssessmentPlan.Status.APPROVED,
                AssessmentPlan.Status.EXECUTING,
                AssessmentPlan.Status.COMPLETED,
            }:
                envelope = build_capability_envelope(plan)
                return {
                    "contract_version": envelope["contract_version"],
                    "allowed_capabilities": envelope["allowed_capabilities"],
                    "allowed_hypothesis_families": envelope[
                        "allowed_hypothesis_families"
                    ],
                    "maximum_decisions": envelope["maximum_decisions"],
                    "maximum_tool_calls": envelope["maximum_tool_calls"],
                    "maximum_run_duration_seconds": envelope[
                        "maximum_run_duration_seconds"
                    ],
                    "maximum_provider_calls": envelope[
                        "maximum_model_provider_calls"
                    ],
                    "additional_approval_capabilities": envelope[
                        "additional_approval_capabilities"
                    ],
                }
            return build_capability_preview(plan)
        except Exception:
            return {}

    class Meta:
        model = AssessmentPlan
        fields = [
            "id",
            "audit",
            "source_finding",
            "plan_kind",
            "parent_plan",
            "source_run",
            "adaptive_cycle",
            "target_package",
            "planner_provider",
            "planner_model",
            "objective",
            "scope",
            "status",
            "validation_status",
            "policy_status",
            "generated_plan",
            "normalized_plan",
            "provider_metadata",
            "validation_errors",
            "planner_input_hash",
            "plan_hash",
            "agentic_capability_preview",
            "scenario_contract",
            "created_by",
            "created_by_username",
            "approved_by",
            "approved_by_username",
            "validated_at",
            "approved_at",
            "created_at",
            "updated_at",
            "steps",
        ]
        read_only_fields = fields


class DynamicValidationResultSerializer(serializers.ModelSerializer):
    evidence_ids = serializers.SerializerMethodField()
    result = serializers.SerializerMethodField()

    def get_evidence_ids(self, obj):
        return list(obj.evidence.values_list("id", flat=True)[:100])

    def get_result(self, obj):
        return obj.oracle_result.get("result_contract", {}).get("result", obj.validation_status)

    class Meta:
        model = DynamicValidationResult
        fields = [
            "id", "audit", "finding", "rule_id", "scenario_id", "playbook_id",
            "agent_run", "oracle_id", "oracle_result", "validation_status", "result",
            "evidence_ids", "confidence", "safe_summary", "limitations", "created_at",
        ]
        read_only_fields = fields


class FindingValidationMissionSerializer(serializers.ModelSerializer):
    evidence_ids = serializers.SerializerMethodField()
    evidence_count = serializers.SerializerMethodField()
    finding_title = serializers.CharField(source="finding.title", read_only=True)
    finding_rule_id = serializers.CharField(source="finding.rule_id", read_only=True)
    finding_severity = serializers.CharField(source="finding.severity", read_only=True)
    assessment_plan_status = serializers.CharField(
        source="assessment_plan.status",
        read_only=True,
    )
    agent_run_status = serializers.CharField(source="agent_run.status", read_only=True)
    dynamic_validation_result_status = serializers.CharField(
        source="dynamic_validation_result.validation_status",
        read_only=True,
    )
    approved_by_username = serializers.CharField(
        source="approved_by.username",
        read_only=True,
        allow_blank=True,
    )
    result_label = serializers.SerializerMethodField()
    result_explanation = serializers.SerializerMethodField()
    scenario_summary = serializers.SerializerMethodField()

    def get_evidence_ids(self, obj):
        return list(obj.evidence.values_list("id", flat=True)[:100])

    def get_evidence_count(self, obj):
        return obj.evidence.count()

    def get_result_label(self, obj):
        return result_label(obj.status)

    def get_result_explanation(self, obj):
        return result_explanation(obj.status)

    def get_scenario_summary(self, obj):
        return scenario_summary_for_mission(obj)

    class Meta:
        model = FindingValidationMission
        fields = [
            "id",
            "audit",
            "apk",
            "finding",
            "finding_title",
            "finding_rule_id",
            "finding_severity",
            "assessment_plan",
            "assessment_plan_status",
            "agent_run",
            "agent_run_status",
            "dynamic_validation_result",
            "dynamic_validation_result_status",
            "target_package",
            "status",
            "scenario_contract",
            "scenario_hash",
            "mission_hash",
            "validation_family",
            "playbook_id",
            "hypothesis",
            "final_conclusion",
            "limitations",
            "oracle_result",
            "provider",
            "model",
            "provider_metadata",
            "allowed_capabilities",
            "budgets",
            "evidence_ids",
            "evidence_count",
            "result_label",
            "result_explanation",
            "scenario_summary",
            "created_by",
            "approved_by",
            "approved_by_username",
            "approved_at",
            "started_at",
            "completed_at",
            "created_at",
            "updated_at",
        ]
        read_only_fields = fields


class CapabilityGapEntrySerializer(serializers.Serializer):
    missing_capability = serializers.CharField()
    affected_finding_count = serializers.IntegerField()
    affected_finding_ids = serializers.ListField(child=serializers.IntegerField())


class CorrelationCandidateSerializer(serializers.Serializer):
    finding_id = serializers.IntegerField()
    finding_title = serializers.CharField()
    severity = serializers.CharField()
    confidence = serializers.CharField()
    rule_id = serializers.CharField()
    category = serializers.CharField()
    classification = serializers.CharField()
    priority = serializers.IntegerField()
    security_hypothesis = serializers.CharField()
    dynamic_validation_value = serializers.CharField()
    recommended_poc_summary = serializers.CharField()
    likely_capabilities = serializers.ListField(child=serializers.CharField())
    expected_evidence = serializers.ListField(child=serializers.CharField())
    prerequisites = serializers.CharField()
    limitations = serializers.CharField()
    estimated_complexity = serializers.CharField()
    current_validation_status = serializers.CharField()
    missing_capabilities = serializers.ListField(child=serializers.CharField())
    start_poc_available = serializers.BooleanField()


class StaticDynamicCorrelationSerializer(serializers.Serializer):
    audit_id = serializers.IntegerField()
    target_package = serializers.CharField()
    contract_version = serializers.CharField()
    total_static_findings = serializers.IntegerField()
    recommended_count = serializers.IntegerField()
    optional_count = serializers.IntegerField()
    static_sufficient_count = serializers.IntegerField()
    not_testable_count = serializers.IntegerField()
    already_validated_count = serializers.IntegerField()
    blocked_count = serializers.IntegerField()
    correlation_mode = serializers.CharField()
    model = serializers.CharField()
    generated_at = serializers.CharField()
    capability_gaps = CapabilityGapEntrySerializer(many=True)
    candidates = CorrelationCandidateSerializer(many=True)


class CorrelationCandidateStartPocRequestSerializer(serializers.Serializer):
    finding_id = serializers.IntegerField()


class CorrelationCandidateStartPocSerializer(serializers.Serializer):
    mission = FindingValidationMissionSerializer()
    next_step = serializers.CharField()


class CorrelationPlaybookStartRequestSerializer(serializers.Serializer):
    playbook_id = serializers.ChoiceField(
        choices=[
            "ROOT_DETECTION_SCREEN_VALIDATION",
            "TLS_PINNING_FRIDA_BYPASS",
        ]
    )


class FindingMissionEvidenceSerializer(EvidenceSerializer):
    """Mission evidence with clean auditor-facing UI labels."""

    evidence_title = serializers.SerializerMethodField()
    evidence_preview_type = serializers.SerializerMethodField()

    def get_evidence_title(self, obj):
        return evidence_title(obj.evidence_type)

    def get_evidence_preview_type(self, obj):
        return evidence_preview_type(obj.evidence_type)

    class Meta(EvidenceSerializer.Meta):
        fields = EvidenceSerializer.Meta.fields + [
            "evidence_title",
            "evidence_preview_type",
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
