from rest_framework import serializers
import re

from apps.analyzers.models import RawAnalyzerResult
from apps.appsec_rules.models import RuleEvaluation
from apps.apk_files.models import APKFile
from apps.audits.models import AnalysisJob, Audit
from apps.evidence.models import Evidence, FindingSourceReference, SourceDocument
from apps.findings.models import Finding
from apps.indicators.models import SuspiciousIndicator
from apps.normalization.models import NormalizedArtifact
from apps.projects.models import Project
from apps.reports.models import Report
from apps.scoring.models import ComplianceScore, RiskScore
from apps.storage.models import ObjectStorageReference
from apps.triage_rules.services.triage_rule_loader import default_attck_rules_by_id


APK_CONTENT_TYPES = {
    "application/vnd.android.package-archive",
    "application/octet-stream",
}


class ProjectSerializer(serializers.ModelSerializer):
    class Meta:
        model = Project
        fields = ["id", "name", "description", "created_at", "updated_at"]
        read_only_fields = ["id", "created_at", "updated_at"]


class AuditSerializer(serializers.ModelSerializer):
    class Meta:
        model = Audit
        fields = ["id", "project", "name", "status", "created_at", "updated_at"]
        read_only_fields = ["id", "created_at", "updated_at"]


class ObjectStorageReferenceSerializer(serializers.ModelSerializer):
    class Meta:
        model = ObjectStorageReference
        fields = [
            "id",
            "bucket",
            "object_key",
            "object_type",
            "storage_status",
            "content_type",
            "size_bytes",
            "sha256",
            "audit",
            "project",
            "retention_policy",
            "encryption_status",
            "redaction_status",
            "access_scope",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]


class APKFileSerializer(serializers.ModelSerializer):
    storage_status = serializers.CharField(
        source="storage_reference.storage_status",
        read_only=True,
        allow_null=True,
    )

    class Meta:
        model = APKFile
        fields = [
            "id",
            "audit",
            "package_name",
            "version_name",
            "sha256",
            "size_bytes",
            "storage_reference",
            "storage_status",
            "created_at",
        ]
        read_only_fields = ["id", "created_at"]


class APKUploadInitiateRequestSerializer(serializers.Serializer):
    filename = serializers.CharField()
    content_type = serializers.CharField()
    size_bytes = serializers.IntegerField(min_value=1)
    sha256 = serializers.CharField(required=False, allow_blank=True, max_length=64)

    def validate_filename(self, value):
        if not value.lower().endswith(".apk"):
            raise serializers.ValidationError("Only .apk files are accepted in V1.0.")
        return value

    def validate_content_type(self, value):
        if value not in APK_CONTENT_TYPES:
            raise serializers.ValidationError("Unsupported APK content type.")
        return value

    def validate_size_bytes(self, value):
        max_size = self.context["max_size_bytes"]
        if value > max_size:
            raise serializers.ValidationError(
                f"APK size exceeds the configured limit of {max_size} bytes."
            )
        return value

    def validate_sha256(self, value):
        normalized = value.strip().lower()
        if normalized and not re.fullmatch(r"[0-9a-f]{64}", normalized):
            raise serializers.ValidationError("sha256 must be 64 hexadecimal characters.")
        return normalized

    def validate(self, attrs):
        if self.context.get("require_sha256") and not attrs.get("sha256"):
            raise serializers.ValidationError(
                {"sha256": "SHA-256 is required for APK uploads."}
            )
        return attrs


class APKUploadInitiateResponseSerializer(serializers.Serializer):
    apk_file_id = serializers.IntegerField()
    storage_reference_id = serializers.IntegerField()
    bucket = serializers.CharField()
    object_key = serializers.CharField()
    upload_url = serializers.URLField()
    expires_in = serializers.IntegerField()
    required_headers = serializers.DictField(child=serializers.CharField())


class AnalyzerMetadataSerializer(serializers.Serializer):
    name = serializers.CharField()
    version = serializers.CharField()
    description = serializers.CharField(allow_blank=True)
    enabled = serializers.BooleanField()
    available = serializers.BooleanField()
    optional = serializers.BooleanField()
    status = serializers.CharField()
    capability = serializers.CharField(required=False, allow_blank=True)
    reason = serializers.CharField(required=False, allow_blank=True)


class APKUploadConfirmRequestSerializer(serializers.Serializer):
    size_bytes = serializers.IntegerField(required=False, min_value=1)
    sha256 = serializers.CharField(required=False, allow_blank=True, max_length=64)

    def validate_sha256(self, value):
        normalized = value.strip().lower()
        if normalized and not re.fullmatch(r"[0-9a-f]{64}", normalized):
            raise serializers.ValidationError("sha256 must be 64 hexadecimal characters.")
        return normalized


class AnalysisJobSerializer(serializers.ModelSerializer):
    class Meta:
        model = AnalysisJob
        fields = [
            "id",
            "task_id",
            "status",
            "started_at",
            "finished_at",
            "error_message",
            "result_summary",
        ]
        read_only_fields = fields


class RawAnalyzerResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = RawAnalyzerResult
        fields = [
            "id",
            "audit",
            "apk_file",
            "analyzer_name",
            "analyzer_version",
            "status",
            "storage_reference",
            "result_summary",
            "error_message",
            "created_at",
            "updated_at",
        ]
        read_only_fields = fields


class NormalizedArtifactSerializer(serializers.ModelSerializer):
    class Meta:
        model = NormalizedArtifact
        fields = [
            "id",
            "audit",
            "apk_file",
            "artifact_type",
            "source",
            "normalized_data",
            "storage_reference",
            "created_at",
            "updated_at",
        ]
        read_only_fields = fields


class FindingSerializer(serializers.ModelSerializer):
    dynamic_validation_status = serializers.SerializerMethodField()
    dynamic_validation_result_id = serializers.SerializerMethodField()
    dynamic_validation_mission_id = serializers.SerializerMethodField()
    dynamic_validation_summary = serializers.SerializerMethodField()
    dynamic_validation_playbooks = serializers.SerializerMethodField()

    def get_dynamic_validation_status(self, obj):
        latest_mission = obj.validation_missions.order_by("-created_at").first()
        if latest_mission is not None:
            return latest_mission.status
        latest = obj.dynamic_validation_results.order_by("-created_at").first()
        return latest.validation_status if latest else "NOT_STARTED"

    def get_dynamic_validation_result_id(self, obj):
        latest = obj.dynamic_validation_results.order_by("-created_at").first()
        return latest.id if latest else None

    def get_dynamic_validation_mission_id(self, obj):
        latest = obj.validation_missions.order_by("-created_at").first()
        return latest.id if latest else None

    def get_dynamic_validation_summary(self, obj):
        latest = obj.validation_missions.order_by("-created_at").first()
        if latest is None:
            return {}
        return {
            "mission_id": latest.id,
            "run_id": latest.agent_run_id,
            "status": latest.status,
            "hypothesis": latest.hypothesis,
            "scenario_summary": latest.scenario_contract.get("validation_goal", "")
            if isinstance(latest.scenario_contract, dict)
            else "",
            "evidence_count": latest.evidence.count(),
            "oracle_result": latest.oracle_result,
            "final_conclusion": latest.final_conclusion,
            "limitations": latest.limitations,
            "created_at": latest.created_at,
            "completed_at": latest.completed_at,
        }

    def get_dynamic_validation_playbooks(self, obj):
        from apps.dynamic_analysis.services.playbook_catalog import executable_playbooks_for_finding
        return [item["playbook_id"] for item in executable_playbooks_for_finding(obj)]

    masvs_controls = serializers.SerializerMethodField()
    maswe_ids = serializers.SerializerMethodField()
    mastg_references = serializers.SerializerMethodField()
    source_reference_count = serializers.SerializerMethodField()
    evidence_count = serializers.SerializerMethodField()
    related_agent_runs = serializers.SerializerMethodField()
    related_agent_run_steps = serializers.SerializerMethodField()
    provenance = serializers.SerializerMethodField()

    @staticmethod
    def _mapping(obj, key):
        return obj.mapping_data.get(key, []) if isinstance(obj.mapping_data, dict) else []

    def get_masvs_controls(self, obj):
        return self._mapping(obj, "masvs_controls")

    def get_maswe_ids(self, obj):
        return self._mapping(obj, "maswe_ids")

    def get_mastg_references(self, obj):
        return self._mapping(obj, "mastg_references")

    def get_source_reference_count(self, obj):
        return obj.source_references.count()

    def get_evidence_count(self, obj):
        return obj.evidence.count()

    def get_related_agent_runs(self, obj):
        return list(
            obj.evidence.exclude(agent_run=None)
            .order_by("agent_run_id")
            .values_list("agent_run_id", flat=True)
            .distinct()[:25]
        )

    def get_related_agent_run_steps(self, obj):
        return list(
            obj.evidence.exclude(agent_run_step=None)
            .order_by("agent_run_step_id")
            .values_list("agent_run_step_id", flat=True)
            .distinct()[:100]
        )

    def get_provenance(self, obj):
        return (
            "DETERMINISTIC_DYNAMIC_EVIDENCE"
            if obj.rule_id.startswith("MSAP-DYN-")
            else "DETERMINISTIC_STATIC_RULE"
        )

    class Meta:
        model = Finding
        fields = [
            "id",
            "audit",
            "rule_id",
            "title",
            "severity",
            "confidence",
            "standard",
            "category",
            "description",
            "mapping_data",
            "masvs_controls",
            "maswe_ids",
            "mastg_references",
            "source_reference_count",
            "evidence_count",
            "related_agent_runs",
            "related_agent_run_steps",
            "provenance",
            "recommendation",
            "false_positive_guidance",
            "requires_manual_validation",
            "status",
            "dynamic_validation_status",
            "dynamic_validation_result_id",
            "dynamic_validation_mission_id",
            "dynamic_validation_summary",
            "dynamic_validation_playbooks",
            "created_at",
        ]
        read_only_fields = fields


class SuspiciousIndicatorSerializer(serializers.ModelSerializer):
    auditor_explanation = serializers.SerializerMethodField()
    dynamic_verification_scenario = serializers.SerializerMethodField()

    @staticmethod
    def _catalog_rule(obj):
        return default_attck_rules_by_id().get(obj.indicator_id, {})

    def get_auditor_explanation(self, obj):
        return obj.auditor_explanation or self._catalog_rule(obj).get(
            "auditor_explanation", obj.triage_interpretation
        )

    def get_dynamic_verification_scenario(self, obj):
        return obj.dynamic_verification_scenario or self._catalog_rule(obj).get(
            "dynamic_verification_scenario", ""
        )

    class Meta:
        model = SuspiciousIndicator
        fields = [
            "id",
            "audit",
            "indicator_id",
            "title",
            "tactic",
            "technique_id",
            "technique_name",
            "severity",
            "confidence",
            "triage_interpretation",
            "auditor_explanation",
            "dynamic_verification_scenario",
            "source_evidence",
            "mapping_rationale",
            "false_positive_considerations",
            "requires_manual_validation",
            "non_malware_verdict_note",
            "created_at",
        ]
        read_only_fields = fields


class EvidenceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Evidence
        fields = [
            "id",
            "audit",
            "finding",
            "indicator",
            "storage_reference",
            "agent_run",
            "agent_run_step",
            "agent_run_artifact",
            "evidence_type",
            "source",
            "snippet",
            "ai_explanation",
            "ai_conclusion",
            "ai_security_impact",
            "ai_evidence_strength",
            "ai_explanation_status",
            "ai_explanation_provider",
            "ai_explanation_model",
            "ai_explanation_metadata",
            "redacted",
            "sha256",
            "provenance",
            "created_at",
        ]
        read_only_fields = fields


class SourceDocumentSerializer(serializers.ModelSerializer):
    representation_label = serializers.CharField(
        source="get_representation_type_display",
        read_only=True,
    )
    storage_available = serializers.SerializerMethodField()

    def get_storage_available(self, obj):
        return bool(obj.storage_reference_id)

    class Meta:
        model = SourceDocument
        fields = [
            "id",
            "audit",
            "apk_file",
            "representation_type",
            "representation_label",
            "logical_path",
            "display_path",
            "language",
            "class_name",
            "package_name",
            "sha256",
            "line_count",
            "generated_by",
            "tool_version",
            "storage_available",
            "metadata",
            "created_at",
        ]
        read_only_fields = fields


class FindingSourceReferenceSerializer(serializers.ModelSerializer):
    representation_label = serializers.CharField(
        source="get_representation_type_display",
        read_only=True,
    )
    source_document_sha256 = serializers.CharField(
        source="source_document.sha256",
        read_only=True,
        allow_null=True,
    )
    source_document_display_path = serializers.CharField(
        source="source_document.display_path",
        read_only=True,
        allow_null=True,
    )
    source_document_line_count = serializers.IntegerField(
        source="source_document.line_count",
        read_only=True,
        allow_null=True,
    )

    class Meta:
        model = FindingSourceReference
        fields = [
            "id",
            "finding",
            "source_document",
            "representation_type",
            "representation_label",
            "logical_path",
            "source_document_display_path",
            "source_document_sha256",
            "source_document_line_count",
            "class_name",
            "method_name",
            "method_descriptor",
            "symbol_name",
            "start_line",
            "end_line",
            "start_offset",
            "end_offset",
            "excerpt",
            "excerpt_sha256",
            "locator",
            "confidence",
            "is_primary",
            "provenance",
            "source_lines_available",
            "unavailable_reason",
            "created_at",
        ]
        read_only_fields = fields


class RiskScoreSerializer(serializers.ModelSerializer):
    class Meta:
        model = RiskScore
        fields = ["id", "audit", "score", "severity", "created_at"]
        read_only_fields = fields


class ComplianceScoreSerializer(serializers.ModelSerializer):
    class Meta:
        model = ComplianceScore
        fields = ["id", "audit", "standard", "score", "created_at"]
        read_only_fields = fields


class ReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = Report
        fields = ["id", "audit", "report_type", "storage_reference", "created_at"]
        read_only_fields = fields


class RuleEvaluationSerializer(serializers.ModelSerializer):
    class Meta:
        model = RuleEvaluation
        fields = [
            "id",
            "audit",
            "framework",
            "rule_id",
            "result",
            "severity",
            "confidence",
            "title",
            "mapping_data",
            "evidence_summary",
            "remediation",
            "requires_manual_validation",
            "evaluator_version",
            "created_at",
            "updated_at",
        ]
        read_only_fields = fields
