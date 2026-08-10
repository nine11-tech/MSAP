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
    masvs_controls = serializers.SerializerMethodField()
    maswe_ids = serializers.SerializerMethodField()
    mastg_references = serializers.SerializerMethodField()
    source_reference_count = serializers.SerializerMethodField()

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
            "recommendation",
            "false_positive_guidance",
            "requires_manual_validation",
            "status",
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
            "evidence_type",
            "source",
            "snippet",
            "redacted",
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
