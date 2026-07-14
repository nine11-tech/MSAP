from rest_framework import serializers

from apps.apk_files.models import APKFile
from apps.audits.models import Audit
from apps.evidence.models import Evidence
from apps.findings.models import Finding
from apps.indicators.models import SuspiciousIndicator
from apps.projects.models import Project
from apps.reports.models import Report
from apps.scoring.models import ComplianceScore, RiskScore
from apps.storage.models import ObjectStorageReference


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
            "created_at",
        ]
        read_only_fields = ["id", "created_at"]


class FindingSerializer(serializers.ModelSerializer):
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
            "recommendation",
            "created_at",
        ]
        read_only_fields = fields


class SuspiciousIndicatorSerializer(serializers.ModelSerializer):
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
