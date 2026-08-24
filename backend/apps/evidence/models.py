import re
import json
from hashlib import sha256
from pathlib import PurePosixPath

from django.core.exceptions import ValidationError
from django.db import models


class Evidence(models.Model):
    audit = models.ForeignKey(
        "audits.Audit",
        on_delete=models.CASCADE,
        related_name="evidence",
    )
    finding = models.ForeignKey(
        "findings.Finding",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="evidence",
    )
    indicator = models.ForeignKey(
        "indicators.SuspiciousIndicator",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="evidence",
    )
    storage_reference = models.ForeignKey(
        "storage.ObjectStorageReference",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="evidence",
    )
    agent_run = models.ForeignKey(
        "dynamic_analysis.AgentRun",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="evidence_records",
    )
    agent_run_step = models.ForeignKey(
        "dynamic_analysis.AgentRunStep",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="evidence_records",
    )
    agent_run_artifact = models.ForeignKey(
        "dynamic_analysis.AgentRunArtifact",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="evidence_records",
    )
    evidence_type = models.CharField(max_length=128)
    source = models.CharField(max_length=255)
    snippet = models.TextField(blank=True)
    ai_explanation = models.TextField(blank=True)
    ai_conclusion = models.TextField(blank=True)
    ai_security_impact = models.TextField(blank=True)
    ai_evidence_strength = models.CharField(max_length=32, blank=True)
    ai_explanation_status = models.CharField(max_length=32, blank=True)
    ai_explanation_provider = models.CharField(max_length=32, blank=True)
    ai_explanation_model = models.CharField(max_length=128, blank=True)
    ai_explanation_metadata = models.JSONField(default=dict, blank=True)
    redacted = models.BooleanField(default=False)
    sha256 = models.CharField(max_length=64, blank=True)
    provenance = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.evidence_type} evidence for audit {self.audit_id}"


def _validate_logical_path(value: str) -> None:
    path = PurePosixPath(value)
    if not value or path.is_absolute() or ".." in path.parts or "\\" in value:
        raise ValidationError("logical_path must be a safe relative POSIX path.")


def _validate_sha256(value: str, field_name: str) -> None:
    if value and not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValidationError({field_name: "Must be a lowercase SHA-256 digest."})


class SourceDocument(models.Model):
    class RepresentationType(models.TextChoices):
        JADX_SOURCE = "JADX_SOURCE", "JADX decompiled source"
        JADX_JAVA = "JADX_JAVA", "JADX decompiled Java"
        JADX_KOTLIN = "JADX_KOTLIN", "JADX decompiled Kotlin"
        SMALI = "SMALI", "Smali representation"
        DEX_DISASSEMBLY = "DEX_DISASSEMBLY", "DEX disassembly"
        DEX_METADATA = "DEX_METADATA", "DEX metadata"
        MANIFEST_XML = "MANIFEST_XML", "Decoded AndroidManifest.xml"
        RESOURCE_XML = "RESOURCE_XML", "Decoded resource XML"
        NETWORK_SECURITY_XML = (
            "NETWORK_SECURITY_XML",
            "Decoded network security XML",
        )
        NATIVE_SYMBOL = "NATIVE_SYMBOL", "Native binary/symbol metadata"
        APK_SIGNING_METADATA = "APK_SIGNING_METADATA", "APK signing metadata"
        CERTIFICATE_METADATA = "CERTIFICATE_METADATA", "Certificate metadata"
        OTHER_TEXT = "OTHER_TEXT", "Other generated text"

    audit = models.ForeignKey(
        "audits.Audit",
        on_delete=models.CASCADE,
        related_name="source_documents",
    )
    apk_file = models.ForeignKey(
        "apk_files.APKFile",
        on_delete=models.CASCADE,
        related_name="source_documents",
    )
    representation_type = models.CharField(
        max_length=64,
        choices=RepresentationType.choices,
    )
    logical_path = models.CharField(max_length=1024)
    display_path = models.CharField(max_length=1024)
    language = models.CharField(max_length=64, blank=True)
    class_name = models.CharField(max_length=512, blank=True)
    package_name = models.CharField(max_length=512, blank=True)
    sha256 = models.CharField(max_length=64)
    line_count = models.PositiveIntegerField(default=0)
    generated_by = models.CharField(max_length=255)
    tool_version = models.CharField(max_length=128, blank=True)
    storage_reference = models.ForeignKey(
        "storage.ObjectStorageReference",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="source_documents",
    )
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["logical_path", "id"]
        indexes = [
            models.Index(fields=["audit", "apk_file"]),
            models.Index(fields=["representation_type", "logical_path"]),
            models.Index(fields=["sha256"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=[
                    "audit",
                    "apk_file",
                    "representation_type",
                    "logical_path",
                ],
                name="unique_source_document_path",
            )
        ]

    def clean(self) -> None:
        super().clean()
        _validate_logical_path(self.logical_path)
        _validate_sha256(self.sha256, "sha256")
        if self.apk_file_id and self.audit_id:
            apk_audit_id = getattr(self.apk_file, "audit_id", None)
            if apk_audit_id is not None and apk_audit_id != self.audit_id:
                raise ValidationError("Source document APK must belong to its audit.")
        if self.storage_reference_id and self.audit_id:
            reference_audit_id = getattr(self.storage_reference, "audit_id", None)
            if reference_audit_id not in {None, self.audit_id}:
                raise ValidationError(
                    "Source document storage reference must belong to its audit."
                )

    def __str__(self) -> str:
        return f"{self.get_representation_type_display()}: {self.logical_path}"


class FindingSourceReference(models.Model):
    class Confidence(models.TextChoices):
        HIGH = "HIGH", "High"
        MEDIUM = "MEDIUM", "Medium"
        LOW = "LOW", "Low"

    finding = models.ForeignKey(
        "findings.Finding",
        on_delete=models.CASCADE,
        related_name="source_references",
    )
    source_document = models.ForeignKey(
        SourceDocument,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="finding_references",
    )
    representation_type = models.CharField(
        max_length=64,
        choices=SourceDocument.RepresentationType.choices,
    )
    logical_path = models.CharField(max_length=1024)
    class_name = models.CharField(max_length=512, blank=True)
    method_name = models.CharField(max_length=512, blank=True)
    method_descriptor = models.CharField(max_length=1024, blank=True)
    symbol_name = models.CharField(max_length=1024, blank=True)
    start_line = models.PositiveIntegerField(null=True, blank=True)
    end_line = models.PositiveIntegerField(null=True, blank=True)
    start_offset = models.BigIntegerField(null=True, blank=True)
    end_offset = models.BigIntegerField(null=True, blank=True)
    excerpt = models.TextField(blank=True)
    excerpt_sha256 = models.CharField(max_length=64, blank=True)
    locator = models.JSONField(default=dict, blank=True)
    confidence = models.CharField(
        max_length=16,
        choices=Confidence.choices,
        default=Confidence.MEDIUM,
    )
    is_primary = models.BooleanField(default=False)
    provenance = models.TextField()
    source_lines_available = models.BooleanField(default=True)
    unavailable_reason = models.TextField(blank=True)
    reference_fingerprint = models.CharField(max_length=64, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    MAX_EXCERPT_LINES = 30
    MAX_EXCERPT_CHARS = 12_000

    class Meta:
        ordering = ["-is_primary", "id"]
        indexes = [
            models.Index(fields=["finding", "is_primary"]),
            models.Index(fields=["source_document", "start_line"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["finding", "reference_fingerprint"],
                name="unique_finding_source_fingerprint",
            )
        ]

    def clean(self) -> None:
        super().clean()
        self.reference_fingerprint = self._build_fingerprint()
        _validate_logical_path(self.logical_path)
        _validate_sha256(self.excerpt_sha256, "excerpt_sha256")
        if self.source_document_id:
            document = self.source_document
            if document.representation_type != self.representation_type:
                raise ValidationError(
                    "Reference representation must match its source document."
                )
            if self.finding_id and document.audit_id != self.finding.audit_id:
                raise ValidationError(
                    "Finding and source document must belong to the same audit."
                )
        if self.source_lines_available:
            if not self.source_document_id:
                raise ValidationError(
                    "Line-based evidence requires a source document."
                )
            if self.start_line is None or self.end_line is None:
                raise ValidationError("Line-based evidence requires a line range.")
            if self.start_line > self.end_line:
                raise ValidationError("start_line cannot exceed end_line.")
            if self.source_document_id and self.end_line > self.source_document.line_count:
                raise ValidationError("Line range exceeds the source document.")
            if not self.excerpt:
                raise ValidationError("Line-based evidence requires an excerpt.")
            if not self.excerpt_sha256:
                raise ValidationError("Line-based evidence requires an excerpt SHA-256.")
        else:
            if any(value is not None for value in (self.start_line, self.end_line)):
                raise ValidationError(
                    "Non-line evidence cannot claim a source line range."
                )
            if self.excerpt:
                raise ValidationError("Non-line evidence cannot contain a source excerpt.")
            if not self.unavailable_reason.strip():
                raise ValidationError(
                    "Non-line evidence requires an explicit unavailable reason."
                )
        if len(self.excerpt) > self.MAX_EXCERPT_CHARS:
            raise ValidationError("Source excerpt exceeds the character limit.")
        if self.excerpt and len(self.excerpt.splitlines()) > self.MAX_EXCERPT_LINES:
            raise ValidationError("Source excerpt exceeds the line limit.")

    def _build_fingerprint(self) -> str:
        payload = {
            "source_document_id": self.source_document_id,
            "representation_type": self.representation_type,
            "logical_path": self.logical_path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "start_offset": self.start_offset,
            "end_offset": self.end_offset,
            "symbol_name": self.symbol_name,
        }
        return sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

    def save(self, *args, **kwargs):
        self.reference_fingerprint = self._build_fingerprint()
        return super().save(*args, **kwargs)

    def __str__(self) -> str:
        location = (
            f"L{self.start_line}-L{self.end_line}"
            if self.source_lines_available
            else "non-line evidence"
        )
        return f"{self.finding.rule_id}: {self.logical_path} {location}"
