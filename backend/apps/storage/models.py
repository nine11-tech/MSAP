from django.db import models


class ObjectStorageReference(models.Model):
    class ObjectType(models.TextChoices):
        APK_UPLOAD = "APK_UPLOAD", "APK upload"
        EXTRACTED_MANIFEST = "EXTRACTED_MANIFEST", "Extracted manifest"
        EXTRACTED_RESOURCE = "EXTRACTED_RESOURCE", "Extracted resource"
        DECOMPILED_CODE_ARCHIVE = "DECOMPILED_CODE_ARCHIVE", "Decompiled code archive"
        RAW_ANALYZER_RESULT = "RAW_ANALYZER_RESULT", "Raw analyzer result"
        NORMALIZED_ARTIFACT = "NORMALIZED_ARTIFACT", "Normalized artifact"
        EVIDENCE_SNIPPET = "EVIDENCE_SNIPPET", "Evidence snippet"
        PDF_REPORT = "PDF_REPORT", "PDF report"
        JSON_EXPORT = "JSON_EXPORT", "JSON export"
        AI_REDACTED_CONTEXT = "AI_REDACTED_CONTEXT", "AI redacted context"

    class RetentionPolicy(models.TextChoices):
        ACTIVE_AUDIT = "active_audit", "Active audit"
        TEMPORARY = "temporary", "Temporary"
        ARCHIVE = "archive", "Archive"
        EXPORT = "export", "Export"

    class EncryptionStatus(models.TextChoices):
        UNKNOWN = "unknown", "Unknown"
        EXPECTED = "expected", "Expected"
        VERIFIED = "verified", "Verified"

    class RedactionStatus(models.TextChoices):
        NOT_REQUIRED = "not_required", "Not required"
        PENDING = "pending", "Pending"
        REDACTED = "redacted", "Redacted"
        BLOCKED = "blocked", "Blocked"

    class AccessScope(models.TextChoices):
        PROJECT = "project", "Project"
        AUDIT = "audit", "Audit"
        WORKER_INTERNAL = "worker_internal", "Worker internal"
        EXPORT = "export", "Export"

    bucket = models.CharField(max_length=255)
    object_key = models.CharField(max_length=1024)
    object_type = models.CharField(max_length=64, choices=ObjectType.choices)
    content_type = models.CharField(max_length=255, blank=True)
    size_bytes = models.BigIntegerField(null=True, blank=True)
    sha256 = models.CharField(max_length=64, blank=True)
    audit = models.ForeignKey(
        "audits.Audit",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="object_references",
    )
    project = models.ForeignKey(
        "projects.Project",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="object_references",
    )
    retention_policy = models.CharField(
        max_length=32,
        choices=RetentionPolicy.choices,
        default=RetentionPolicy.ACTIVE_AUDIT,
    )
    encryption_status = models.CharField(
        max_length=32,
        choices=EncryptionStatus.choices,
        default=EncryptionStatus.UNKNOWN,
    )
    redaction_status = models.CharField(
        max_length=32,
        choices=RedactionStatus.choices,
        default=RedactionStatus.NOT_REQUIRED,
    )
    access_scope = models.CharField(
        max_length=32,
        choices=AccessScope.choices,
        default=AccessScope.AUDIT,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["bucket", "object_key"]),
            models.Index(fields=["object_type"]),
            models.Index(fields=["sha256"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["bucket", "object_key"],
                name="unique_object_storage_reference",
            )
        ]

    def __str__(self) -> str:
        return f"{self.bucket}/{self.object_key}"

