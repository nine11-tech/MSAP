from django.db import models


class RawAnalyzerResult(models.Model):
    class Status(models.TextChoices):
        PENDING = "PENDING", "Pending"
        RUNNING = "RUNNING", "Running"
        COMPLETED = "COMPLETED", "Completed"
        FAILED = "FAILED", "Failed"
        SKIPPED = "SKIPPED", "Skipped"

    audit = models.ForeignKey(
        "audits.Audit",
        on_delete=models.CASCADE,
        related_name="raw_analyzer_results",
    )
    apk_file = models.ForeignKey(
        "apk_files.APKFile",
        on_delete=models.CASCADE,
        related_name="raw_analyzer_results",
    )
    analyzer_name = models.CharField(max_length=128)
    analyzer_version = models.CharField(max_length=64)
    status = models.CharField(
        max_length=32,
        choices=Status.choices,
        default=Status.PENDING,
    )
    storage_reference = models.ForeignKey(
        "storage.ObjectStorageReference",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="raw_analyzer_results",
    )
    result_summary = models.JSONField(default=dict, blank=True)
    error_message = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["audit", "apk_file"]),
            models.Index(fields=["analyzer_name", "status"]),
        ]

    def __str__(self) -> str:
        return f"{self.analyzer_name} result for audit {self.audit_id}"

