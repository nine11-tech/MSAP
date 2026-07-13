from django.db import models


class Report(models.Model):
    class ReportType(models.TextChoices):
        JSON = "json", "JSON"
        PDF = "pdf", "PDF"

    audit = models.ForeignKey(
        "audits.Audit",
        on_delete=models.CASCADE,
        related_name="reports",
    )
    report_type = models.CharField(
        max_length=32,
        choices=ReportType.choices,
        default=ReportType.JSON,
    )
    storage_reference = models.ForeignKey(
        "storage.ObjectStorageReference",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="reports",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.report_type} report for audit {self.audit_id}"

