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
    evidence_type = models.CharField(max_length=128)
    source = models.CharField(max_length=255)
    snippet = models.TextField(blank=True)
    redacted = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.evidence_type} evidence for audit {self.audit_id}"

