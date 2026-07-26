from django.db import models


class Finding(models.Model):
    audit = models.ForeignKey(
        "audits.Audit",
        on_delete=models.CASCADE,
        related_name="findings",
    )
    rule_id = models.CharField(max_length=128)
    title = models.CharField(max_length=255)
    severity = models.CharField(max_length=32)
    confidence = models.CharField(max_length=32)
    standard = models.CharField(max_length=128)
    category = models.CharField(max_length=128, blank=True)
    description = models.TextField(blank=True)
    mapping_data = models.JSONField(default=dict, blank=True)
    recommendation = models.TextField(blank=True)
    false_positive_guidance = models.TextField(blank=True)
    requires_manual_validation = models.BooleanField(default=False)
    status = models.CharField(max_length=32, default="OPEN")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["audit", "rule_id"],
                name="unique_finding_per_audit_rule",
            )
        ]

    def __str__(self) -> str:
        return f"{self.rule_id}: {self.title}"
