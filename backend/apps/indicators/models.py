from django.db import models


class SuspiciousIndicator(models.Model):
    audit = models.ForeignKey(
        "audits.Audit",
        on_delete=models.CASCADE,
        related_name="indicators",
    )
    indicator_id = models.CharField(max_length=128)
    title = models.CharField(max_length=255)
    tactic = models.CharField(max_length=128, blank=True)
    technique_id = models.CharField(max_length=64, blank=True)
    technique_name = models.CharField(max_length=255, blank=True)
    severity = models.CharField(max_length=32)
    confidence = models.CharField(max_length=32)
    triage_interpretation = models.TextField(blank=True)
    auditor_explanation = models.TextField(blank=True)
    dynamic_verification_scenario = models.TextField(blank=True)
    source_evidence = models.JSONField(default=list, blank=True)
    mapping_rationale = models.TextField(blank=True)
    false_positive_considerations = models.TextField(blank=True)
    requires_manual_validation = models.BooleanField(default=True)
    non_malware_verdict_note = models.TextField(
        default="Triage signal — not a malware verdict."
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["audit", "indicator_id"],
                name="unique_indicator_per_audit_rule",
            )
        ]

    def __str__(self) -> str:
        return f"{self.indicator_id}: {self.title}"
