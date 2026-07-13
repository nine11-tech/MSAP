from django.db import models


class RiskScore(models.Model):
    audit = models.ForeignKey(
        "audits.Audit",
        on_delete=models.CASCADE,
        related_name="risk_scores",
    )
    score = models.DecimalField(max_digits=5, decimal_places=2)
    severity = models.CharField(max_length=32)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.audit_id}: {self.score} {self.severity}"


class ComplianceScore(models.Model):
    audit = models.ForeignKey(
        "audits.Audit",
        on_delete=models.CASCADE,
        related_name="compliance_scores",
    )
    standard = models.CharField(max_length=128)
    score = models.DecimalField(max_digits=5, decimal_places=2)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.audit_id}: {self.standard} {self.score}"

