from django.db import models


class RuleEvaluation(models.Model):
    class Framework(models.TextChoices):
        MASVS = "MASVS", "OWASP MASVS"
        ATTACK_MOBILE = "ATTACK_MOBILE", "MITRE ATT&CK Mobile"

    class Result(models.TextChoices):
        PASS = "PASS", "Pass"
        FAIL = "FAIL", "Fail"
        REVIEW_REQUIRED = "REVIEW_REQUIRED", "Review required"
        NOT_APPLICABLE = "NOT_APPLICABLE", "Not applicable"
        NOT_EVALUATED = "NOT_EVALUATED", "Not evaluated"

    class Confidence(models.TextChoices):
        HIGH = "HIGH", "High"
        MEDIUM = "MEDIUM", "Medium"
        LOW = "LOW", "Low"

    audit = models.ForeignKey(
        "audits.Audit",
        on_delete=models.CASCADE,
        related_name="rule_evaluations",
    )
    framework = models.CharField(max_length=32, choices=Framework.choices)
    rule_id = models.CharField(max_length=128)
    result = models.CharField(max_length=32, choices=Result.choices)
    severity = models.CharField(max_length=32)
    confidence = models.CharField(max_length=16, choices=Confidence.choices)
    title = models.CharField(max_length=255)
    mapping_data = models.JSONField(default=dict, blank=True)
    evidence_summary = models.TextField(blank=True)
    remediation = models.TextField(blank=True)
    requires_manual_validation = models.BooleanField(default=False)
    evaluator_version = models.CharField(max_length=64)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["framework", "rule_id"]
        constraints = [
            models.UniqueConstraint(
                fields=["audit", "framework", "rule_id"],
                name="unique_audit_framework_rule_evaluation",
            )
        ]
        indexes = [
            models.Index(
                fields=["audit", "framework", "result"],
                name="appsec_rule_audit_i_5777a2_idx",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.framework}:{self.rule_id}={self.result}"
