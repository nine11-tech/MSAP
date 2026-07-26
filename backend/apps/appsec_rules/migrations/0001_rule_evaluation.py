from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    initial = True
    dependencies = [("audits", "0003_analysisjob_result_summary")]
    operations = [
        migrations.CreateModel(
            name="RuleEvaluation",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("framework", models.CharField(choices=[("MASVS", "OWASP MASVS"), ("ATTACK_MOBILE", "MITRE ATT&CK Mobile")], max_length=32)),
                ("rule_id", models.CharField(max_length=128)),
                ("result", models.CharField(choices=[("PASS", "Pass"), ("FAIL", "Fail"), ("REVIEW_REQUIRED", "Review required"), ("NOT_APPLICABLE", "Not applicable"), ("NOT_EVALUATED", "Not evaluated")], max_length=32)),
                ("severity", models.CharField(max_length=32)),
                ("confidence", models.CharField(choices=[("HIGH", "High"), ("MEDIUM", "Medium"), ("LOW", "Low")], max_length=16)),
                ("title", models.CharField(max_length=255)),
                ("mapping_data", models.JSONField(blank=True, default=dict)),
                ("evidence_summary", models.TextField(blank=True)),
                ("remediation", models.TextField(blank=True)),
                ("requires_manual_validation", models.BooleanField(default=False)),
                ("evaluator_version", models.CharField(max_length=64)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("audit", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="rule_evaluations", to="audits.audit")),
            ],
            options={"ordering": ["framework", "rule_id"]},
        ),
        migrations.AddConstraint(
            model_name="ruleevaluation",
            constraint=models.UniqueConstraint(fields=("audit", "framework", "rule_id"), name="unique_audit_framework_rule_evaluation"),
        ),
        migrations.AddIndex(
            model_name="ruleevaluation",
            index=models.Index(fields=["audit", "framework", "result"], name="appsec_rule_audit_i_5777a2_idx"),
        ),
    ]
