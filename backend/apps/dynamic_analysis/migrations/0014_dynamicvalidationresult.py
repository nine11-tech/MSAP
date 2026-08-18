from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("dynamic_analysis", "0013_adaptive_pre_execution_retry"),
        ("findings", "0002_finding_details_and_unique"),
        ("evidence", "0003_evidence_agent_run_evidence_agent_run_artifact_and_more"),
    ]

    operations = [
        migrations.CreateModel(
            name="DynamicValidationResult",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("rule_id", models.CharField(max_length=128)),
                ("playbook_id", models.CharField(max_length=128)),
                ("oracle_id", models.CharField(max_length=128)),
                ("oracle_result", models.JSONField(blank=True, default=dict)),
                ("validation_status", models.CharField(choices=[("CONFIRMED", "Confirmed"), ("REFUTED", "Refuted"), ("INCONCLUSIVE", "Inconclusive"), ("NOT_ASSESSABLE", "Not assessable"), ("STATIC_ONLY", "Static only")], max_length=32)),
                ("confidence", models.FloatField(default=0.0)),
                ("safe_summary", models.CharField(max_length=1000)),
                ("limitations", models.TextField(blank=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("action_decision", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="dynamic_validation_results", to="dynamic_analysis.agentactiondecision")),
                ("agent_run", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="dynamic_validation_results", to="dynamic_analysis.agentrun")),
                ("audit", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="dynamic_validation_results", to="audits.audit")),
                ("evidence", models.ManyToManyField(blank=True, related_name="dynamic_validation_results", to="evidence.evidence")),
                ("finding", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="dynamic_validation_results", to="findings.finding")),
                ("hypothesis", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="dynamic_validation_results", to="dynamic_analysis.agenthypothesis")),
            ],
            options={"ordering": ["-created_at"], "indexes": [models.Index(fields=["audit", "validation_status"], name="dynamic_ana_audit_i_21aa5a_idx"), models.Index(fields=["finding", "playbook_id"], name="dynamic_ana_finding_a2f2af_idx")]},
        )
    ]
