from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("audits", "0001_initial"),
        ("findings", "0001_initial"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("dynamic_analysis", "0023_openaicallbudget_correlation_call_count_and_more"),
    ]

    operations = [
        migrations.CreateModel(
            name="FridaScriptProposal",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("title", models.CharField(max_length=200)),
                ("rationale", models.CharField(max_length=1000)),
                ("expected_evidence", models.JSONField(blank=True, default=list)),
                ("source_identifier", models.CharField(blank=True, max_length=128, unique=True)),
                ("source_sha256", models.CharField(max_length=64)),
                ("source_code", models.TextField()),
                ("source_size_bytes", models.PositiveIntegerField(default=0)),
                ("generator_provider", models.CharField(max_length=32)),
                ("generator_model", models.CharField(blank=True, max_length=128)),
                ("provider_metadata", models.JSONField(blank=True, default=dict)),
                ("validation_warnings", models.JSONField(blank=True, default=list)),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("GENERATED", "Generated"),
                            ("APPROVED", "Approved"),
                            ("REJECTED", "Rejected"),
                            ("EXECUTED", "Executed"),
                            ("FAILED", "Failed"),
                        ],
                        default="GENERATED",
                        max_length=16,
                    ),
                ),
                ("approved_at", models.DateTimeField(blank=True, null=True)),
                ("executed_at", models.DateTimeField(blank=True, null=True)),
                ("last_error", models.CharField(blank=True, max_length=1000)),
                ("suggested_fix", models.CharField(blank=True, max_length=1000)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "approved_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="approved_frida_script_proposals",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "audit",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="frida_script_proposals",
                        to="audits.audit",
                    ),
                ),
                (
                    "created_by",
                    models.ForeignKey(
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="created_frida_script_proposals",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "finding",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="frida_script_proposals",
                        to="findings.finding",
                    ),
                ),
                (
                    "hypothesis",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="frida_script_proposals",
                        to="dynamic_analysis.agenthypothesis",
                    ),
                ),
                (
                    "mission",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="frida_script_proposals",
                        to="dynamic_analysis.findingvalidationmission",
                    ),
                ),
                (
                    "run",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="frida_script_proposals",
                        to="dynamic_analysis.agentrun",
                    ),
                ),
            ],
            options={
                "ordering": ["-created_at"],
                "indexes": [
                    models.Index(fields=["run", "status", "created_at"], name="dynamic_ana_run_id_e1960d_idx"),
                    models.Index(fields=["audit", "status", "created_at"], name="dynamic_ana_audit_i_209a6f_idx"),
                ],
            },
        ),
        migrations.AlterField(
            model_name="openaicallbudget",
            name="max_adaptive_decision_calls",
            field=models.PositiveIntegerField(default=12),
        ),
        migrations.AlterField(
            model_name="openaicallbudget",
            name="max_total_openai_calls",
            field=models.PositiveIntegerField(default=50),
        ),
    ]
