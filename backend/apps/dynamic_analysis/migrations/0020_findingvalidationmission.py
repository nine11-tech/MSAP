from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("apk_files", "0001_initial"),
        ("audits", "0003_analysisjob_result_summary"),
        ("dynamic_analysis", "0019_add_root_demo_reset_capability"),
        ("evidence", "0003_evidence_agent_run_evidence_agent_run_artifact_and_more"),
        ("findings", "0002_finding_details_and_unique"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="FindingValidationMission",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("target_package", models.CharField(max_length=255)),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("DRAFT", "Draft"),
                            ("GENERATED", "Generated"),
                            ("VALIDATED", "Validated"),
                            ("APPROVED", "Approved"),
                            ("RUNNING", "Running"),
                            ("CONFIRMED", "Confirmed"),
                            ("NOT_REPRODUCED", "Not reproduced"),
                            ("INCONCLUSIVE", "Inconclusive"),
                            ("BLOCKED", "Blocked"),
                            (
                                "NOT_DYNAMICALLY_TESTABLE",
                                "Not dynamically testable",
                            ),
                            ("FAILED", "Failed"),
                        ],
                        default="DRAFT",
                        max_length=32,
                    ),
                ),
                ("scenario_contract", models.JSONField(blank=True, default=dict)),
                ("scenario_hash", models.CharField(blank=True, max_length=64)),
                ("mission_hash", models.CharField(blank=True, max_length=64)),
                ("validation_family", models.CharField(blank=True, max_length=64)),
                ("playbook_id", models.CharField(blank=True, max_length=128)),
                ("hypothesis", models.TextField(blank=True)),
                ("final_conclusion", models.TextField(blank=True)),
                ("limitations", models.TextField(blank=True)),
                ("oracle_result", models.JSONField(blank=True, default=dict)),
                ("provider", models.CharField(blank=True, max_length=32)),
                ("model", models.CharField(blank=True, max_length=128)),
                ("provider_metadata", models.JSONField(blank=True, default=dict)),
                ("allowed_capabilities", models.JSONField(blank=True, default=list)),
                ("budgets", models.JSONField(blank=True, default=dict)),
                ("approved_at", models.DateTimeField(blank=True, null=True)),
                ("started_at", models.DateTimeField(blank=True, null=True)),
                ("completed_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "agent_run",
                    models.OneToOneField(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="finding_validation_mission",
                        to="dynamic_analysis.agentrun",
                    ),
                ),
                (
                    "apk",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="finding_validation_missions",
                        to="apk_files.apkfile",
                    ),
                ),
                (
                    "approved_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="approved_finding_validation_missions",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "assessment_plan",
                    models.OneToOneField(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="finding_validation_mission",
                        to="dynamic_analysis.assessmentplan",
                    ),
                ),
                (
                    "audit",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="finding_validation_missions",
                        to="audits.audit",
                    ),
                ),
                (
                    "created_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="created_finding_validation_missions",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "dynamic_validation_result",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="missions",
                        to="dynamic_analysis.dynamicvalidationresult",
                    ),
                ),
                (
                    "evidence",
                    models.ManyToManyField(
                        blank=True,
                        related_name="finding_validation_missions",
                        to="evidence.evidence",
                    ),
                ),
                (
                    "finding",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="validation_missions",
                        to="findings.finding",
                    ),
                ),
            ],
            options={
                "ordering": ["-created_at"],
            },
        ),
        migrations.AddIndex(
            model_name="findingvalidationmission",
            index=models.Index(fields=["audit", "status"], name="dynamic_ana_audit_i_d96ca1_idx"),
        ),
        migrations.AddIndex(
            model_name="findingvalidationmission",
            index=models.Index(fields=["finding", "created_at"], name="dynamic_ana_finding_33e5d7_idx"),
        ),
        migrations.AddIndex(
            model_name="findingvalidationmission",
            index=models.Index(fields=["target_package", "status"], name="dynamic_ana_target__bc5c3a_idx"),
        ),
        migrations.AddIndex(
            model_name="findingvalidationmission",
            index=models.Index(fields=["scenario_hash"], name="dynamic_ana_scenari_7cf5b0_idx"),
        ),
    ]
