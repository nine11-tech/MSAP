from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("dynamic_analysis", "0012_agent_adaptive_execution"),
    ]

    operations = [
        migrations.AlterField(
            model_name="agentrun",
            name="assessment_plan",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="execution_runs",
                to="dynamic_analysis.assessmentplan",
            ),
        ),
        migrations.AlterField(
            model_name="agentrun",
            name="failure_category",
            field=models.CharField(
                blank=True,
                choices=[
                    ("HOST_AGENT_UNAVAILABLE", "Host agent unavailable"),
                    ("RUNTIME_UNAVAILABLE", "Runtime unavailable"),
                    ("AI_PROVIDER_FAILURE", "AI provider failure"),
                    ("AI_DECISION_REJECTED", "AI decision rejected"),
                    ("TOOL_EXECUTION_FAILED", "Tool execution failed"),
                    ("TIMEOUT", "Timeout"),
                    ("INTERNAL_ERROR", "Internal error"),
                ],
                max_length=64,
            ),
        ),
    ]
