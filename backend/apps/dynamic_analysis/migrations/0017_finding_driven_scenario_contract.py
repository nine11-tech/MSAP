from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("dynamic_analysis", "0016_dynamicvalidationresult_finding_nullable"),
        ("findings", "0002_finding_details_and_unique"),
    ]

    operations = [
        migrations.AddField(
            model_name="dynamicvalidationresult",
            name="scenario_id",
            field=models.CharField(blank=True, max_length=128),
        ),
        migrations.AddField(
            model_name="assessmentplan",
            name="source_finding",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="dynamic_validation_plans",
                to="findings.finding",
            ),
        ),
        migrations.AddField(
            model_name="assessmentplan",
            name="scenario_contract",
            field=models.JSONField(blank=True, default=dict),
        ),
    ]
