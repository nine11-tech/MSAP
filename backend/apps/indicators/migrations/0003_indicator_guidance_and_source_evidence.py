from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("indicators", "0002_indicator_details_and_unique")]

    operations = [
        migrations.AddField(
            model_name="suspiciousindicator",
            name="auditor_explanation",
            field=models.TextField(blank=True),
        ),
        migrations.AddField(
            model_name="suspiciousindicator",
            name="dynamic_verification_scenario",
            field=models.TextField(blank=True),
        ),
        migrations.AddField(
            model_name="suspiciousindicator",
            name="source_evidence",
            field=models.JSONField(blank=True, default=list),
        ),
    ]
