from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("indicators", "0001_initial")]
    operations = [
        migrations.AddField(model_name="suspiciousindicator", name="mapping_rationale", field=models.TextField(blank=True)),
        migrations.AddField(model_name="suspiciousindicator", name="false_positive_considerations", field=models.TextField(blank=True)),
        migrations.AddField(model_name="suspiciousindicator", name="requires_manual_validation", field=models.BooleanField(default=True)),
        migrations.AddField(model_name="suspiciousindicator", name="non_malware_verdict_note", field=models.TextField(default="Triage signal — not a malware verdict.")),
        migrations.AddConstraint(model_name="suspiciousindicator", constraint=models.UniqueConstraint(fields=("audit", "indicator_id"), name="unique_indicator_per_audit_rule")),
    ]
