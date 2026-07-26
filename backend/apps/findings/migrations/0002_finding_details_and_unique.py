from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("findings", "0001_initial")]
    operations = [
        migrations.AddField(model_name="finding", name="description", field=models.TextField(blank=True)),
        migrations.AddField(model_name="finding", name="mapping_data", field=models.JSONField(blank=True, default=dict)),
        migrations.AddField(model_name="finding", name="false_positive_guidance", field=models.TextField(blank=True)),
        migrations.AddField(model_name="finding", name="requires_manual_validation", field=models.BooleanField(default=False)),
        migrations.AddField(model_name="finding", name="status", field=models.CharField(default="OPEN", max_length=32)),
        migrations.AddConstraint(model_name="finding", constraint=models.UniqueConstraint(fields=("audit", "rule_id"), name="unique_finding_per_audit_rule")),
    ]
