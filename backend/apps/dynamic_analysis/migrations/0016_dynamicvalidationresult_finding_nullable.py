from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("dynamic_analysis", "0015_runtime_playbook_capabilities")]
    operations = [migrations.AlterField(
        model_name="dynamicvalidationresult",
        name="finding",
        field=models.ForeignKey(blank=True, null=True, on_delete=models.deletion.CASCADE, related_name="dynamic_validation_results", to="findings.finding"),
    )]
