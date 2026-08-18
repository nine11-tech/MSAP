from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("dynamic_analysis", "0017_finding_driven_scenario_contract")]

    operations = [
        migrations.AlterField(
            model_name="dynamicvalidationresult",
            name="validation_status",
            field=models.CharField(
                choices=[
                    ("NOT_STARTED", "Not started"),
                    ("SCENARIO_GENERATED", "Scenario generated"),
                    ("SCENARIO_VALIDATED", "Scenario validated"),
                    ("APPROVED", "Approved"),
                    ("RUNNING", "Running"),
                    ("SUPPORTED", "Supported"),
                    ("REJECTED", "Rejected"),
                    ("CONFIRMED", "Confirmed"),
                    ("REFUTED", "Refuted"),
                    ("INCONCLUSIVE", "Inconclusive"),
                    ("NOT_ASSESSABLE", "Not assessable"),
                    ("FAILED", "Failed"),
                    ("STATIC_ONLY", "Static only"),
                ],
                max_length=32,
            ),
        ),
    ]
