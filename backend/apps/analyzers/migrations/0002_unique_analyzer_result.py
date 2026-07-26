from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("analyzers", "0001_initial")]
    operations = [
        migrations.AddConstraint(
            model_name="rawanalyzerresult",
            constraint=models.UniqueConstraint(
                fields=("audit", "apk_file", "analyzer_name"),
                name="unique_raw_analyzer_result",
            ),
        )
    ]
