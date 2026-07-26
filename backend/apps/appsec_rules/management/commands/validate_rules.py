from pathlib import Path

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError
import yaml

from apps.appsec_rules.services.rule_loader import load_masvs_rules
from apps.triage_rules.services.triage_rule_loader import load_attck_triage_rules


class Command(BaseCommand):
    help = "Validate MSAP MASVS and ATT&CK Mobile YAML rule catalogs."

    def handle(self, *args, **options):
        rules_dir = Path(settings.PROJECT_ROOT) / "rules"
        masvs_path = rules_dir / "masvs_static_rules.yaml"
        attck_path = rules_dir / "attck_mobile_triage_rules.yaml"
        metadata_path = rules_dir / "framework_metadata.yaml"

        try:
            masvs_rules = load_masvs_rules(masvs_path)
            attck_rules = load_attck_triage_rules(attck_path)
            with metadata_path.open("r", encoding="utf-8") as handle:
                metadata = yaml.safe_load(handle) or {}
            frameworks = metadata.get("frameworks")
            if not isinstance(frameworks, list) or not frameworks:
                raise ValidationError("Framework metadata must contain a non-empty frameworks list.")
            required = {
                "name",
                "short_name",
                "source",
                "snapshot_date",
                "applicable_platform",
                "catalog_version",
                "updater_notes",
            }
            for framework in frameworks:
                missing = sorted(field for field in required if not framework.get(field))
                if missing:
                    raise ValidationError(
                        f"Framework metadata {framework.get('short_name', 'unknown')} is missing: "
                        f"{', '.join(missing)}"
                    )
        except ValidationError as exc:
            raise CommandError(f"Rule validation failed: {exc}") from exc
        except (OSError, yaml.YAMLError) as exc:
            raise CommandError(f"Framework metadata validation failed: {exc}") from exc

        self.stdout.write(f"MASVS rules: {len(masvs_rules)}")
        self.stdout.write(f"ATT&CK Mobile indicators: {len(attck_rules)}")
        self.stdout.write(f"Framework metadata records: {len(frameworks)}")
        self.stdout.write(self.style.SUCCESS("MSAP rule catalogs are valid."))
