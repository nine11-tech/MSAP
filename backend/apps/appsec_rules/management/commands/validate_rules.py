from pathlib import Path

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError

from apps.appsec_rules.services.rule_loader import load_masvs_rules
from apps.triage_rules.services.triage_rule_loader import load_attck_triage_rules


class Command(BaseCommand):
    help = "Validate MSAP MASVS and ATT&CK Mobile YAML rule catalogs."

    def handle(self, *args, **options):
        rules_dir = Path(settings.PROJECT_ROOT) / "rules"
        masvs_path = rules_dir / "masvs_static_rules.yaml"
        attck_path = rules_dir / "attck_mobile_triage_rules.yaml"

        try:
            masvs_rules = load_masvs_rules(masvs_path)
            attck_rules = load_attck_triage_rules(attck_path)
        except ValidationError as exc:
            raise CommandError(f"Rule validation failed: {exc}") from exc

        self.stdout.write(f"MASVS rules: {len(masvs_rules)}")
        self.stdout.write(f"ATT&CK Mobile indicators: {len(attck_rules)}")
        self.stdout.write(self.style.SUCCESS("MSAP rule catalogs are valid."))

