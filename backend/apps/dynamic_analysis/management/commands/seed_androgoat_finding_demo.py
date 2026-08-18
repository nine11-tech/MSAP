"""Seed the explicit AndroGoat finding used by the local validation demo.

This is a development fixture, never a production finding.  It represents a
finding emitted by a static analyzer for the known AndroGoat root-detection
control so the demo can exercise the real finding-driven workflow.
"""
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from apps.apk_files.models import APKFile
from apps.audits.models import Audit
from apps.findings.models import Finding


class Command(BaseCommand):
    help = "Seed the development-only AndroGoat root detection finding for the dynamic validation demo."

    def add_arguments(self, parser):
        parser.add_argument("--audit-id", type=int, required=True)
        parser.add_argument("--dev-fixture", action="store_true")

    def handle(self, *args, **options):
        if not settings.DEBUG or not options["dev_fixture"]:
            raise CommandError("This command requires DEBUG=true and --dev-fixture; it cannot seed production evidence.")
        try:
            audit = Audit.objects.get(pk=options["audit_id"])
        except Audit.DoesNotExist as exc:
            raise CommandError(f"Audit {options['audit_id']} does not exist.") from exc

        apk = APKFile.objects.filter(audit=audit).order_by("-created_at").first()
        if apk is None or apk.package_name != "owasp.sat.agoat":
            raise CommandError("The selected audit must contain an OWASP AndroGoat APK (owasp.sat.agoat).")

        finding, created = Finding.objects.update_or_create(
            audit=audit,
            rule_id="MSAP-AND-ROOT-DEMO-001",
            defaults={
                "title": "Root detection control identified in AndroGoat",
                "severity": "MEDIUM",
                "confidence": "HIGH",
                "standard": "MASVS",
                "category": "MASVS-RESILIENCE",
                "description": "Static analyzer fixture: AndroGoat contains a root-detection control whose runtime screen can be validated in the authorized emulator lab.",
                "mapping_data": {
                    "masvs_controls": ["MASVS-RESILIENCE-1"],
                    "fixture_only": True,
                    "provenance": "STATIC_ANALYZER_DEV_FIXTURE",
                    "evidence_summary": "AndroGoat root-detection control selected for the development acceptance demo.",
                    "affected_component": "Root detection activity/control",
                },
                "recommendation": "Retain root-detection resilience and verify behavior on approved rooted/emulator lab targets.",
                "requires_manual_validation": True,
                "status": "OPEN",
            },
        )
        self.stdout.write(self.style.SUCCESS(
            f"{'Created' if created else 'Updated'} AndroGoat demo finding {finding.id} for audit {audit.id}."
        ))
        self.stdout.write("STATIC_FINDING_DEMO_FIXTURE=PASS")
