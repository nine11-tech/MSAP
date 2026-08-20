"""Seed the explicit AndroGoat finding used by the local validation demo.

This is a development fixture, never a production finding.  It represents a
finding emitted by a static analyzer for the known AndroGoat root-detection
control so the demo can exercise the real finding-driven workflow.
"""
import os

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.management.base import BaseCommand, CommandError

from apps.apk_files.models import APKFile
from apps.audits.models import Audit
from apps.api.roles import ANALYST_GROUP
from apps.findings.models import Finding
from apps.projects.models import Project


PROJECT_NAME = "MSAP AndroGoat Dynamic Validation Demo"
AUDIT_NAME = "AndroGoat Dynamic Validation Demo"
DEMO_USERNAME = "msap_demo_analyst"
TARGET_PACKAGE = "owasp.sat.agoat"
DEMO_RULE_ID = "MSAP-AND-ROOT-DEMO-001"


class Command(BaseCommand):
    help = "Seed the development-only AndroGoat root detection finding for the dynamic validation demo."

    def add_arguments(self, parser):
        parser.add_argument("--audit-id", type=int)
        parser.add_argument("--dev-fixture", action="store_true")
        parser.add_argument("--demo-username", default=DEMO_USERNAME)

    def handle(self, *args, **options):
        if not settings.DEBUG or not options["dev_fixture"]:
            raise CommandError("This command requires DEBUG=true and --dev-fixture; it cannot seed production evidence.")
        audit = self._get_or_create_audit(options.get("audit_id"))
        self._ensure_demo_user(options["demo_username"])

        apk = APKFile.objects.filter(audit=audit).order_by("-created_at").first()
        if apk is None or apk.package_name != TARGET_PACKAGE:
            apk = APKFile.objects.filter(audit=audit, package_name=TARGET_PACKAGE).first()
        if apk is None:
            apk = APKFile.objects.create(
                audit=audit,
                package_name=TARGET_PACKAGE,
                version_name="demo-authorized",
                sha256="",
                size_bytes=None,
            )
        else:
            apk.package_name = TARGET_PACKAGE
            apk.version_name = apk.version_name or "demo-authorized"
            apk.save(update_fields=["package_name", "version_name"])

        finding, created = Finding.objects.update_or_create(
            audit=audit,
            rule_id=DEMO_RULE_ID,
            defaults={
                "title": "Runtime root detection UI can be instrumented in AndroGoat",
                "severity": "MEDIUM",
                "confidence": "HIGH",
                "standard": "MASVS",
                "category": "MASVS-RESILIENCE",
                "description": "Static analyzer fixture: AndroGoat contains a root detection screen whose runtime behavior can be validated with the approved Frida UI proof playbook in the authorized emulator lab.",
                "mapping_data": {
                    "masvs_controls": ["MASVS-RESILIENCE-1"],
                    "fixture_only": True,
                    "provenance": "STATIC_ANALYZER_DEV_FIXTURE",
                    "evidence_summary": "AndroGoat root-detection UI selected for the finding-driven dynamic validation demo.",
                    "affected_component": "Root detection activity/control",
                    "expected_dynamic_playbook_family": "ROOT_DETECTION_SCREEN_VALIDATION",
                    "target_package": TARGET_PACKAGE,
                },
                "recommendation": "Retain root-detection resilience and verify behavior on approved rooted/emulator lab targets.",
                "requires_manual_validation": True,
                "status": "OPEN",
            },
        )
        self.stdout.write(self.style.SUCCESS(
            f"{'Created' if created else 'Updated'} AndroGoat demo finding {finding.id} for audit {audit.id}."
        ))
        self.stdout.write(f"DEMO_PROJECT_ID={audit.project_id}")
        self.stdout.write(f"DEMO_AUDIT_ID={audit.id}")
        self.stdout.write(f"DEMO_APK_ID={apk.id}")
        self.stdout.write(f"DEMO_FINDING_ID={finding.id}")
        self.stdout.write(f"DEMO_TARGET_PACKAGE={TARGET_PACKAGE}")
        self.stdout.write(f"DEMO_EXPECTED_PLAYBOOK=ROOT_DETECTION_SCREEN_VALIDATION")
        self.stdout.write(f"DEMO_USERNAME={options['demo_username']}")
        self.stdout.write("STATIC_FINDING_DEMO_FIXTURE=PASS")

    def _get_or_create_audit(self, audit_id: int | None) -> Audit:
        if audit_id:
            try:
                return Audit.objects.get(pk=audit_id)
            except Audit.DoesNotExist as exc:
                raise CommandError(f"Audit {audit_id} does not exist.") from exc

        project, _ = Project.objects.get_or_create(
            name=PROJECT_NAME,
            defaults={
                "description": (
                    "Local development project for the AndroGoat finding-driven "
                    "dynamic validation demo."
                )
            },
        )
        audit, _ = Audit.objects.update_or_create(
            project=project,
            name=AUDIT_NAME,
            defaults={"status": Audit.Status.ANALYSIS_COMPLETED},
        )
        return audit

    def _ensure_demo_user(self, username: str) -> None:
        password = (
            os.getenv("MSAP_DEMO_PASSWORD")
            or os.getenv("MSAP_E2E_PASSWORD")
            or "MSAP-demo-password-123!"
        )
        User = get_user_model()
        user, created = User.objects.get_or_create(
            username=username,
            defaults={"email": "msap-demo@example.local"},
        )
        if created or not user.has_usable_password():
            user.set_password(password)
            user.save(update_fields=["password"])
        group, _ = Group.objects.get_or_create(name=ANALYST_GROUP)
        user.groups.add(group)
