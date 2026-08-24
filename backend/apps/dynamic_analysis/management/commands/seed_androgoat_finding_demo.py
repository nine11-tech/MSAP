"""Seed the explicit AndroGoat finding used by the local validation demo.

This is a development fixture, never a production finding.  It represents a
small, fixed set of findings emitted by a static analyzer so the live demo can
exercise the real finding-driven workflow repeatedly.
"""
import os

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from apps.apk_files.models import APKFile
from apps.audits.models import Audit
from apps.api.roles import ANALYST_GROUP
from apps.findings.models import Finding
from apps.projects.models import Project


PROJECT_NAME = "AndroGoat Demo"
AUDIT_NAME = "audit-demo"
DEMO_USERNAME = "msap_demo_analyst"
TARGET_PACKAGE = "owasp.sat.agoat"

DEMO_FINDINGS = (
    {
        "rule_id": "MSAP-AND-001",
        "title": "Debuggable build enables runtime instrumentation",
        "severity": "MEDIUM",
        "category": "MASVS-RESILIENCE",
        "description": "AndroGoat permits runtime instrumentation in the approved emulator lab, enabling a controlled root-detection manipulation demo.",
        "recommendation": "Ship release builds without debug exposure and validate runtime protections on approved test devices.",
        "mapping_data": {
            "masvs_controls": ["MASVS-RESILIENCE-1"],
            "fixture_only": True,
            "provenance": "STATIC_ANALYZER_DEV_FIXTURE",
            "affected_component": "Root detection activity/control",
            "expected_dynamic_playbook_family": "ROOT_DETECTION_SCREEN_VALIDATION",
            "target_package": TARGET_PACKAGE,
        },
    },
    {
        "rule_id": "MSAP-AND-004",
        "title": "Exported activity can be launched externally",
        "severity": "MEDIUM",
        "category": "MASVS-PLATFORM",
        "description": "The static manifest exposes an activity that should be validated through the bounded exported-activity playbook.",
        "recommendation": "Restrict exported components or enforce caller-side authorization.",
        "mapping_data": {
            "masvs_controls": ["MASVS-PLATFORM-1"],
            "fixture_only": True,
            "provenance": "STATIC_ANALYZER_DEV_FIXTURE",
            "affected_component": "Exported activity",
            "expected_dynamic_playbook_family": "EXPORTED_ACTIVITY_LAUNCH_VERIFICATION",
            "target_package": TARGET_PACKAGE,
        },
    },
    {
        "rule_id": "MSAP-AND-006",
        "title": "Exported receiver accepts explicit broadcasts",
        "severity": "MEDIUM",
        "category": "MASVS-PLATFORM",
        "description": "The static manifest exposes a receiver that should be validated through a bounded explicit-broadcast exercise.",
        "recommendation": "Restrict exported receivers or require signature-level permissions where appropriate.",
        "mapping_data": {
            "masvs_controls": ["MASVS-PLATFORM-1"],
            "fixture_only": True,
            "provenance": "STATIC_ANALYZER_DEV_FIXTURE",
            "affected_component": "Exported broadcast receiver",
            "expected_dynamic_playbook_family": "EXPORTED_RECEIVER_BROADCAST_VERIFICATION",
            "target_package": TARGET_PACKAGE,
        },
    },
    {
        "rule_id": "MSAP-AND-007",
        "title": "Exported content provider is externally queryable",
        "severity": "MEDIUM",
        "category": "MASVS-PLATFORM",
        "description": "The static manifest exposes a provider authority that should be validated through a bounded read-only query.",
        "recommendation": "Require permissions or remove unnecessary external exposure for content providers.",
        "mapping_data": {
            "masvs_controls": ["MASVS-PLATFORM-1"],
            "fixture_only": True,
            "provenance": "STATIC_ANALYZER_DEV_FIXTURE",
            "affected_component": "Exported content provider",
            "expected_dynamic_playbook_family": "EXPORTED_PROVIDER_ACCESS_VERIFICATION",
            "target_package": TARGET_PACKAGE,
        },
    },
    {
        "rule_id": "MSAP-AND-016",
        "title": "Certificate pinning blocks controlled proxy interception",
        "severity": "HIGH",
        "category": "NETWORK",
        "description": "The static assessment indicates a TLS pinning path that can be exercised with the approved Frida-plus-proxy playbook.",
        "recommendation": "Document pinning behavior and test bypass resistance only in approved assessment labs.",
        "mapping_data": {
            "masvs_controls": ["MASVS-NETWORK-1"],
            "fixture_only": True,
            "provenance": "STATIC_ANALYZER_DEV_FIXTURE",
            "affected_component": "OkHttp certificate pinning flow",
            "expected_dynamic_playbook_family": "TLS_PINNING_FRIDA_BYPASS",
            "target_package": TARGET_PACKAGE,
        },
    },
    {
        "rule_id": "MSAP-AND-029",
        "title": "Pinned TLS trust path requires runtime validation",
        "severity": "HIGH",
        "category": "NETWORK",
        "description": "The static assessment indicates a pinned trust path that should be exercised with a bounded interception demo.",
        "recommendation": "Validate certificate-pinning logic in controlled labs and track approved bypass evidence separately from production claims.",
        "mapping_data": {
            "masvs_controls": ["MASVS-NETWORK-1"],
            "fixture_only": True,
            "provenance": "STATIC_ANALYZER_DEV_FIXTURE",
            "affected_component": "Pinned TLS request path",
            "expected_dynamic_playbook_family": "TLS_PINNING_FRIDA_BYPASS",
            "target_package": TARGET_PACKAGE,
        },
    },
)


class Command(BaseCommand):
    help = "Seed the development-only AndroGoat audit-demo findings used by the live dynamic validation demo."

    def add_arguments(self, parser):
        parser.add_argument("--audit-id", type=int)
        parser.add_argument("--dev-fixture", action="store_true")
        parser.add_argument("--demo-username", default=DEMO_USERNAME)
        parser.add_argument("--audit-name", default=AUDIT_NAME)
        parser.add_argument("--project-name", default=PROJECT_NAME)
        parser.add_argument("--reinitialize", action="store_true")

    def handle(self, *args, **options):
        if not settings.DEBUG or not options["dev_fixture"]:
            raise CommandError("This command requires DEBUG=true and --dev-fixture; it cannot seed production evidence.")
        with transaction.atomic():
            audit = self._get_or_create_audit(
                options.get("audit_id"),
                audit_name=options["audit_name"],
                project_name=options["project_name"],
                reinitialize=options["reinitialize"],
            )
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

            created_ids: list[int] = []
            for finding_data in DEMO_FINDINGS:
                finding, _created = Finding.objects.update_or_create(
                    audit=audit,
                    rule_id=finding_data["rule_id"],
                    defaults={
                        "title": finding_data["title"],
                        "severity": finding_data["severity"],
                        "confidence": "HIGH",
                        "standard": "MASVS",
                        "category": finding_data["category"],
                        "description": finding_data["description"],
                        "mapping_data": finding_data["mapping_data"],
                        "recommendation": finding_data["recommendation"],
                        "requires_manual_validation": True,
                        "status": "OPEN",
                    },
                )
                created_ids.append(finding.id)

            self.stdout.write(
                self.style.SUCCESS(
                    f"Seeded {len(created_ids)} AndroGoat demo findings for audit {audit.id}."
                )
            )
        self.stdout.write(f"DEMO_PROJECT_ID={audit.project_id}")
        self.stdout.write(f"DEMO_AUDIT_ID={audit.id}")
        self.stdout.write(f"DEMO_AUDIT_NAME={audit.name}")
        self.stdout.write(f"DEMO_APK_ID={apk.id}")
        self.stdout.write(
            "DEMO_FINDING_RULES=" + ",".join(item["rule_id"] for item in DEMO_FINDINGS)
        )
        self.stdout.write(f"DEMO_TARGET_PACKAGE={TARGET_PACKAGE}")
        self.stdout.write(
            "DEMO_EXPECTED_PLAYBOOKS="
            "EXPORTED_ACTIVITY_LAUNCH_VERIFICATION,"
            "EXPORTED_RECEIVER_BROADCAST_VERIFICATION,"
            "EXPORTED_PROVIDER_ACCESS_VERIFICATION,"
            "ROOT_DETECTION_SCREEN_VALIDATION,"
            "TLS_PINNING_FRIDA_BYPASS"
        )
        self.stdout.write(f"DEMO_USERNAME={options['demo_username']}")
        self.stdout.write("STATIC_FINDING_DEMO_FIXTURE=PASS")

    def _get_or_create_audit(
        self,
        audit_id: int | None,
        *,
        audit_name: str,
        project_name: str,
        reinitialize: bool,
    ) -> Audit:
        if audit_id:
            if reinitialize:
                raise CommandError("--reinitialize cannot be used with --audit-id.")
            try:
                return Audit.objects.get(pk=audit_id)
            except Audit.DoesNotExist as exc:
                raise CommandError(f"Audit {audit_id} does not exist.") from exc

        project, _ = Project.objects.get_or_create(
            name=project_name,
            defaults={
                "description": (
                    "Local development project for the repeatable AndroGoat "
                    "dynamic validation demo."
                )
            },
        )
        if reinitialize:
            Audit.objects.filter(project=project, name=audit_name).delete()
        audit, _ = Audit.objects.update_or_create(
            project=project,
            name=audit_name,
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
