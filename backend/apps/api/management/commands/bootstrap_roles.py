from django.contrib.auth.models import Group, Permission
from django.core.management.base import BaseCommand
from django.db.models import Q

from apps.api.roles import ADMIN_GROUP, ANALYST_GROUP, VIEWER_GROUP


MSAP_APP_LABELS = {
    "projects",
    "audits",
    "storage",
    "apk_files",
    "analyzers",
    "normalization",
    "appsec_rules",
    "triage_rules",
    "findings",
    "indicators",
    "evidence",
    "scoring",
    "reports",
}

ANALYST_WRITE_MODELS = {"project", "audit", "apkfile"}


class Command(BaseCommand):
    help = "Create the idempotent MSAP role groups and assign model permissions."

    def handle(self, *args, **options):
        admin, _ = Group.objects.get_or_create(name=ADMIN_GROUP)
        analyst, _ = Group.objects.get_or_create(name=ANALYST_GROUP)
        viewer, _ = Group.objects.get_or_create(name=VIEWER_GROUP)

        msap_permissions = Permission.objects.filter(
            content_type__app_label__in=MSAP_APP_LABELS
        )
        admin_permissions = Permission.objects.filter(
            content_type__app_label__in=MSAP_APP_LABELS | {"auth", "axes"}
        )
        viewer_permissions = msap_permissions.filter(codename__startswith="view_")
        analyst_permissions = msap_permissions.filter(
            Q(codename__startswith="view_")
            | Q(
                content_type__model__in=ANALYST_WRITE_MODELS,
                codename__in=[
                    *(f"add_{model}" for model in ANALYST_WRITE_MODELS),
                    *(f"change_{model}" for model in ANALYST_WRITE_MODELS),
                ],
            )
        )

        admin.permissions.set(admin_permissions)
        analyst.permissions.set(analyst_permissions)
        viewer.permissions.set(viewer_permissions)

        self.stdout.write(
            self.style.SUCCESS(
                "MSAP roles ready: "
                f"{ADMIN_GROUP}, {ANALYST_GROUP}, {VIEWER_GROUP}."
            )
        )
