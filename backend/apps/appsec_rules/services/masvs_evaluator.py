from pathlib import Path

from django.conf import settings
from django.db import transaction

from apps.appsec_rules.services.rule_loader import load_masvs_rules
from apps.audits.models import Audit
from apps.evidence.models import Evidence
from apps.findings.models import Finding
from apps.normalization.models import NormalizedArtifact


IMPLEMENTED_RULE_IDS = ("MSAP-AND-001", "MSAP-AND-002")


@transaction.atomic
def evaluate_masvs_rules(
    audit: Audit | int,
    rules_path: str | Path | None = None,
) -> dict[str, int]:
    audit_id = audit.pk if isinstance(audit, Audit) else audit
    rules = load_masvs_rules(
        rules_path
        or Path(settings.ANALYZER_RULES_PATH) / "masvs_static_rules.yaml"
    )
    implemented_rules = {
        rule["id"]: rule for rule in rules if rule["id"] in IMPLEMENTED_RULE_IDS
    }
    summary = {
        "evaluated_rules": 0,
        "findings_created": 0,
        "findings_existing": 0,
        "evidence_created": 0,
    }

    manifest = (
        NormalizedArtifact.objects.filter(
            audit_id=audit_id,
            artifact_type=NormalizedArtifact.ArtifactType.MANIFEST,
        )
        .order_by("-created_at", "-id")
        .first()
    )
    if manifest is None:
        return summary

    normalized_data = manifest.normalized_data
    if not isinstance(normalized_data, dict):
        normalized_data = {}
    application = normalized_data.get("application", {})
    if not isinstance(application, dict):
        application = {}

    conditions = {
        "MSAP-AND-001": (
            application.get("debuggable") is True,
            "application.debuggable=true",
        ),
        "MSAP-AND-002": (
            application.get("allow_backup") is True,
            "application.allow_backup=true",
        ),
    }

    for rule_id in IMPLEMENTED_RULE_IDS:
        rule = implemented_rules.get(rule_id)
        if rule is None:
            continue
        summary["evaluated_rules"] += 1
        matched, snippet = conditions[rule_id]
        if not matched:
            continue

        finding, created = Finding.objects.get_or_create(
            audit_id=audit_id,
            rule_id=rule_id,
            defaults={
                "title": rule["title"],
                "severity": rule["severity"],
                "confidence": rule["confidence"],
                "standard": rule["standard"],
                "category": rule["masvs_category"],
                "recommendation": rule["recommendation"],
            },
        )
        summary["findings_created" if created else "findings_existing"] += 1

        _, evidence_created = Evidence.objects.get_or_create(
            audit_id=audit_id,
            finding=finding,
            indicator=None,
            evidence_type=rule["detection_type"],
            source=rule["source"],
            snippet=snippet,
            redacted=False,
        )
        summary["evidence_created"] += int(evidence_created)

    return summary
