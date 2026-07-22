import json
from pathlib import Path
from typing import Any

from django.conf import settings
from django.db import transaction

from apps.audits.models import Audit
from apps.evidence.models import Evidence
from apps.indicators.models import SuspiciousIndicator
from apps.normalization.models import NormalizedArtifact
from apps.triage_rules.services.triage_rule_loader import load_attck_triage_rules


IMPLEMENTED_INDICATOR_IDS = ("MSAP-MOB-001", "MSAP-MOB-002")
SMS_PERMISSIONS = {
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
}
ACCESSIBILITY_SERVICE_PERMISSION = "android.permission.BIND_ACCESSIBILITY_SERVICE"


@transaction.atomic
def evaluate_attck_indicators(
    audit: Audit | int,
    rules_path: str | Path | None = None,
) -> dict[str, int]:
    audit_id = audit.pk if isinstance(audit, Audit) else audit
    rules = load_attck_triage_rules(
        rules_path
        or Path(settings.ANALYZER_RULES_PATH) / "attck_mobile_triage_rules.yaml"
    )
    implemented_rules = {
        rule["id"]: rule
        for rule in rules
        if rule["id"] in IMPLEMENTED_INDICATOR_IDS
    }
    summary = {
        "evaluated_indicators": 0,
        "indicators_created": 0,
        "indicators_existing": 0,
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
    conditions = {
        "MSAP-MOB-001": _sms_evidence(normalized_data.get("permissions", [])),
        "MSAP-MOB-002": _accessibility_evidence(
            normalized_data.get("components", [])
        ),
    }

    for indicator_id in IMPLEMENTED_INDICATOR_IDS:
        rule = implemented_rules.get(indicator_id)
        if rule is None:
            continue
        summary["evaluated_indicators"] += 1
        snippet = conditions[indicator_id]
        if snippet is None:
            continue

        indicator, created = SuspiciousIndicator.objects.get_or_create(
            audit_id=audit_id,
            indicator_id=indicator_id,
            defaults={
                "title": rule["title"],
                "tactic": rule["tactic"],
                "technique_id": rule["technique_id"],
                "technique_name": rule["technique_name"],
                "severity": rule["severity"],
                "confidence": rule["confidence"],
                "triage_interpretation": rule["triage_interpretation"],
            },
        )
        summary[
            "indicators_created" if created else "indicators_existing"
        ] += 1

        _, evidence_created = Evidence.objects.get_or_create(
            audit_id=audit_id,
            finding=None,
            indicator=indicator,
            evidence_type=rule["detection_type"],
            source=rule["source"],
            snippet=snippet,
            redacted=False,
        )
        summary["evidence_created"] += int(evidence_created)

    return summary


def _sms_evidence(permissions: Any) -> str | None:
    if not isinstance(permissions, list):
        return None
    for permission in permissions:
        permission_name = permission
        if isinstance(permission, dict):
            permission_name = permission.get("name")
        if isinstance(permission_name, str) and permission_name in SMS_PERMISSIONS:
            return f"permission={permission_name}"
    return None


def _accessibility_evidence(components: Any) -> str | None:
    if not isinstance(components, list):
        return None
    for component in components:
        if not isinstance(component, dict):
            continue
        component_type = component.get("type") or component.get("component_type")
        if not isinstance(component_type, str) or component_type.lower() != "service":
            continue

        permission = component.get("permission") or component.get(
            "android:permission"
        )
        if permission == ACCESSIBILITY_SERVICE_PERMISSION:
            return f"service.permission={permission}"

        name = component.get("name")
        if isinstance(name, str) and "accessibility" in name.lower():
            return f"service.name={_short_value(name)}"

        for metadata_key in ("metadata", "meta_data"):
            metadata = component.get(metadata_key)
            metadata_contains_accessibility = (
                metadata is not None
                and "accessibility" in _serialized(metadata).lower()
            )
            if metadata_contains_accessibility:
                return f"service.metadata={_short_value(metadata)}"
    return None


def _serialized(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _short_value(value: Any, limit: int = 160) -> str:
    serialized = _serialized(value)
    if len(serialized) <= limit:
        return serialized
    return f"{serialized[: limit - 3]}..."
