from pathlib import Path
from typing import Any

from django.conf import settings
from django.db import transaction

from apps.appsec_rules.models import RuleEvaluation
from apps.audits.models import Audit
from apps.evidence.models import Evidence
from apps.indicators.models import SuspiciousIndicator
from apps.normalization.models import NormalizedArtifact
from apps.triage_rules.services.triage_rule_loader import load_attck_triage_rules


EVALUATOR_VERSION = "2.0.0"


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
    artifacts = _artifact_map(audit_id)
    summary = {
        "catalog_indicators": len(rules),
        "evaluated_indicators": 0,
        "matched_indicators": 0,
        "not_evaluated": 0,
        "indicators_created": 0,
        "indicators_existing": 0,
        "evidence_created": 0,
    }

    for rule in rules:
        missing = [name for name in rule["prerequisites"] if name not in artifacts]
        if missing:
            result = RuleEvaluation.Result.NOT_EVALUATED
            snippet = f"Prerequisite artifact unavailable: {', '.join(missing)}"
            matched = False
            summary["not_evaluated"] += 1
        else:
            matched, snippet = _match(rule, artifacts)
            result = (
                RuleEvaluation.Result.REVIEW_REQUIRED
                if matched
                else RuleEvaluation.Result.NOT_APPLICABLE
            )
            summary["evaluated_indicators"] += 1
            summary["matched_indicators"] += int(matched)

        mappings = {
            "technique_id": rule["technique_id"],
            "technique_name": rule["technique_name"],
            "tactic": rule["tactic"],
            "mapping_rationale": rule["mapping_rationale"],
            "non_malware_verdict_note": rule["non_malware_verdict_note"],
        }
        RuleEvaluation.objects.update_or_create(
            audit_id=audit_id,
            framework=RuleEvaluation.Framework.ATTACK_MOBILE,
            rule_id=rule["id"],
            defaults={
                "result": result,
                "severity": rule["severity"].upper(),
                "confidence": rule["confidence"].upper(),
                "title": rule["title"],
                "mapping_data": mappings,
                "evidence_summary": snippet,
                "remediation": "",
                "requires_manual_validation": True,
                "evaluator_version": EVALUATOR_VERSION,
            },
        )

        if not matched:
            SuspiciousIndicator.objects.filter(
                audit_id=audit_id, indicator_id=rule["id"]
            ).delete()
            continue

        indicator, created = SuspiciousIndicator.objects.update_or_create(
            audit_id=audit_id,
            indicator_id=rule["id"],
            defaults={
                "title": rule["title"],
                "tactic": rule["tactic"],
                "technique_id": rule["technique_id"],
                "technique_name": rule["technique_name"],
                "severity": rule["severity"],
                "confidence": rule["confidence"],
                "triage_interpretation": rule["triage_interpretation"],
                "mapping_rationale": rule["mapping_rationale"],
                "false_positive_considerations": rule[
                    "false_positive_considerations"
                ],
                "requires_manual_validation": True,
                "non_malware_verdict_note": rule["non_malware_verdict_note"],
            },
        )
        summary["indicators_created" if created else "indicators_existing"] += 1
        _, evidence_created = Evidence.objects.get_or_create(
            audit_id=audit_id,
            finding=None,
            indicator=indicator,
            evidence_type=rule["detection_type"],
            source=rule["source"],
            snippet=snippet[:500],
            redacted=False,
        )
        summary["evidence_created"] += int(evidence_created)

    return summary


def _artifact_map(audit_id: int) -> dict[str, dict]:
    artifacts: dict[str, dict] = {}
    for artifact in NormalizedArtifact.objects.filter(audit_id=audit_id).order_by(
        "created_at", "id"
    ):
        value = artifact.normalized_data if isinstance(artifact.normalized_data, dict) else {}
        data = value.get("data") if isinstance(value.get("data"), dict) else value
        if value.get("extraction_status") in {"FAILED", "NOT_STARTED"}:
            continue
        artifacts[artifact.artifact_type] = data
    return artifacts


def _match(rule: dict[str, Any], artifacts: dict[str, dict]) -> tuple[bool, str]:
    manifest = artifacts.get("MANIFEST", {})
    permissions = {
        item.get("name") if isinstance(item, dict) else item
        for item in manifest.get("permissions", [])
    }
    components = [
        item for item in manifest.get("components", []) if isinstance(item, dict)
    ]
    values = set(rule.get("values", []))
    condition = rule["condition"]

    if condition == "permission_any":
        matches = sorted(permissions & values)
        return bool(matches), f"declared permission capability: {', '.join(matches)}"
    if condition in {"accessibility_service", "device_admin", "vpn_service"}:
        condition_keywords = {
            "accessibility_service": ("accessibility",),
            "device_admin": ("device_admin", "deviceadmin"),
            "vpn_service": ("vpnservice", "bind_vpn_service"),
        }[condition]
        matches = []
        for component in components:
            serialized = " ".join(
                str(component.get(field, ""))
                for field in ("name", "permission", "metadata", "intent_filters")
            )
            if any(value.lower() in serialized.lower() for value in values) or any(
                keyword in serialized.lower() for keyword in condition_keywords
            ):
                matches.append(component.get("name", "unnamed component"))
        return bool(matches), f"matched component capability declarations: {len(matches)}"
    if condition == "code_reference_category":
        matches = [
            item
            for item in artifacts.get("CODE_REFERENCES", {}).get("matches", [])
            if item.get("category") in values
        ]
        return bool(matches), _reference_summary(matches, "code")
    if condition == "native_libraries":
        libraries = artifacts.get("NATIVE_LIBRARIES", {}).get("libraries", [])
        return bool(libraries), f"native library inventory count: {len(libraries)}"
    if condition == "any_crypto_reference":
        matches = artifacts.get("CRYPTO_USAGE", {}).get("matches", [])
        return bool(matches), _reference_summary(matches, "cryptographic")
    return False, f"condition '{condition}' produced no triage match"


def _reference_summary(matches: list[dict], label: str) -> str:
    categories = sorted(
        {
            str(item.get("category") or item.get("type"))
            for item in matches
            if item.get("category") or item.get("type")
        }
    )
    return f"{label} reference categories: {', '.join(categories[:12])}"
