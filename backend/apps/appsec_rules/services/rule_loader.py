from pathlib import Path
import re
from typing import Any

import yaml
from django.core.exceptions import ValidationError


ALLOWED_SEVERITIES = {"Low", "Medium", "High", "Critical"}
ALLOWED_CONFIDENCES = {"Low", "Medium", "High"}

REQUIRED_FIELDS = {
    "id",
    "title",
    "description",
    "standard",
    "masvs_category",
    "severity",
    "confidence",
    "source",
    "detection_type",
    "condition",
    "pattern_or_condition",
    "prerequisites",
    "evidence_requirements",
    "recommendation",
    "masvs_controls",
    "maswe_ids",
    "mastg_references",
    "false_positive_guidance",
    "requires_manual_validation",
    "test_type",
}

RULE_ID_PATTERN = re.compile(r"^MSAP-AND-\d{3}$")
MASVS_PATTERN = re.compile(
    r"^MASVS-(STORAGE|CRYPTO|AUTH|NETWORK|PLATFORM|CODE|RESILIENCE|PRIVACY)-\d+$"
)
MASWE_PATTERN = re.compile(r"^MASWE-\d{4}$")
MASTG_PATTERN = re.compile(r"^MASTG-(?:TEST|BEST|TECH|DEMO)-\d{4}$")


def load_masvs_rules(path: str | Path) -> list[dict[str, Any]]:
    rules = _load_rules_document(path)
    identifiers = [rule.get("id") for rule in rules if isinstance(rule, dict)]
    duplicates = sorted({identifier for identifier in identifiers if identifiers.count(identifier) > 1})
    if duplicates:
        raise ValidationError(f"Duplicate MASVS rule IDs: {', '.join(duplicates)}")
    for index, rule in enumerate(rules, start=1):
        _validate_rule(rule, index)
    return rules


def _load_rules_document(path: str | Path) -> list[dict[str, Any]]:
    rule_path = Path(path)
    if not rule_path.exists():
        raise ValidationError(f"MASVS rules file not found: {rule_path}")

    with rule_path.open("r", encoding="utf-8") as handle:
        document = yaml.safe_load(handle) or {}

    rules = document.get("rules")
    if not isinstance(rules, list):
        raise ValidationError("MASVS rules file must contain a top-level 'rules' list.")

    return rules


def _validate_rule(rule: dict[str, Any], index: int) -> None:
    if not isinstance(rule, dict):
        raise ValidationError(f"MASVS rule #{index} must be a mapping.")

    severity = rule.get("severity")
    if severity is not None and severity not in ALLOWED_SEVERITIES:
        raise ValidationError(
            f"MASVS rule {rule.get('id', 'unknown')} has invalid severity '{severity}'. "
            f"Allowed values: {', '.join(sorted(ALLOWED_SEVERITIES))}."
        )
    confidence = rule.get("confidence")
    if confidence is not None and confidence not in ALLOWED_CONFIDENCES:
        raise ValidationError(
            f"MASVS rule {rule.get('id', 'unknown')} has invalid confidence '{confidence}'. "
            f"Allowed values: {', '.join(sorted(ALLOWED_CONFIDENCES))}."
        )

    missing_fields = sorted(
        field
        for field in REQUIRED_FIELDS
        if field not in rule or rule[field] is None or rule[field] == ""
    )
    if missing_fields:
        raise ValidationError(
            f"MASVS rule #{index} ({rule.get('id', 'unknown')}) is missing required fields: "
            f"{', '.join(missing_fields)}"
        )

    if not RULE_ID_PATTERN.fullmatch(str(rule["id"])):
        raise ValidationError(f"MASVS rule {rule['id']} has an invalid internal rule ID.")

    list_fields = ("prerequisites", "masvs_controls", "maswe_ids", "mastg_references")
    for field in list_fields:
        if not isinstance(rule[field], list):
            raise ValidationError(f"MASVS rule {rule['id']} field '{field}' must be a list.")

    invalid_controls = [
        value for value in rule["masvs_controls"] if not MASVS_PATTERN.fullmatch(str(value))
    ]
    invalid_maswe = [value for value in rule["maswe_ids"] if not MASWE_PATTERN.fullmatch(str(value))]
    invalid_mastg = [
        value for value in rule["mastg_references"] if not MASTG_PATTERN.fullmatch(str(value))
    ]
    invalid = invalid_controls + invalid_maswe + invalid_mastg
    if invalid:
        raise ValidationError(
            f"MASVS rule {rule['id']} contains invalid framework identifiers: "
            f"{', '.join(str(value) for value in invalid)}"
        )
