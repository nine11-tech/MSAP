from pathlib import Path
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
    "pattern_or_condition",
    "recommendation",
}


def load_masvs_rules(path: str | Path) -> list[dict[str, Any]]:
    rules = _load_rules_document(path)
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

    missing_fields = sorted(field for field in REQUIRED_FIELDS if not rule.get(field))
    if missing_fields:
        raise ValidationError(
            f"MASVS rule #{index} ({rule.get('id', 'unknown')}) is missing required fields: "
            f"{', '.join(missing_fields)}"
        )

    severity = rule["severity"]
    if severity not in ALLOWED_SEVERITIES:
        raise ValidationError(
            f"MASVS rule {rule['id']} has invalid severity '{severity}'. "
            f"Allowed values: {', '.join(sorted(ALLOWED_SEVERITIES))}."
        )

    confidence = rule["confidence"]
    if confidence not in ALLOWED_CONFIDENCES:
        raise ValidationError(
            f"MASVS rule {rule['id']} has invalid confidence '{confidence}'. "
            f"Allowed values: {', '.join(sorted(ALLOWED_CONFIDENCES))}."
        )

