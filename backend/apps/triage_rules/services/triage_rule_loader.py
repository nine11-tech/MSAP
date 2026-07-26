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
    "tactic",
    "technique_id",
    "technique_name",
    "severity",
    "confidence",
    "source",
    "detection_type",
    "condition",
    "pattern_or_condition",
    "triage_interpretation",
    "prerequisites",
    "mapping_rationale",
    "false_positive_considerations",
    "requires_manual_validation",
    "non_malware_verdict_note",
}

RULE_ID_PATTERN = re.compile(r"^MSAP-MOB-\d{3}$")
TECHNIQUE_ID_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def load_attck_triage_rules(path: str | Path) -> list[dict[str, Any]]:
    rules = _load_rules_document(path)
    identifiers = [rule.get("id") for rule in rules if isinstance(rule, dict)]
    duplicates = sorted({identifier for identifier in identifiers if identifiers.count(identifier) > 1})
    if duplicates:
        raise ValidationError(f"Duplicate ATT&CK Mobile rule IDs: {', '.join(duplicates)}")
    for index, rule in enumerate(rules, start=1):
        _validate_rule(rule, index)
    return rules


def _load_rules_document(path: str | Path) -> list[dict[str, Any]]:
    rule_path = Path(path)
    if not rule_path.exists():
        raise ValidationError(f"ATT&CK Mobile triage rules file not found: {rule_path}")

    with rule_path.open("r", encoding="utf-8") as handle:
        document = yaml.safe_load(handle) or {}

    rules = document.get("rules")
    if not isinstance(rules, list):
        raise ValidationError("ATT&CK Mobile rules file must contain a top-level 'rules' list.")

    return rules


def _validate_rule(rule: dict[str, Any], index: int) -> None:
    if not isinstance(rule, dict):
        raise ValidationError(f"ATT&CK Mobile rule #{index} must be a mapping.")

    severity = rule.get("severity")
    if severity is not None and severity not in ALLOWED_SEVERITIES:
        raise ValidationError(
            f"ATT&CK Mobile rule {rule.get('id', 'unknown')} has invalid severity '{severity}'. "
            f"Allowed values: {', '.join(sorted(ALLOWED_SEVERITIES))}."
        )
    confidence = rule.get("confidence")
    if confidence is not None and confidence not in ALLOWED_CONFIDENCES:
        raise ValidationError(
            f"ATT&CK Mobile rule {rule.get('id', 'unknown')} has invalid confidence "
            f"'{confidence}'. Allowed values: {', '.join(sorted(ALLOWED_CONFIDENCES))}."
        )

    missing_fields = sorted(
        field
        for field in REQUIRED_FIELDS
        if field not in rule or rule[field] is None or rule[field] == ""
    )
    if missing_fields:
        raise ValidationError(
            f"ATT&CK Mobile rule #{index} ({rule.get('id', 'unknown')}) is missing required fields: "
            f"{', '.join(missing_fields)}"
        )

    if not RULE_ID_PATTERN.fullmatch(str(rule["id"])):
        raise ValidationError(f"ATT&CK Mobile rule {rule['id']} has an invalid internal rule ID.")
    if not TECHNIQUE_ID_PATTERN.fullmatch(str(rule["technique_id"])):
        raise ValidationError(
            f"ATT&CK Mobile rule {rule['id']} has invalid technique ID "
            f"'{rule['technique_id']}'."
        )
    if not isinstance(rule["prerequisites"], list):
        raise ValidationError(
            f"ATT&CK Mobile rule {rule['id']} field 'prerequisites' must be a list."
        )
    if rule["non_malware_verdict_note"] != "Triage signal — not a malware verdict.":
        raise ValidationError(
            f"ATT&CK Mobile rule {rule['id']} must retain the non-malware-verdict note."
        )
