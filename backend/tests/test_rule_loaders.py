from pathlib import Path

import pytest
import yaml
from django.core.exceptions import ValidationError

from apps.appsec_rules.services.rule_loader import load_masvs_rules
from apps.triage_rules.services.triage_rule_loader import load_attck_triage_rules


RULES_DIR = Path(__file__).resolve().parents[2] / "rules"


def test_masvs_yaml_loads_successfully():
    rules = load_masvs_rules(RULES_DIR / "masvs_static_rules.yaml")

    assert rules


def test_attck_yaml_loads_successfully():
    rules = load_attck_triage_rules(RULES_DIR / "attck_mobile_triage_rules.yaml")

    assert rules


def test_selected_masvs_rules_are_present():
    rules = load_masvs_rules(RULES_DIR / "masvs_static_rules.yaml")
    rule_ids = {rule["id"] for rule in rules}

    assert "MSAP-AND-001" in rule_ids
    assert "MSAP-AND-002" in rule_ids


def test_selected_attck_indicators_are_present():
    rules = load_attck_triage_rules(RULES_DIR / "attck_mobile_triage_rules.yaml")
    rules_by_id = {rule["id"]: rule for rule in rules}

    assert "MSAP-MOB-001" in rules_by_id
    assert rules_by_id["MSAP-MOB-002"]["title"] == "Accessibility service usage"


def test_invalid_masvs_severity_fails(tmp_path):
    path = _write_rules_file(tmp_path, _valid_masvs_rule(severity="Severe"))

    with pytest.raises(ValidationError, match="invalid severity"):
        load_masvs_rules(path)


def test_invalid_attck_confidence_fails(tmp_path):
    path = _write_rules_file(tmp_path, _valid_attck_rule(confidence="Certain"))

    with pytest.raises(ValidationError, match="invalid confidence"):
        load_attck_triage_rules(path)


def test_missing_required_field_fails(tmp_path):
    rule = _valid_masvs_rule()
    del rule["recommendation"]
    path = _write_rules_file(tmp_path, rule)

    with pytest.raises(ValidationError, match="missing required fields"):
        load_masvs_rules(path)


def _write_rules_file(tmp_path, rule: dict) -> Path:
    path = tmp_path / "rules.yaml"
    path.write_text(yaml.safe_dump({"rules": [rule]}), encoding="utf-8")
    return path


def _valid_masvs_rule(**overrides) -> dict:
    rule = {
        "id": "MSAP-TEST-001",
        "title": "Test MASVS rule",
        "description": "Test rule.",
        "standard": "OWASP MASVS",
        "masvs_category": "MASVS-TEST",
        "severity": "Low",
        "confidence": "Medium",
        "source": "AndroidManifest.xml",
        "detection_type": "manifest_attribute",
        "pattern_or_condition": "test == true",
        "recommendation": "Review the test condition.",
    }
    rule.update(overrides)
    return rule


def _valid_attck_rule(**overrides) -> dict:
    rule = {
        "id": "MSAP-MOB-TEST-001",
        "title": "Test ATT&CK rule",
        "description": "Test indicator.",
        "standard": "MITRE ATT&CK Mobile",
        "tactic": "Collection",
        "technique_id": "M0000",
        "technique_name": "Test Technique",
        "severity": "Medium",
        "confidence": "Medium",
        "source": "AndroidManifest.xml",
        "detection_type": "manifest_permission",
        "pattern_or_condition": "TEST_PERMISSION",
        "triage_interpretation": "Requires analyst review.",
    }
    rule.update(overrides)
    return rule
