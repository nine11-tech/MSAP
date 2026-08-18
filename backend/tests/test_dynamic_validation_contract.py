import pytest

from apps.dynamic_analysis.services.dynamic_validation import build_validation_result
from apps.dynamic_analysis.services.dynamic_validation_scenario import (
    CONTRACT_VERSION,
    DynamicValidationScenarioError,
    scenario_from_finding,
    validate_scenario,
)


def _scenario(**overrides):
    value = scenario_from_finding(
        audit_id=1,
        target_package="org.owasp.goatdroid.fourgoats",
        finding={"finding_id": 2, "rule_id": "MSAP-AND-001", "title": "Debuggable"},
        family="BASIC_RUNTIME_REACHABILITY",
        tools=["launch_package", "take_screenshot"],
        evidence=["screenshot"],
        steps=[{"sequence": 1, "step_id": "launch", "tools":[{"name":"launch_package"}]}],
    )
    value.update(overrides)
    return value


def test_scenario_is_versioned_and_closed():
    assert _scenario()["contract_version"] == CONTRACT_VERSION
    with pytest.raises(DynamicValidationScenarioError):
        validate_scenario(_scenario(supported_tool_capabilities=["unknown_tool"]))


def test_unsafe_scenario_is_rejected():
    with pytest.raises(DynamicValidationScenarioError):
        validate_scenario(_scenario(validation_goal="Read a password from adb shell"))


def test_supported_requires_real_evidence():
    result = build_validation_result(
        source_finding_id=2, scenario_id="scenario-1", agent_run_id=3,
        oracle_result={"status": "CONFIRMED", "summary": "observed"}, evidence_ids=[],
    )
    assert result["result"] == "INCONCLUSIVE"


def test_model_only_result_is_not_a_finding():
    result = build_validation_result(
        source_finding_id=2, scenario_id="scenario-1", agent_run_id=None,
        oracle_result={"status": "UNKNOWN", "summary": "model claim"}, evidence_ids=[],
    )
    assert result["result"] == "INCONCLUSIVE"
