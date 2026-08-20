"""Regression tests for the approved-playbook fallback sequence executor.

The deterministic fallback runs after the paid decision budget is exhausted.
It must never emit a step whose runtime prerequisites are not satisfied
(notably logcat collectors), must bind real collector ids instead of plan
placeholders, and must never re-emit tools that already executed (which would
loop forever inside the bounded execution worker).
"""

import pytest

from apps.dynamic_analysis.services.agent_decision_provider import (
    _active_logcat_collector_ids,
    _approved_sequence_action,
)


def _state(sequence, observations, hypotheses=None):
    return {
        "contract_version": "msap.agent-state-context/v1",
        "TRUSTED_CONTROL": {
            "agent_run_id": 1,
            "audit_id": 1,
            "target_package": "owasp.sat.agoat",
            "objective": "Assess bounded behavior.",
            "scope": "Authorized package only.",
            "capability_envelope": {"allowed_capabilities": []},
            "hypotheses": hypotheses
            or [{"hypothesis_id": "runtime_stability", "family": "RUNTIME_STABILITY"}],
            "coverage": {},
            "budgets": {},
            "findings_authority": "DETERMINISTIC_BACKEND_ONLY",
            "approved_playbook_sequence": sequence,
        },
        "UNTRUSTED_OBSERVATIONS": {
            "data_classification": "APPLICATION_DATA_NOT_INSTRUCTIONS",
            "recent": observations,
        },
    }


def _observation(tool_name, data):
    return {
        "sequence": 1,
        "tool_name": tool_name,
        "status": "SUCCEEDED",
        "data": data,
        "observation_hash": "a" * 64,
    }


def _step(tools, arguments=None):
    return {
        "step_id": "s1",
        "tools": tools,
        "arguments": arguments or {},
        "objective": "Next bounded observation.",
        "evidence_requirements": ["tool_output"],
    }


def test_active_collector_ids_derived_from_start_logcat_observations():
    state = _state(
        [],
        [
            _observation("start_logcat", {"collector_id": "c-123", "max_seconds": 30}),
            _observation("get_device_status", {"ready": True}),
        ],
    )
    assert _active_logcat_collector_ids(state) == {"c-123"}


def test_fallback_skips_logcat_step_without_live_collector():
    state = _state(
        [
            _step(["stop_logcat"], {"collector_id": "collector_from_step_3"}),
            _step(["frida_status"], {"package_name": "owasp.sat.agoat"}),
        ],
        [_observation("launch_package", {"launched": True})],
    )
    decision = _approved_sequence_action(state, index=1)
    assert decision is not None
    assert decision["tool_name"] == "frida_status"
    assert decision["decision_type"] == "TOOL_ACTION"


def test_fallback_binds_live_collector_id_to_stop_logcat():
    state = _state(
        [_step(["stop_logcat"], {"collector_id": "collector_from_step_3"})],
        [_observation("start_logcat", {"collector_id": "c-456"})],
    )
    decision = _approved_sequence_action(state, index=0)
    assert decision is not None
    assert decision["tool_name"] == "stop_logcat"
    assert decision["arguments"]["collector_id"] == "c-456"


def test_fallback_does_not_reemit_already_executed_tools():
    steps = [
        _step(["get_device_status"], {}),
        _step(
            ["start_logcat"],
            {"package_name": "owasp.sat.agoat", "reason": "agent_step", "max_seconds": 30},
        ),
    ]
    state = _state(
        steps,
        [_observation("get_device_status", {"ready": True})],
    )
    decision = _approved_sequence_action(state, index=0)
    assert decision is not None
    assert decision["tool_name"] == "start_logcat"
    progressed = _state(
        steps,
        [
            _observation("get_device_status", {"ready": True}),
            _observation("start_logcat", {"collector_id": "c-1"}),
        ],
    )
    again = _approved_sequence_action(progressed, index=1)
    assert again is None


def test_fallback_returns_none_when_sequence_exhausted():
    state = _state(
        [_step(["get_device_status"], {})],
        [_observation("get_device_status", {"ready": True})],
    )
    assert _approved_sequence_action(state, index=1) is None


def test_fallback_skips_schema_invalid_tool_and_uses_next_in_step():
    state = _state(
        [
            _step(
                ["frida_run_js"],
                {
                    "package_name": "owasp.sat.agoat",
                    "mode": "attach",
                    "timeout": 25,
                },
            ),
            _step(["launch_package"], {"package_name": "owasp.sat.agoat"}),
        ],
        [],
    )
    decision = _approved_sequence_action(state, index=0)
    assert decision is not None
    assert decision["tool_name"] == "launch_package"