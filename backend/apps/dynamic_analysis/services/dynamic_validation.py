from __future__ import annotations

from typing import Any

from apps.dynamic_analysis.models import DynamicValidationResult
from apps.dynamic_analysis.services.playbook_catalog import validate_playbook_selection
from apps.dynamic_analysis.services.playbook_oracles import ORACLES

RESULT_CONTRACT_VERSION = "msap.dynamic-validation-result/v1"


def build_validation_result(
    *, source_finding_id: int, scenario_id: str, agent_run_id: int | None,
    oracle_result: dict[str, Any], evidence_ids: list[int],
    artifact_ids: list[int] | None = None, confidence: float = 0.0,
    summary: str = "", limitations: str = "",
) -> dict[str, Any]:
    """Create the backend-owned result envelope; model text cannot set result."""
    result = {
        "CONFIRMED": "SUPPORTED",
        "REFUTED": "REJECTED",
        "INCONCLUSIVE": "INCONCLUSIVE",
        "NOT_ASSESSABLE": "NOT_ASSESSABLE",
    }.get(str(oracle_result.get("status") or ""), "INCONCLUSIVE")
    if result == "SUPPORTED" and not evidence_ids:
        result = "INCONCLUSIVE"
    return {
        "contract_version": RESULT_CONTRACT_VERSION,
        "source_finding_id": source_finding_id,
        "scenario_id": scenario_id,
        "agent_run_id": agent_run_id,
        "result": result,
        "evidence_ids": list(evidence_ids),
        "artifact_ids": list(artifact_ids or []),
        "oracle_results": [oracle_result],
        "confidence": max(0.0, min(1.0, confidence)),
        "summary": summary[:1000],
        "limitations": limitations[:4000],
        "recommended_next_manual_step": "Collect additional target-correlated evidence." if result == "INCONCLUSIVE" else "",
    }


def evaluate_playbook(playbook_id: str, evidence: dict[str, Any]) -> dict[str, Any]:
    playbook = validate_playbook_selection(playbook_id)
    oracle = ORACLES[playbook["oracle_id"]]
    return oracle(evidence)


def record_dynamic_validation(*, finding=None, playbook_id: str, evidence: dict[str, Any], audit=None, agent_run=None, hypothesis=None, action_decision=None, evidence_records=None, confidence: float = 0.0, rule_id: str | None = None, scenario_id: str = "") -> DynamicValidationResult:
    playbook = validate_playbook_selection(playbook_id)
    oracle_result = evaluate_playbook(playbook_id, evidence)
    evidence_records = list(evidence_records or [])
    result_envelope = build_validation_result(
        source_finding_id=finding.pk if finding is not None else 0,
        scenario_id=scenario_id,
        agent_run_id=agent_run.pk if agent_run is not None else None,
        oracle_result=oracle_result,
        evidence_ids=[item.pk for item in evidence_records],
        confidence=confidence,
        summary=oracle_result["summary"],
        limitations=playbook["limitations"],
    )
    result = DynamicValidationResult.objects.create(
        audit=audit or finding.audit,
        finding=finding,
        rule_id=rule_id or (finding.rule_id if finding is not None else "DYNAMIC-PLAYBOOK"),
        playbook_id=playbook_id,
        agent_run=agent_run,
        hypothesis=hypothesis,
        action_decision=action_decision,
        oracle_id=playbook["oracle_id"],
        oracle_result={**oracle_result, "result_contract": result_envelope},
        validation_status=result_envelope["result"],
        confidence=max(0.0, min(1.0, confidence)),
        safe_summary=oracle_result["summary"][:1000],
        limitations=playbook["limitations"],
    )
    if evidence_records:
        result.evidence.set(evidence_records)
    return result
