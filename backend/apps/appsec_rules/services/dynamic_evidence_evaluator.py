"""Deterministic rules over bounded AgentRun evidence.

These rules create assessment observations and coverage findings. They never
interpret planner prose and never assert a vulnerability or malware verdict.
"""

from __future__ import annotations

from typing import Any

from django.db import transaction

from apps.appsec_rules.models import RuleEvaluation
from apps.dynamic_analysis.models import AgentRun, AgentRunStep
from apps.evidence.models import Evidence
from apps.findings.models import Finding


EVALUATOR_VERSION = "1.0.0"
MAX_EVIDENCE_LINKS_PER_RULE = 50


@transaction.atomic
def evaluate_dynamic_evidence(run: AgentRun | int) -> dict[str, int]:
    run_id = run.pk if isinstance(run, AgentRun) else run
    run = AgentRun.objects.select_related("audit", "assessment_plan").get(pk=run_id)
    if (
        run.audit_id is None
        or run.objective != AgentRun.Objective.ASSESSMENT_PLAN_EXECUTION
        or run.status
        not in {
            AgentRun.Status.SUCCEEDED,
            AgentRun.Status.FAILED,
            AgentRun.Status.TIMEOUT,
        }
    ):
        return {
            "rules_evaluated": 0,
            "findings_created": 0,
            "findings_updated": 0,
            "evidence_linked": 0,
        }

    summary = {
        "rules_evaluated": 0,
        "findings_created": 0,
        "findings_updated": 0,
        "evidence_linked": 0,
    }
    rules = _resolved_rules(run)
    for rule in rules:
        summary["rules_evaluated"] += 1
        RuleEvaluation.objects.update_or_create(
            audit_id=run.audit_id,
            framework=RuleEvaluation.Framework.DYNAMIC_RUNTIME,
            rule_id=rule["rule_id"],
            defaults={
                "result": RuleEvaluation.Result.REVIEW_REQUIRED,
                "severity": rule["severity"].upper(),
                "confidence": RuleEvaluation.Confidence.HIGH,
                "title": rule["title"],
                "mapping_data": {
                    "category": rule["category"],
                    "agent_run_id": run.id,
                    "assessment_plan_id": run.assessment_plan_id,
                    "plan_hash": run.approved_plan_hash,
                    "deterministic_runtime_rule": True,
                    "vulnerability_verdict": False,
                },
                "evidence_summary": rule["evidence_summary"],
                "remediation": rule["recommendation"],
                "requires_manual_validation": True,
                "evaluator_version": EVALUATOR_VERSION,
            },
        )
        finding, created = Finding.objects.update_or_create(
            audit_id=run.audit_id,
            rule_id=rule["rule_id"],
            defaults={
                "title": rule["title"],
                "severity": rule["severity"],
                "confidence": "High",
                "standard": "MSAP Dynamic Runtime",
                "category": rule["category"],
                "description": rule["description"],
                "mapping_data": {
                    "deterministic_rule": rule["rule_id"],
                    "latest_agent_run_id": run.id,
                    "latest_plan_hash": run.approved_plan_hash,
                    "vulnerability_verdict": False,
                },
                "recommendation": rule["recommendation"],
                "false_positive_guidance": rule["false_positive_guidance"],
                "requires_manual_validation": True,
            },
        )
        summary["findings_created" if created else "findings_updated"] += 1
        summary["evidence_linked"] += _link_evidence(
            finding=finding,
            evidence_ids=rule["evidence_ids"],
            rule_id=rule["rule_id"],
        )
    return summary


def _resolved_rules(run: AgentRun) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    frida_steps = list(
        AgentRunStep.objects.filter(
            run=run,
            tool_name="frida_run_js",
            status=AgentRunStep.Status.SUCCEEDED,
        ).order_by("id")[:MAX_EVIDENCE_LINKS_PER_RULE]
    )
    confirmed_steps = [
        step for step in frida_steps if _contains_confirmed_ui_event(step.observation)
    ]
    if confirmed_steps:
        evidence_ids = _evidence_ids(confirmed_steps)
        rules.append(
            {
                "rule_id": "MSAP-DYN-001",
                "title": "Controlled runtime instrumentation was evidenced",
                "severity": "Informational",
                "category": "DYNAMIC_RUNTIME_EVIDENCE",
                "description": (
                    "The controlled Frida capability emitted a structured successful "
                    "UI-modification event from the authorized target process. This "
                    "confirms instrumentation evidence, not a vulnerability."
                ),
                "evidence_summary": (
                    f"{len(confirmed_steps)} approved frida_run_js step(s) emitted "
                    "a structured ui_modification success event."
                ),
                "recommendation": (
                    "Review the linked before/after evidence and decide whether a "
                    "separate security hypothesis warrants another approved cycle."
                ),
                "false_positive_guidance": (
                    "Confirm the event belongs to the authorized package and compare "
                    "the linked screenshot/UI evidence before treating it as proof."
                ),
                "evidence_ids": evidence_ids,
            }
        )

    empty_ui_steps = [
        step
        for step in AgentRunStep.objects.filter(
            run=run,
            tool_name="dump_ui",
            status=AgentRunStep.Status.SUCCEEDED,
        ).order_by("id")[:MAX_EVIDENCE_LINKS_PER_RULE]
        if _ui_node_count(step.observation) == 0
    ]
    if empty_ui_steps:
        rules.append(
            {
                "rule_id": "MSAP-DYN-002",
                "title": "UI hierarchy evidence requires review",
                "severity": "Informational",
                "category": "ASSESSMENT_COVERAGE",
                "description": (
                    "A UI-dump capability completed without parsed UI nodes. The "
                    "capture is not treated as successful hierarchy evidence."
                ),
                "evidence_summary": (
                    f"{len(empty_ui_steps)} dump_ui step(s) returned zero parsed nodes."
                ),
                "recommendation": (
                    "Verify foreground-package state and repeat UI capture in a new "
                    "approved assessment cycle if hierarchy evidence is required."
                ),
                "false_positive_guidance": (
                    "Some surfaces are not exposed to UIAutomator; inspect the precise "
                    "tool failure/partial reason before retrying."
                ),
                "evidence_ids": _evidence_ids(empty_ui_steps),
            }
        )

    if run.status in {AgentRun.Status.FAILED, AgentRun.Status.TIMEOUT}:
        failed_steps = list(
            run.steps.filter(
                status__in=[
                    AgentRunStep.Status.FAILED,
                    AgentRunStep.Status.TIMEOUT,
                ]
            ).order_by("id")[:MAX_EVIDENCE_LINKS_PER_RULE]
        )
        rules.append(
            {
                "rule_id": "MSAP-DYN-003",
                "title": "Dynamic assessment execution was incomplete",
                "severity": "Informational",
                "category": "ASSESSMENT_COVERAGE",
                "description": (
                    "The approved bounded run did not complete every assessment step. "
                    "This is a coverage limitation, not an application vulnerability."
                ),
                "evidence_summary": (
                    f"AgentRun {run.id} ended {run.status} with "
                    f"{len(failed_steps)} failed or timed-out step(s)."
                ),
                "recommendation": (
                    "Review the linked controlled failures before proposing a bounded "
                    "follow-up plan."
                ),
                "false_positive_guidance": (
                    "Infrastructure failures may be unrelated to application behavior."
                ),
                "evidence_ids": _evidence_ids(failed_steps),
            }
        )
    return rules


def _contains_confirmed_ui_event(observation: Any) -> bool:
    if not isinstance(observation, dict):
        return False
    data = observation.get("data")
    if not isinstance(data, dict):
        return False
    events = data.get("events")
    if not isinstance(events, list):
        return False
    return any(
        isinstance(event, dict)
        and event.get("type") == "ui_modification"
        and event.get("success") is True
        for event in events[:200]
    )


def _ui_node_count(observation: Any) -> int | None:
    if not isinstance(observation, dict):
        return None
    data = observation.get("data")
    if not isinstance(data, dict):
        return None
    node_count = data.get("node_count")
    if isinstance(node_count, bool) or not isinstance(node_count, int):
        return None
    return node_count


def _evidence_ids(steps: list[AgentRunStep]) -> list[int]:
    if not steps:
        return []
    return list(
        Evidence.objects.filter(agent_run_step_id__in=[step.id for step in steps])
        .order_by("id")
        .values_list("id", flat=True)[:MAX_EVIDENCE_LINKS_PER_RULE]
    )


def _link_evidence(*, finding: Finding, evidence_ids: list[int], rule_id: str) -> int:
    linked = 0
    for evidence in Evidence.objects.filter(id__in=evidence_ids).order_by("id")[
        :MAX_EVIDENCE_LINKS_PER_RULE
    ]:
        if evidence.finding_id not in {None, finding.id}:
            continue
        provenance = (
            dict(evidence.provenance)
            if isinstance(evidence.provenance, dict)
            else {}
        )
        provenance.update(
            {
                "deterministic_rule_id": rule_id,
                "finding_id": finding.id,
                "finding_source": "DETERMINISTIC_DYNAMIC_EVIDENCE",
            }
        )
        changed = evidence.finding_id != finding.id
        evidence.finding = finding
        evidence.provenance = provenance
        evidence.save(update_fields=["finding", "provenance"])
        linked += int(changed)
    return linked
