from __future__ import annotations

from hashlib import sha256
import json
from typing import Any

from django.db import transaction
from django.utils import timezone

from apps.apk_files.models import APKFile
from apps.dynamic_analysis.models import (
    AgentRun,
    AssessmentPlan,
    DynamicValidationResult,
    FindingValidationMission,
)
from apps.dynamic_analysis.services.assessment_agent import AssessmentAgent
from apps.dynamic_analysis.services.assessment_executor import AssessmentExecutionError
from apps.dynamic_analysis.services.assessment_planner import (
    AssessmentPlannerError,
    AssessmentPlannerService,
    PlanPolicyError,
    configured_planner_provider,
)
from apps.dynamic_analysis.services.dynamic_validation_scenario import (
    scenario_from_finding,
)
from apps.dynamic_analysis.services.playbook_catalog import (
    executable_playbooks_for_finding,
    playbooks_for_finding,
)
from apps.findings.models import Finding


class FindingValidationMissionError(RuntimeError):
    def __init__(self, message: str, *, code: str, http_status: int = 400):
        super().__init__(message)
        self.code = code
        self.http_status = http_status


def _json_hash(value: Any) -> str:
    return sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


def _latest_apk_for_audit(audit_id: int, target_package: str | None = None) -> APKFile:
    queryset = APKFile.objects.filter(audit_id=audit_id).order_by("-created_at")
    if target_package:
        queryset = queryset.filter(package_name=target_package)
    apk = queryset.first()
    if apk is None or not apk.package_name:
        raise FindingValidationMissionError(
            "The audit has no authorized APK package metadata for dynamic validation.",
            code="MISSION_TARGET_PACKAGE_UNAVAILABLE",
            http_status=409,
        )
    return apk


def generate_finding_validation_mission(
    *,
    finding: Finding,
    requested_by,
    target_package: str | None = None,
) -> FindingValidationMission:
    """Generate and backend-validate one bounded mission for one static finding."""

    apk = _latest_apk_for_audit(finding.audit_id, target_package)
    executable = executable_playbooks_for_finding(finding)
    all_playbooks = playbooks_for_finding(finding)
    if not executable:
        playbook = all_playbooks[0] if all_playbooks else None
        scenario = scenario_from_finding(
            audit_id=finding.audit_id,
            target_package=apk.package_name,
            finding={
                "finding_id": finding.pk,
                "rule_id": finding.rule_id,
                "title": finding.title,
            },
            family="NOT_ASSESSABLE_WITH_CURRENT_TOOLS",
            tools=[],
            evidence=[],
            steps=[
                {
                    "sequence": 1,
                    "step_id": "not_dynamically_testable",
                    "objective": "Explain the current dynamic validation limitation.",
                    "rationale": "No approved Tool Gateway playbook can validate this static finding dynamically.",
                    "tools": [],
                    "expected_observation": "No runtime action is attempted.",
                    "success_condition": "The limitation is recorded for the auditor.",
                    "evidence_requirements": ["tool_output"],
                    "dependencies": [],
                }
            ],
            reason=(
                playbook.get("limitations")
                if playbook
                else "No supported runtime validation family maps to this static finding."
            ),
        )
        return _create_mission_from_parts(
            finding=finding,
            apk=apk,
            status=FindingValidationMission.Status.NOT_DYNAMICALLY_TESTABLE,
            scenario=scenario,
            assessment_plan=None,
            playbook=playbook,
            requested_by=requested_by,
            final_conclusion=scenario["not_assessable_reason"],
            limitations=scenario["not_assessable_reason"],
        )

    objective = f"Validate static finding {finding.rule_id} dynamically."
    scope = (
        "Use only the approved Tool Gateway and authorized Android lab target. "
        "Generate a bounded PoC mission for the selected finding, collect "
        "target-correlated evidence, and stop if current tools cannot validate it."
    )
    try:
        provider = configured_planner_provider(model_profile="ECONOMY")
        service = AssessmentPlannerService(provider)
        plan = service.generate(
            audit=finding.audit,
            target_package=apk.package_name,
            objective=objective,
            scope=scope,
            source_finding=finding,
            requested_by=requested_by,
        )
        plan = service.validate(plan)
    except AssessmentPlannerError:
        raise
    except Exception as exc:
        raise FindingValidationMissionError(
            "The validation mission could not be generated safely.",
            code="MISSION_GENERATION_FAILED",
            http_status=503,
        ) from exc

    playbook = executable[0]
    return _create_mission_from_parts(
        finding=finding,
        apk=apk,
        status=FindingValidationMission.Status.VALIDATED,
        scenario=plan.scenario_contract,
        assessment_plan=plan,
        playbook=playbook,
        requested_by=requested_by,
        final_conclusion="Awaiting auditor approval and execution.",
        limitations=playbook.get("limitations", ""),
    )


def _create_mission_from_parts(
    *,
    finding: Finding,
    apk: APKFile,
    status: str,
    scenario: dict[str, Any],
    assessment_plan: AssessmentPlan | None,
    playbook: dict[str, Any] | None,
    requested_by,
    final_conclusion: str,
    limitations: str,
) -> FindingValidationMission:
    scenario_hash = _json_hash(scenario)
    mission_seed = {
        "audit_id": finding.audit_id,
        "finding_id": finding.pk,
        "target_package": apk.package_name,
        "scenario_hash": scenario_hash,
        "assessment_plan_id": assessment_plan.pk if assessment_plan else None,
    }
    return FindingValidationMission.objects.create(
        audit=finding.audit,
        apk=apk,
        finding=finding,
        assessment_plan=assessment_plan,
        target_package=apk.package_name,
        status=status,
        scenario_contract=scenario,
        scenario_hash=scenario_hash,
        mission_hash=_json_hash(mission_seed),
        validation_family=scenario.get("validation_strategy", ""),
        playbook_id=playbook.get("playbook_id", "") if playbook else "",
        hypothesis=scenario.get("validation_hypothesis", ""),
        final_conclusion=final_conclusion,
        limitations=limitations,
        provider=assessment_plan.planner_provider if assessment_plan else "DETERMINISTIC",
        model=assessment_plan.planner_model if assessment_plan else "msap-not-testable-v1",
        provider_metadata=assessment_plan.provider_metadata if assessment_plan else {},
        allowed_capabilities=scenario.get("supported_tool_capabilities", []),
        budgets={
            "max_decisions": scenario.get("max_decisions"),
            "max_tool_calls": scenario.get("max_tool_calls"),
            "max_duration_seconds": scenario.get("max_duration_seconds"),
        },
        created_by=requested_by,
    )


def approve_finding_validation_mission(
    *,
    mission: FindingValidationMission,
    approved_by,
) -> FindingValidationMission:
    if mission.status == FindingValidationMission.Status.APPROVED:
        return mission
    if mission.status == FindingValidationMission.Status.NOT_DYNAMICALLY_TESTABLE:
        raise FindingValidationMissionError(
            "This finding is not dynamically testable with the current approved tools.",
            code="MISSION_NOT_DYNAMICALLY_TESTABLE",
            http_status=409,
        )
    if mission.status != FindingValidationMission.Status.VALIDATED:
        raise FindingValidationMissionError(
            "Only a backend-validated mission can be approved.",
            code="MISSION_NOT_VALIDATED",
            http_status=409,
        )
    if mission.assessment_plan is None:
        raise FindingValidationMissionError(
            "The mission has no linked approved-plan candidate.",
            code="MISSION_PLAN_MISSING",
            http_status=409,
        )
    if mission.finding.audit_id != mission.audit_id:
        raise FindingValidationMissionError(
            "The mission finding no longer belongs to the mission audit.",
            code="MISSION_AUDIT_MISMATCH",
        )
    if mission.assessment_plan.target_package != mission.target_package:
        raise FindingValidationMissionError(
            "The mission target package failed its integrity check.",
            code="MISSION_TARGET_PACKAGE_MISMATCH",
        )
    try:
        plan = AssessmentPlannerService.approve(
            mission.assessment_plan,
            approved_by=approved_by,
        )
    except PlanPolicyError as exc:
        raise FindingValidationMissionError(
            str(exc),
            code=exc.code,
            http_status=exc.http_status,
        ) from None
    with transaction.atomic():
        mission.assessment_plan = plan
        mission.status = FindingValidationMission.Status.APPROVED
        mission.approved_by = approved_by
        mission.approved_at = timezone.now()
        mission.save(
            update_fields=[
                "assessment_plan",
                "status",
                "approved_by",
                "approved_at",
                "updated_at",
            ]
        )
    return mission


def start_finding_validation_mission(
    *,
    mission: FindingValidationMission,
    requested_by,
    decision_provider_name: str | None = None,
) -> AgentRun:
    if mission.status not in {
        FindingValidationMission.Status.APPROVED,
        FindingValidationMission.Status.RUNNING,
    }:
        raise FindingValidationMissionError(
            "Only an approved validation mission can be started.",
            code="MISSION_NOT_APPROVED",
            http_status=409,
        )
    if mission.agent_run_id:
        return mission.agent_run
    if mission.assessment_plan is None:
        raise FindingValidationMissionError(
            "The approved mission has no linked plan.",
            code="MISSION_PLAN_MISSING",
            http_status=409,
        )
    try:
        run = AssessmentAgent().create_run(
            plan=mission.assessment_plan,
            requested_by=requested_by,
            decision_provider_name=decision_provider_name,
        )
    except AssessmentExecutionError as exc:
        raise FindingValidationMissionError(
            str(exc),
            code=exc.code,
            http_status=exc.http_status,
        ) from None
    with transaction.atomic():
        mission.agent_run = run
        mission.status = FindingValidationMission.Status.RUNNING
        mission.started_at = timezone.now()
        mission.save(update_fields=["agent_run", "status", "started_at", "updated_at"])
    return run


def refresh_mission_from_run(run: AgentRun) -> FindingValidationMission | None:
    mission = (
        FindingValidationMission.objects.select_related("finding", "agent_run")
        .filter(agent_run=run)
        .first()
    )
    if mission is None:
        return None
    evidence = list(run.evidence_records.all()[:100])
    result = (
        DynamicValidationResult.objects.filter(agent_run=run, finding=mission.finding)
        .order_by("-created_at")
        .first()
    )
    if result is not None:
        status = _mission_status_from_result(result)
        oracle = result.oracle_result if isinstance(result.oracle_result, dict) else {}
        conclusion = result.safe_summary or oracle.get("summary", "")
        limitations = result.limitations or mission.limitations
    elif run.status == AgentRun.Status.SUCCEEDED:
        status = FindingValidationMission.Status.INCONCLUSIVE
        oracle = {}
        conclusion = "The mission completed, but no deterministic oracle result was produced."
        limitations = mission.limitations
    elif run.status in {AgentRun.Status.FAILED, AgentRun.Status.TIMEOUT}:
        status = FindingValidationMission.Status.BLOCKED
        oracle = {}
        conclusion = run.failure_message or "The lab/tool/runtime prevented completion."
        limitations = mission.limitations
    else:
        return mission
    mission.status = status
    mission.dynamic_validation_result = result
    mission.oracle_result = oracle
    mission.final_conclusion = conclusion[:4000]
    mission.limitations = limitations
    mission.completed_at = timezone.now()
    mission.save(
        update_fields=[
            "status",
            "dynamic_validation_result",
            "oracle_result",
            "final_conclusion",
            "limitations",
            "completed_at",
            "updated_at",
        ]
    )
    if evidence:
        mission.evidence.set(evidence)
    return mission


def _mission_status_from_result(result: DynamicValidationResult) -> str:
    value = (
        result.oracle_result.get("result_contract", {}).get("result")
        if isinstance(result.oracle_result, dict)
        else ""
    ) or result.validation_status
    return {
        "SUPPORTED": FindingValidationMission.Status.CONFIRMED,
        "CONFIRMED": FindingValidationMission.Status.CONFIRMED,
        "REJECTED": FindingValidationMission.Status.NOT_REPRODUCED,
        "REFUTED": FindingValidationMission.Status.NOT_REPRODUCED,
        "INCONCLUSIVE": FindingValidationMission.Status.INCONCLUSIVE,
        "NOT_ASSESSABLE": FindingValidationMission.Status.NOT_DYNAMICALLY_TESTABLE,
        "STATIC_ONLY": FindingValidationMission.Status.NOT_DYNAMICALLY_TESTABLE,
        "FAILED": FindingValidationMission.Status.FAILED,
    }.get(str(value), FindingValidationMission.Status.INCONCLUSIVE)
