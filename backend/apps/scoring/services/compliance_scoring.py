from django.db import transaction

from apps.appsec_rules.models import RuleEvaluation
from apps.indicators.models import SuspiciousIndicator
from apps.scoring.models import ComplianceScore


ATTCK_TRIAGE_NOTE = (
    "ATT&CK Mobile indicators are triage signals, not malware verdicts."
)


@transaction.atomic
def calculate_masvs_compliance(audit_id: int) -> dict:
    results = list(
        RuleEvaluation.objects.filter(
            audit_id=audit_id,
            framework=RuleEvaluation.Framework.MASVS,
        ).values_list("result", flat=True)
    )
    passed_rules = results.count(RuleEvaluation.Result.PASS)
    failed_rules = results.count(RuleEvaluation.Result.FAIL)
    review_required = results.count(RuleEvaluation.Result.REVIEW_REQUIRED)
    not_evaluated = results.count(RuleEvaluation.Result.NOT_EVALUATED)
    not_applicable = results.count(RuleEvaluation.Result.NOT_APPLICABLE)
    applicable_rules = passed_rules + failed_rules + review_required
    evaluated_rules = applicable_rules + not_applicable
    score = round((passed_rules / applicable_rules) * 100, 2) if applicable_rules else 0.0

    ComplianceScore.objects.update_or_create(
        audit_id=audit_id,
        standard="MASVS",
        defaults={"score": score},
    )

    return {
        "standard": "MASVS",
        "score": score,
        "evaluated_rules": evaluated_rules,
        "applicable_rules": applicable_rules,
        "failed_rules": failed_rules,
        "passed_rules": passed_rules,
        "review_required": review_required,
        "not_evaluated": not_evaluated,
        "not_applicable": not_applicable,
        "partial_coverage": not_evaluated > 0,
        "coverage_warning": (
            f"{not_evaluated} catalog rule(s) were not evaluated and are not counted as passing."
            if not_evaluated
            else ""
        ),
    }


def summarize_attck_triage(audit_id: int) -> dict:
    indicator_count = SuspiciousIndicator.objects.filter(audit_id=audit_id).count()
    if indicator_count >= 2:
        triage_level = "High"
    elif indicator_count == 1:
        triage_level = "Medium"
    else:
        triage_level = "Low"

    return {
        "triage_indicators": indicator_count,
        "triage_level": triage_level,
        "note": ATTCK_TRIAGE_NOTE,
    }
