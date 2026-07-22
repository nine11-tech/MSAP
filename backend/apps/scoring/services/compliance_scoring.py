from django.db import transaction

from apps.findings.models import Finding
from apps.indicators.models import SuspiciousIndicator
from apps.scoring.models import ComplianceScore


IMPLEMENTED_MASVS_RULE_IDS = ("MSAP-AND-001", "MSAP-AND-002")
ATTCK_TRIAGE_NOTE = (
    "ATT&CK Mobile indicators are triage signals, not malware verdicts."
)


@transaction.atomic
def calculate_masvs_compliance(audit_id: int) -> dict:
    evaluated_rules = len(IMPLEMENTED_MASVS_RULE_IDS)
    failed_rules = (
        Finding.objects.filter(
            audit_id=audit_id,
            rule_id__in=IMPLEMENTED_MASVS_RULE_IDS,
        )
        .values("rule_id")
        .distinct()
        .count()
    )
    passed_rules = evaluated_rules - failed_rules
    score = round((passed_rules / evaluated_rules) * 100, 2)

    ComplianceScore.objects.update_or_create(
        audit_id=audit_id,
        standard="MASVS",
        defaults={"score": score},
    )

    return {
        "standard": "MASVS",
        "score": score,
        "evaluated_rules": evaluated_rules,
        "failed_rules": failed_rules,
        "passed_rules": passed_rules,
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
