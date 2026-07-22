from django.db import transaction

from apps.findings.models import Finding
from apps.indicators.models import SuspiciousIndicator
from apps.scoring.models import RiskScore


SEVERITY_WEIGHTS = {
    "Critical": 10,
    "High": 7,
    "Medium": 4,
    "Low": 1,
}


@transaction.atomic
def calculate_risk_score(audit_id: int) -> dict:
    finding_severities = Finding.objects.filter(audit_id=audit_id).values_list(
        "severity",
        flat=True,
    )
    indicator_severities = SuspiciousIndicator.objects.filter(
        audit_id=audit_id
    ).values_list("severity", flat=True)

    finding_weights = [
        SEVERITY_WEIGHTS.get(severity, 0) for severity in finding_severities
    ]
    indicator_weights = [
        SEVERITY_WEIGHTS.get(severity, 0) for severity in indicator_severities
    ]
    raw_weight = sum(finding_weights) + sum(indicator_weights)

    # Each weight point contributes 10 score points; cumulative risk is capped
    # at 100 so the result remains a small, transparent MVP score.
    score = min(raw_weight * 10, 100)
    severity = _score_severity(score)

    RiskScore.objects.update_or_create(
        audit_id=audit_id,
        defaults={"score": score, "severity": severity},
    )

    return {
        "score": score,
        "severity": severity,
        "finding_count": len(finding_weights),
        "indicator_count": len(indicator_weights),
        "raw_weight": raw_weight,
    }


def _score_severity(score: int) -> str:
    if score >= 81:
        return "Critical"
    if score >= 61:
        return "High"
    if score >= 31:
        return "Medium"
    return "Low"
