from django.db import transaction

from apps.findings.models import Finding
from apps.scoring.models import RiskScore


SEVERITY_WEIGHTS = {
    "Critical": 10,
    "High": 7,
    "Medium": 4,
    "Low": 1,
}
CONFIDENCE_WEIGHTS = {"High": 1.0, "Medium": 0.75, "Low": 0.5}


@transaction.atomic
def calculate_risk_score(audit_id: int) -> dict:
    findings = list(
        Finding.objects.filter(audit_id=audit_id).values(
            "rule_id", "severity", "confidence"
        )
    )
    finding_weights = [
        SEVERITY_WEIGHTS.get(item["severity"].title(), 0)
        * CONFIDENCE_WEIGHTS.get(item["confidence"].title(), 0.5)
        for item in findings
    ]
    raw_weight = round(sum(finding_weights), 2)

    # Each weight point contributes 10 score points; cumulative risk is capped
    # at 100 so the result remains a small, transparent MVP score.
    score = round(min(raw_weight * 10, 100), 2)
    severity = _score_severity(score)

    RiskScore.objects.update_or_create(
        audit_id=audit_id,
        defaults={"score": score, "severity": severity},
    )

    return {
        "score": score,
        "severity": severity,
        "finding_count": len(finding_weights),
        "indicator_count": 0,
        "raw_weight": raw_weight,
        "method": "Unique failed findings weighted by severity and confidence; ATT&CK triage excluded.",
    }


def _score_severity(score: float) -> str:
    if score >= 81:
        return "Critical"
    if score >= 61:
        return "High"
    if score >= 31:
        return "Medium"
    return "Low"
