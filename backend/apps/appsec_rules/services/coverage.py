from collections import Counter, defaultdict

from apps.analyzers.models import RawAnalyzerResult
from apps.appsec_rules.models import RuleEvaluation


def calculate_rule_coverage(audit_id: int) -> dict:
    evaluations = list(
        RuleEvaluation.objects.filter(audit_id=audit_id).values(
            "framework", "result", "mapping_data"
        )
    )
    masvs = [item for item in evaluations if item["framework"] == RuleEvaluation.Framework.MASVS]
    attack = [
        item
        for item in evaluations
        if item["framework"] == RuleEvaluation.Framework.ATTACK_MOBILE
    ]
    analyzer_states = list(
        RawAnalyzerResult.objects.filter(audit_id=audit_id).values(
            "analyzer_name", "status", "error_message"
        )
    )
    return {
        "total_catalog_rules": len(evaluations),
        "applicable": sum(
            item["result"]
            not in {RuleEvaluation.Result.NOT_APPLICABLE, RuleEvaluation.Result.NOT_EVALUATED}
            for item in evaluations
        ),
        "evaluated": sum(item["result"] != RuleEvaluation.Result.NOT_EVALUATED for item in evaluations),
        "passed": _count(evaluations, RuleEvaluation.Result.PASS),
        "failed": _count(evaluations, RuleEvaluation.Result.FAIL),
        "review_required": _count(evaluations, RuleEvaluation.Result.REVIEW_REQUIRED),
        "not_applicable": _count(evaluations, RuleEvaluation.Result.NOT_APPLICABLE),
        "not_evaluated": _count(evaluations, RuleEvaluation.Result.NOT_EVALUATED),
        "partial_coverage": any(
            item["result"] == RuleEvaluation.Result.NOT_EVALUATED for item in evaluations
        ),
        "analyzers": {
            "completed": [
                item["analyzer_name"]
                for item in analyzer_states
                if item["status"] == RawAnalyzerResult.Status.COMPLETED
            ],
            "skipped": [
                {"name": item["analyzer_name"], "reason": _safe_reason(item["error_message"])}
                for item in analyzer_states
                if item["status"] == RawAnalyzerResult.Status.SKIPPED
            ],
            "failed": [
                {"name": item["analyzer_name"], "reason": _safe_reason(item["error_message"])}
                for item in analyzer_states
                if item["status"] == RawAnalyzerResult.Status.FAILED
            ],
        },
        "masvs": {
            "total": len(masvs),
            "by_category": _breakdown(masvs, "masvs_category"),
        },
        "attack_mobile": {
            "total": len(attack),
            "by_tactic": _breakdown(attack, "tactic"),
            "matched_techniques": sorted(
                {
                    item["mapping_data"].get("technique_id")
                    for item in attack
                    if item["result"] == RuleEvaluation.Result.REVIEW_REQUIRED
                    and item["mapping_data"].get("technique_id")
                }
            ),
            "note": "Triage signal — not a malware verdict.",
        },
    }


def _count(items: list[dict], result: str) -> int:
    return sum(item["result"] == result for item in items)


def _breakdown(items: list[dict], mapping_field: str) -> dict:
    counts: dict[str, Counter] = defaultdict(Counter)
    for item in items:
        label = item["mapping_data"].get(mapping_field) or "Unmapped"
        for part in str(label).split(","):
            counts[part.strip()][item["result"].lower()] += 1
    return {
        label: {"total": sum(values.values()), **dict(sorted(values.items()))}
        for label, values in sorted(counts.items())
    }


def _safe_reason(value: str) -> str:
    if not value:
        return "No analyzer result was produced."
    allowed = {
        "Analyzer is disabled.",
        "Analyzer capability is unavailable.",
        "No local APK path is available.",
        "Advanced static APK inspection failed safely.",
    }
    return value if value in allowed else "Analyzer did not complete; review worker logs."
