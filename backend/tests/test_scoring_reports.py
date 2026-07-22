import json

import pytest
from rest_framework.test import APIClient

from apps.apk_files.models import APKFile
from apps.audits.models import AnalysisJob, Audit
from apps.evidence.models import Evidence
from apps.findings.models import Finding
from apps.indicators.models import SuspiciousIndicator
from apps.normalization.models import NormalizedArtifact
from apps.projects.models import Project
from apps.reports.models import Report
from apps.scoring.models import ComplianceScore, RiskScore
from apps.scoring.services.compliance_scoring import calculate_masvs_compliance
from apps.scoring.services.risk_scoring import calculate_risk_score


@pytest.fixture
def audit(db):
    project = Project.objects.create(
        name="Scoring project",
        description="JSON reporting tests",
    )
    return Audit.objects.create(project=project, name="Scoring audit")


@pytest.mark.django_db
def test_risk_scoring_creates_and_updates_score_by_severity(audit):
    finding = _create_finding(audit, "MSAP-AND-001", "Low")

    low_summary = calculate_risk_score(audit.id)
    finding.severity = "High"
    finding.save(update_fields=["severity"])
    high_summary = calculate_risk_score(audit.id)

    risk_score = RiskScore.objects.get(audit=audit)
    assert low_summary["score"] == 10
    assert high_summary == {
        "score": 70,
        "severity": "High",
        "finding_count": 1,
        "indicator_count": 0,
        "raw_weight": 7,
    }
    assert risk_score.score == 70
    assert RiskScore.objects.filter(audit=audit).count() == 1


@pytest.mark.django_db
def test_masvs_compliance_updates_for_zero_one_and_two_failed_rules(audit):
    fully_compliant = calculate_masvs_compliance(audit.id)
    _create_finding(audit, "MSAP-AND-001", "High")
    half_compliant = calculate_masvs_compliance(audit.id)
    _create_finding(audit, "MSAP-AND-002", "Medium")
    non_compliant = calculate_masvs_compliance(audit.id)

    assert fully_compliant["score"] == 100
    assert half_compliant["score"] == 50
    assert non_compliant["score"] == 0
    assert non_compliant["evaluated_rules"] == 2
    assert non_compliant["failed_rules"] == 2
    assert ComplianceScore.objects.filter(
        audit=audit,
        standard="MASVS",
    ).count() == 1


@pytest.mark.django_db
def test_json_report_endpoint_returns_results_without_raw_manifest(audit):
    apk_file = APKFile.objects.create(
        audit=audit,
        package_name="com.example.scored",
        version_name="1.0.0",
        sha256="a" * 64,
        size_bytes=1024,
    )
    finding = _create_finding(audit, "MSAP-AND-001", "High")
    indicator = _create_indicator(audit, "MSAP-MOB-001", "Medium")
    Evidence.objects.create(
        audit=audit,
        finding=finding,
        evidence_type="manifest_attribute",
        source="AndroidManifest.xml",
        snippet="application.debuggable=true",
        redacted=False,
    )
    Evidence.objects.create(
        audit=audit,
        indicator=indicator,
        evidence_type="manifest_permission",
        source="AndroidManifest.xml",
        snippet="permission=android.permission.READ_SMS",
        redacted=False,
    )
    raw_manifest_marker = "RAW_MANIFEST_XML_MUST_NOT_APPEAR"
    NormalizedArtifact.objects.create(
        audit=audit,
        apk_file=apk_file,
        artifact_type=NormalizedArtifact.ArtifactType.MANIFEST,
        source="test",
        normalized_data={
            "raw_manifest_xml": f"<manifest>{raw_manifest_marker}</manifest>"
        },
    )
    AnalysisJob.objects.create(
        audit=audit,
        status=AnalysisJob.Status.COMPLETED,
        result_summary={
            "summary": {
                "analyzers_run": ["test"],
                "normalized_artifacts_created": 1,
                "raw_manifest_xml": raw_manifest_marker,
            }
        },
    )

    client = APIClient()
    response = client.get(f"/api/audits/{audit.id}/report/json/")
    second_response = client.get(f"/api/audits/{audit.id}/report/json/")

    assert response.status_code == 200
    assert second_response.status_code == 200
    data = response.json()
    assert data["audit"]["id"] == audit.id
    assert data["project"]["id"] == audit.project_id
    assert data["apk"]["package_name"] == "com.example.scored"
    assert len(data["findings"]) == 1
    assert len(data["indicators"]) == 1
    assert len(data["evidence"]) == 2
    assert data["summary"]["risk"]["score"] == 100
    assert data["summary"]["masvs_compliance"]["score"] == 50
    assert data["normalized_artifacts"]["by_type"] == {"MANIFEST": 1}
    assert data["limitations"] == [
        "Static analysis only",
        "ATT&CK indicators are triage signals, not malware verdicts",
        "Dynamic behavior is not observed",
    ]
    assert raw_manifest_marker not in json.dumps(data)
    assert Report.objects.filter(
        audit=audit,
        report_type=Report.ReportType.JSON,
    ).count() == 1


@pytest.mark.django_db
def test_attck_report_summary_is_triage_only(audit):
    _create_indicator(audit, "MSAP-MOB-001", "Medium")

    response = APIClient().get(f"/api/audits/{audit.id}/report/json/")

    triage = response.json()["summary"]["attack_mobile_triage"]
    assert triage == {
        "triage_indicators": 1,
        "triage_level": "Medium",
        "note": "ATT&CK Mobile indicators are triage signals, not malware verdicts.",
    }
    assert "malware_score" not in response.json()["summary"]


def _create_finding(audit: Audit, rule_id: str, severity: str) -> Finding:
    return Finding.objects.create(
        audit=audit,
        rule_id=rule_id,
        title=f"Finding {rule_id}",
        severity=severity,
        confidence="High",
        standard="OWASP MASVS",
    )


def _create_indicator(
    audit: Audit,
    indicator_id: str,
    severity: str,
) -> SuspiciousIndicator:
    return SuspiciousIndicator.objects.create(
        audit=audit,
        indicator_id=indicator_id,
        title=f"Indicator {indicator_id}",
        severity=severity,
        confidence="Medium",
        triage_interpretation="Review in application context.",
    )
