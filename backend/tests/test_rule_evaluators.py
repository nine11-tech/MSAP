import pytest

from apps.analyzers.models import RawAnalyzerResult
from apps.analyzers.services.base import AnalyzerResult
from apps.analyzers.services.registry import AnalyzerRegistry
from apps.appsec_rules.services.masvs_evaluator import evaluate_masvs_rules
from apps.apk_files.models import APKFile
from apps.audits.models import Audit
from apps.audits.services.analysis_orchestrator import AnalysisOrchestrator
from apps.evidence.models import Evidence
from apps.findings.models import Finding
from apps.indicators.models import SuspiciousIndicator
from apps.normalization.models import NormalizedArtifact
from apps.normalization.services.schemas import (
    NormalizedArtifactPayload,
    build_manifest_artifact,
)
from apps.projects.models import Project
from apps.storage.models import ObjectStorageReference
from apps.triage_rules.services.attck_evaluator import evaluate_attck_indicators


@pytest.fixture
def audit_and_apk(db):
    project = Project.objects.create(name="Rule evaluator project")
    audit = Audit.objects.create(project=project, name="Rule evaluator audit")
    storage_reference = ObjectStorageReference.objects.create(
        project=project,
        audit=audit,
        bucket="msap-apk-uploads",
        object_key="rule-tests/app.apk",
        object_type=ObjectStorageReference.ObjectType.APK_UPLOAD,
    )
    apk_file = APKFile.objects.create(
        audit=audit,
        storage_reference=storage_reference,
    )
    return audit, apk_file


@pytest.mark.django_db
def test_masvs_evaluator_creates_debuggable_finding_and_evidence(audit_and_apk):
    audit, apk_file = audit_and_apk
    _create_manifest(audit, apk_file, application={"debuggable": True})

    summary = evaluate_masvs_rules(audit)

    finding = Finding.objects.get(audit=audit, rule_id="MSAP-AND-001")
    evidence = Evidence.objects.get(finding=finding)
    assert summary == {
        "evaluated_rules": 2,
        "findings_created": 1,
        "findings_existing": 0,
        "evidence_created": 1,
    }
    assert evidence.snippet == "application.debuggable=true"
    assert evidence.redacted is False


@pytest.mark.django_db
def test_masvs_evaluator_creates_allow_backup_finding(audit_and_apk):
    audit, apk_file = audit_and_apk
    _create_manifest(audit, apk_file, application={"allow_backup": True})

    summary = evaluate_masvs_rules(audit)

    assert summary["findings_created"] == 1
    assert Finding.objects.filter(
        audit=audit,
        rule_id="MSAP-AND-002",
    ).exists()


@pytest.mark.django_db
def test_attck_evaluator_creates_sms_indicator_and_evidence(audit_and_apk):
    audit, apk_file = audit_and_apk
    _create_manifest(
        audit,
        apk_file,
        permissions=["android.permission.READ_SMS"],
    )

    summary = evaluate_attck_indicators(audit)

    indicator = SuspiciousIndicator.objects.get(
        audit=audit,
        indicator_id="MSAP-MOB-001",
    )
    evidence = Evidence.objects.get(indicator=indicator)
    assert summary == {
        "evaluated_indicators": 2,
        "indicators_created": 1,
        "indicators_existing": 0,
        "evidence_created": 1,
    }
    assert evidence.snippet == "permission=android.permission.READ_SMS"
    assert evidence.redacted is False


@pytest.mark.django_db
def test_attck_evaluator_creates_accessibility_service_indicator(audit_and_apk):
    audit, apk_file = audit_and_apk
    _create_manifest(
        audit,
        apk_file,
        components=[
            {
                "type": "service",
                "name": "com.example.AssistService",
                "permission": "android.permission.BIND_ACCESSIBILITY_SERVICE",
            }
        ],
    )

    summary = evaluate_attck_indicators(audit)

    indicator = SuspiciousIndicator.objects.get(
        audit=audit,
        indicator_id="MSAP-MOB-002",
    )
    assert summary["indicators_created"] == 1
    assert indicator.title == "Accessibility service usage"
    assert indicator.evidence.get().snippet == (
        "service.permission=android.permission.BIND_ACCESSIBILITY_SERVICE"
    )


@pytest.mark.django_db
def test_evaluator_rerun_does_not_duplicate_results_or_evidence(audit_and_apk):
    audit, apk_file = audit_and_apk
    _create_manifest(
        audit,
        apk_file,
        permissions=["android.permission.SEND_SMS"],
        components=[{"type": "service", "name": ".AccessibilityService"}],
        application={"debuggable": True, "allow_backup": True},
    )

    evaluate_masvs_rules(audit)
    evaluate_attck_indicators(audit)
    masvs_rerun = evaluate_masvs_rules(audit)
    attck_rerun = evaluate_attck_indicators(audit)

    assert Finding.objects.filter(audit=audit).count() == 2
    assert SuspiciousIndicator.objects.filter(audit=audit).count() == 2
    assert Evidence.objects.filter(audit=audit).count() == 4
    assert masvs_rerun["findings_existing"] == 2
    assert masvs_rerun["evidence_created"] == 0
    assert attck_rerun["indicators_existing"] == 2
    assert attck_rerun["evidence_created"] == 0


@pytest.mark.django_db
def test_orchestrator_evaluates_created_manifest_artifact(audit_and_apk):
    audit, _ = audit_and_apk
    registry = AnalyzerRegistry(analyzers=[_MatchingManifestAnalyzer()])

    result = AnalysisOrchestrator(registry=registry).run(audit.id)

    assert Finding.objects.filter(audit=audit).count() == 2
    assert SuspiciousIndicator.objects.filter(audit=audit).count() == 2
    assert Evidence.objects.filter(audit=audit).count() == 4
    assert result.summary["masvs_evaluation"]["findings_created"] == 2
    assert result.summary["attck_evaluation"]["indicators_created"] == 2
    assert result.summary["created_findings"] == 2
    assert result.summary["created_suspicious_indicators"] == 2
    assert result.summary["created_evidence"] == 4


def _create_manifest(
    audit: Audit,
    apk_file: APKFile,
    *,
    permissions=None,
    components=None,
    application=None,
) -> NormalizedArtifact:
    return NormalizedArtifact.objects.create(
        audit=audit,
        apk_file=apk_file,
        artifact_type=NormalizedArtifact.ArtifactType.MANIFEST,
        source="manifest_metadata_analyzer",
        normalized_data=build_manifest_artifact(
            permissions=permissions,
            components=components,
            application=application,
            parsing_status="PARSED",
        ),
    )


class _MatchingManifestAnalyzer:
    name = "matching_manifest_analyzer"
    version = "0.1.0"
    description = "Produces a matching normalized manifest for rule tests."
    enabled = True

    def supports(self, context):
        return True

    def run(self, context):
        return AnalyzerResult(
            analyzer_name=self.name,
            analyzer_version=self.version,
            status=RawAnalyzerResult.Status.COMPLETED,
            raw_summary={"parsing_status": "PARSED"},
            normalized_artifacts=[
                NormalizedArtifactPayload(
                    artifact_type=NormalizedArtifact.ArtifactType.MANIFEST,
                    source=self.name,
                    normalized_data=build_manifest_artifact(
                        permissions=["android.permission.RECEIVE_SMS"],
                        components=[
                            {
                                "type": "service",
                                "name": "com.example.AccessibilityService",
                            }
                        ],
                        application={
                            "debuggable": True,
                            "allow_backup": True,
                        },
                        parsing_status="PARSED",
                    ),
                )
            ],
        )
