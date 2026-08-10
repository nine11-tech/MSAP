from hashlib import sha256

import pytest

from apps.analyzers.models import RawAnalyzerResult
from apps.analyzers.services.base import AnalyzerResult
from apps.analyzers.services.registry import AnalyzerRegistry
from apps.appsec_rules.services.masvs_evaluator import evaluate_masvs_rules
from apps.appsec_rules.models import RuleEvaluation
from apps.apk_files.models import APKFile
from apps.audits.models import Audit
from apps.audits.services.analysis_orchestrator import AnalysisOrchestrator
from apps.evidence.models import Evidence, SourceDocument
from apps.findings.models import Finding
from apps.indicators.models import SuspiciousIndicator
from apps.normalization.models import NormalizedArtifact
from apps.normalization.services.schemas import (
    NormalizedArtifactPayload,
    build_manifest_artifact,
)
from apps.projects.models import Project
from apps.scoring.models import ComplianceScore, RiskScore
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
    assert summary["catalog_rules"] == 44
    assert summary["evaluated_rules"] == 17
    assert summary["not_evaluated"] == 27
    assert summary["findings_created"] == 1
    assert summary["failed"] == 1
    assert RuleEvaluation.objects.filter(audit=audit).count() == 44
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
def test_masvs_evaluator_collapses_duplicate_finding_evidence(audit_and_apk):
    audit, apk_file = audit_and_apk
    _create_manifest(audit, apk_file, application={"debuggable": True})
    evaluate_masvs_rules(audit)
    finding = Finding.objects.get(audit=audit, rule_id="MSAP-AND-001")
    original = finding.evidence.get()
    Evidence.objects.create(
        audit=audit,
        finding=finding,
        evidence_type=original.evidence_type,
        source=original.source,
        snippet="stale duplicate",
    )

    evaluate_masvs_rules(audit)

    assert finding.evidence.count() == 1
    assert finding.evidence.get().snippet == "application.debuggable=true"


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
    assert summary["catalog_indicators"] == 20
    assert summary["evaluated_indicators"] == 14
    assert summary["not_evaluated"] == 6
    assert summary["matched_indicators"] == 1
    assert summary["indicators_created"] == 1
    assert evidence.snippet == (
        "declared permission capability: android.permission.READ_SMS"
    )
    assert evidence.redacted is False
    assert "permission" in indicator.auditor_explanation.lower()
    assert "disposable emulator" in indicator.dynamic_verification_scenario
    assert indicator.source_evidence[0]["source_lines_available"] is False


@pytest.mark.django_db
def test_attck_evaluator_resolves_exact_decoded_manifest_line(audit_and_apk):
    audit, apk_file = audit_and_apk
    manifest = (
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android">\n'
        '    <uses-permission android:name="android.permission.READ_SMS" />\n'
        "</manifest>\n"
    )
    _create_manifest(
        audit,
        apk_file,
        permissions=["android.permission.READ_SMS"],
    )
    document = SourceDocument.objects.create(
        audit=audit,
        apk_file=apk_file,
        representation_type=SourceDocument.RepresentationType.MANIFEST_XML,
        logical_path="AndroidManifest.xml",
        display_path="Decoded AndroidManifest.xml",
        sha256=sha256(manifest.encode()).hexdigest(),
        line_count=3,
        generated_by="test decoder",
        metadata={
            "provenance_note": "Lines refer to decoded AndroidManifest.xml."
        },
    )

    class StaticContentService:
        def read_text(self, requested_document):
            assert requested_document.id == document.id
            return manifest

    evaluate_attck_indicators(
        audit,
        content_service=StaticContentService(),
    )

    indicator = SuspiciousIndicator.objects.get(
        audit=audit,
        indicator_id="MSAP-MOB-001",
    )
    reference = indicator.source_evidence[0]
    assert reference["source_document"] == document.id
    assert reference["representation_label"] == "Decoded AndroidManifest.xml"
    assert reference["start_line"] == 2
    assert reference["end_line"] == 2
    assert reference["excerpt"] == (
        '    <uses-permission android:name="android.permission.READ_SMS" />'
    )
    assert reference["source_lines_available"] is True


@pytest.mark.django_db
def test_attck_evaluator_resolves_exact_jadx_code_line(audit_and_apk):
    audit, apk_file = audit_and_apk
    apk_file.package_name = "com.example"
    apk_file.save(update_fields=["package_name"])
    source = (
        "package com.example;\n"
        "public class ClipboardReader {\n"
        "    public String readClipboard() {\n"
        "        return clipboard.getPrimaryClip().toString();\n"
        "    }\n"
        "}\n"
    )
    NormalizedArtifact.objects.create(
        audit=audit,
        apk_file=apk_file,
        artifact_type=NormalizedArtifact.ArtifactType.CODE_REFERENCES,
        source="advanced_static_analyzer",
        normalized_data={
            "matches": [
                {
                    "category": "clipboard",
                    "value": "Landroid/content/ClipboardManager;->getPrimaryClip",
                    "locator_terms": ["getPrimaryClip"],
                }
            ]
        },
    )
    document = SourceDocument.objects.create(
        audit=audit,
        apk_file=apk_file,
        representation_type=SourceDocument.RepresentationType.JADX_JAVA,
        logical_path="sources/com/example/ClipboardReader.java",
        display_path="sources/com/example/ClipboardReader.java",
        language="Java",
        class_name="com.example.ClipboardReader",
        package_name="com.example",
        sha256=sha256(source.encode()).hexdigest(),
        line_count=6,
        generated_by="JADX",
        tool_version="test",
    )

    class StaticContentService:
        def read_text(self, requested_document):
            assert requested_document.id == document.id
            return source

    evaluate_attck_indicators(
        audit,
        content_service=StaticContentService(),
    )

    indicator = SuspiciousIndicator.objects.get(
        audit=audit,
        indicator_id="MSAP-MOB-012",
    )
    reference = indicator.source_evidence[0]
    assert reference["representation_label"] == "JADX decompiled Java"
    assert reference["path"] == "sources/com/example/ClipboardReader.java"
    assert reference["method_name"] == "readClipboard"
    assert reference["start_line"] == 4
    assert reference["excerpt"] == (
        "        return clipboard.getPrimaryClip().toString();"
    )
    assert "ClipboardManager.getPrimaryClip" in (
        indicator.dynamic_verification_scenario
    )


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
    assert indicator.title == "Accessibility service capability"
    assert indicator.evidence.get().snippet == "matched component capability declarations: 1"


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
    assert result.summary["scoring"] == {
        "risk": {
            "score": 100,
            "severity": "Critical",
            "finding_count": 2,
            "indicator_count": 0,
            "raw_weight": 11,
            "method": (
                "Unique failed findings weighted by severity and confidence; "
                "ATT&CK triage excluded."
            ),
        },
        "masvs_compliance": {
            "standard": "MASVS",
            "score": 88.24,
            "evaluated_rules": 17,
            "applicable_rules": 17,
            "failed_rules": 2,
            "passed_rules": 15,
            "review_required": 0,
            "not_evaluated": 27,
            "not_applicable": 0,
            "partial_coverage": True,
            "coverage_warning": (
                "27 catalog rule(s) were not evaluated and are not counted as passing."
            ),
        },
        "attack_mobile_triage": {
            "triage_indicators": 2,
            "triage_level": "High",
            "note": (
                "ATT&CK Mobile indicators are triage signals, "
                "not malware verdicts."
            ),
        },
    }
    assert RiskScore.objects.filter(audit=audit).count() == 1
    assert ComplianceScore.objects.filter(audit=audit, standard="MASVS").count() == 1


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
