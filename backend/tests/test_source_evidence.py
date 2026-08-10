from contextlib import nullcontext
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from zipfile import ZIP_DEFLATED, ZipFile

import pytest
from django.contrib.auth.models import Group
from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.db import IntegrityError, transaction
from django.test import override_settings
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.platypus import Table
from rest_framework.test import APIClient

from apps.analyzers.services.base import AnalyzerContext
from apps.analyzers.services.manifest_analyzer import ManifestMetadataAnalyzer
from apps.analyzers.services.source_index import SourceIndexService, _safe_logical_path
from apps.analyzers.services.source_verification import SourceVerificationService
from apps.appsec_rules.models import RuleEvaluation
from apps.appsec_rules.services.masvs_evaluator import evaluate_masvs_rules
from apps.api.roles import VIEWER_GROUP
from apps.apk_files.models import APKFile
from apps.audits.models import Audit
from apps.evidence.models import FindingSourceReference, SourceDocument
from apps.evidence.services.source_content import (
    SourceDocumentContentService,
    redact_source_line,
)
from apps.evidence.services.source_resolution import enrich_finding_source_references
from apps.findings.models import Finding
from apps.normalization.models import NormalizedArtifact
from apps.projects.models import Project
from apps.reports.services.json_report import generate_json_report
from apps.reports.services.pdf_report import (
    _build_styles,
    _finding_source_evidence,
    generate_pdf_report,
)
from apps.storage.models import ObjectStorageReference


MANIFEST = b"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.source">
    <uses-sdk android:targetSdkVersion="28" />
    <application android:debuggable="true" android:allowBackup="true">
        <activity android:name=".ExportedActivity" android:exported="true" />
    </application>
</manifest>
"""


class MemoryStorage:
    def __init__(self):
        self.objects: dict[tuple[str, str], bytes] = {}
        self.counter = 0

    def build_object_key(self, project_id, audit_id, object_type, filename):
        self.counter += 1
        return f"projects/{project_id}/audits/{audit_id}/source/{self.counter}-{filename}"

    def upload_file(self, bucket, object_key, source, content_type="text/plain"):
        self.objects[(bucket, object_key)] = Path(source).read_bytes()

    def download_file(self, bucket, object_key, destination):
        Path(destination).write_bytes(self.objects[(bucket, object_key)])


class StaticContentService:
    def __init__(self, documents: dict[int, str]):
        self.documents = documents

    def read_text(self, document):
        return self.documents[document.id]


@pytest.fixture
def source_context(db):
    project = Project.objects.create(name="Source evidence project")
    audit = Audit.objects.create(project=project, name="Source evidence audit")
    upload = ObjectStorageReference.objects.create(
        project=project,
        audit=audit,
        bucket="apk",
        object_key="source/app.apk",
        object_type=ObjectStorageReference.ObjectType.APK_UPLOAD,
        storage_status=ObjectStorageReference.StorageStatus.VERIFIED,
    )
    apk = APKFile.objects.create(
        audit=audit,
        storage_reference=upload,
        package_name="com.example.source",
        sha256="a" * 64,
    )
    return AnalyzerContext(audit=audit, apk_file=apk)


@pytest.fixture
def source_apk(tmp_path):
    path = tmp_path / "source.apk"
    with ZipFile(path, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", MANIFEST)
        archive.writestr(
            "res/xml/network_security_config.xml",
            b'<network-security-config><base-config cleartextTrafficPermitted="true" /></network-security-config>',
        )
    return path


def _document(source_context, content, *, representation="MANIFEST_XML", path="AndroidManifest.xml"):
    storage = ObjectStorageReference.objects.create(
        project=source_context.audit.project,
        audit=source_context.audit,
        bucket="artifacts",
        object_key=f"documents/{sha256(content.encode()).hexdigest()}/{Path(path).name}",
        object_type=ObjectStorageReference.ObjectType.SOURCE_DOCUMENT,
        storage_status=ObjectStorageReference.StorageStatus.VERIFIED,
        sha256=sha256(content.encode()).hexdigest(),
        size_bytes=len(content.encode()),
    )
    return SourceDocument.objects.create(
        audit=source_context.audit,
        apk_file=source_context.apk_file,
        representation_type=representation,
        logical_path=path,
        display_path=path,
        language="XML" if path.endswith(".xml") else "Java",
        sha256=sha256(content.encode()).hexdigest(),
        line_count=len(content.splitlines()),
        generated_by="test",
        storage_reference=storage,
        metadata={"provenance_note": "MSAP generated test representation."},
    )


def _finding(source_context, rule_id="MSAP-AND-001"):
    return Finding.objects.create(
        audit=source_context.audit,
        rule_id=rule_id,
        title="Source finding",
        severity="High",
        confidence="High",
        standard="OWASP MASVS",
    )


def _artifact(source_context, artifact_type, locators, data=None):
    NormalizedArtifact.objects.create(
        audit=source_context.audit,
        apk_file=source_context.apk_file,
        artifact_type=artifact_type,
        source="test",
        normalized_data={
            "schema_version": "2.0",
            "extraction_status": "COMPLETED",
            "data": {**(data or {}), "_source_locators": locators},
        },
    )


@pytest.mark.django_db
def test_source_document_and_reference_validation(source_context):
    document = _document(source_context, "one\ntwo\nthree\n")
    document.logical_path = "../secret.txt"
    with pytest.raises(ValidationError):
        document.full_clean()

    finding = _finding(source_context)
    reference = FindingSourceReference(
        finding=finding,
        source_document=document,
        representation_type=SourceDocument.RepresentationType.MANIFEST_XML,
        logical_path="AndroidManifest.xml",
        start_line=3,
        end_line=2,
        excerpt="two",
        excerpt_sha256=sha256(b"two").hexdigest(),
        provenance="test",
    )
    with pytest.raises(ValidationError):
        reference.full_clean()

    reference.source_lines_available = False
    reference.start_line = None
    reference.end_line = None
    reference.excerpt = ""
    reference.excerpt_sha256 = ""
    reference.unavailable_reason = "Binary metadata evidence."
    reference.source_document = None
    reference.representation_type = SourceDocument.RepresentationType.DEX_METADATA
    reference.full_clean()


@pytest.mark.django_db
def test_finding_source_reference_fingerprint_prevents_duplicates(source_context):
    document = _document(source_context, "one\ntwo\n")
    finding = _finding(source_context)
    values = {
        "finding": finding,
        "source_document": document,
        "representation_type": document.representation_type,
        "logical_path": document.logical_path,
        "start_line": 2,
        "end_line": 2,
        "excerpt": "two",
        "excerpt_sha256": sha256(b"two").hexdigest(),
        "provenance": "test",
    }
    FindingSourceReference.objects.create(**values)
    with pytest.raises(IntegrityError), transaction.atomic():
        FindingSourceReference.objects.create(**values)


@pytest.mark.django_db
@override_settings(MSAP_SOURCE_INDEX_ENABLED=True, MSAP_JADX_ENABLED=False)
def test_source_index_is_deterministic_and_reuses_documents(
    source_context,
    source_apk,
):
    storage = MemoryStorage()
    provider = SimpleNamespace(open_apk_local_copy=lambda apk: nullcontext(source_apk))
    service = SourceIndexService(file_provider=provider, storage_service=storage)

    first = service.index(source_context)
    second = service.index(source_context)

    manifest = SourceDocument.objects.get(
        audit=source_context.audit,
        representation_type=SourceDocument.RepresentationType.MANIFEST_XML,
    )
    content = storage.objects[
        (manifest.storage_reference.bucket, manifest.storage_reference.object_key)
    ]
    assert first.documents_created == 2
    assert second.documents_reused == 2
    assert manifest.line_count == len(content.decode().splitlines())
    assert manifest.sha256 == sha256(content).hexdigest()
    assert b"android:debuggable=\"true\"" in content
    assert manifest.metadata["apk_sha256"] == "a" * 64


@pytest.mark.django_db
@override_settings(MSAP_SOURCE_INDEX_ENABLED=True, MSAP_JADX_ENABLED=True)
def test_jadx_unavailable_is_a_graceful_manifest_fallback(source_context, source_apk):
    storage = MemoryStorage()
    provider = SimpleNamespace(open_apk_local_copy=lambda apk: nullcontext(source_apk))
    service = SourceIndexService(
        file_provider=provider,
        storage_service=storage,
        executable_resolver=lambda name: None,
    )

    result = service.index(source_context)

    assert result.status == "COMPLETED"
    assert result.jadx_status == "UNAVAILABLE"
    assert SourceDocument.objects.filter(
        representation_type=SourceDocument.RepresentationType.MANIFEST_XML
    ).exists()
    assert "DEX metadata evidence" in result.warnings[0]


@pytest.mark.django_db
@override_settings(MSAP_SOURCE_INDEX_ENABLED=True, MSAP_JADX_ENABLED=True)
def test_jadx_index_output_is_bounded_and_temporary_data_is_cleaned(
    source_context,
    source_apk,
):
    storage = MemoryStorage()
    generated_output = None

    def runner(command, **kwargs):
        nonlocal generated_output
        if "--version" in command:
            return SimpleNamespace(returncode=0, stdout="1.5.0", stderr="")
        generated_output = Path(command[command.index("-d") + 1])
        java = generated_output / "sources/com/example/source/MainActivity.java"
        java.parent.mkdir(parents=True)
        java.write_text(
            "package com.example.source;\nclass MainActivity { void run() { Log.d(\"x\", \"y\"); } }\n",
            encoding="utf-8",
        )
        return SimpleNamespace(returncode=0)

    provider = SimpleNamespace(open_apk_local_copy=lambda apk: nullcontext(source_apk))
    result = SourceIndexService(
        file_provider=provider,
        storage_service=storage,
        executable_resolver=lambda name: "/usr/bin/jadx",
        command_runner=runner,
    ).index(source_context)

    assert result.jadx_status == "COMPLETED"
    assert SourceDocument.objects.filter(
        representation_type=SourceDocument.RepresentationType.JADX_JAVA,
        class_name="com.example.source.MainActivity",
    ).exists()
    assert generated_output is not None and not generated_output.exists()


def test_unsafe_source_paths_are_rejected():
    for value in ("../outside.java", "/absolute.java", "sources\\bad.java"):
        with pytest.raises(ValueError):
            _safe_logical_path(value)


@pytest.mark.django_db
def test_manifest_analyzer_emits_typed_semantic_locator_hints(
    source_context,
    source_apk,
):
    provider = SimpleNamespace(open_apk_local_copy=lambda apk: nullcontext(source_apk))

    result = ManifestMetadataAnalyzer(file_provider=provider).run(source_context)

    hints = result.normalized_artifacts[0].source_locators
    semantic_keys = {hint.semantic_key for hint in hints}
    assert "manifest_debuggable" in semantic_keys
    assert "manifest_allow_backup" in semantic_keys
    assert "exported_activity_unprotected" in semantic_keys
    assert all(hint.representation == "MANIFEST_XML" for hint in hints)


@pytest.mark.django_db
def test_manifest_resolution_creates_exact_line_reference(source_context):
    content = (
        "<manifest\n"
        "    xmlns:android=\"http://schemas.android.com/apk/res/android\"\n"
        ">\n"
        "    <application\n"
        "        android:debuggable=\"true\"\n"
        "    />\n"
        "</manifest>\n"
    )
    document = _document(source_context, content)
    _artifact(
        source_context,
        NormalizedArtifact.ArtifactType.MANIFEST,
        [{
            "representation": "MANIFEST_XML",
            "semantic_key": "manifest_debuggable",
            "logical_path": "AndroidManifest.xml",
            "search_terms": ["android:debuggable", "true"],
            "confidence": "HIGH",
            "locator": {"match_all": True},
        }],
    )
    finding = _finding(source_context)

    summary = enrich_finding_source_references(
        source_context.audit,
        source_context.apk_file,
        content_service=StaticContentService({document.id: content}),
    )

    reference = finding.source_references.get()
    assert summary["line_references_created"] == 1
    assert reference.start_line == 5
    assert reference.end_line == 5
    assert 'android:debuggable="true"' in reference.excerpt
    assert reference.locator["provenance_chain"]["apk_sha256"] == "a" * 64


@pytest.mark.django_db
def test_multiple_code_matches_are_retained_as_ambiguous(source_context):
    content = (
        "package com.example;\nclass Crypto {\n"
        " void first() { Cipher.getInstance(\"AES/ECB/PKCS5Padding\"); }\n"
        " void second() { Cipher.getInstance(\"AES/ECB/NoPadding\"); }\n}\n"
    )
    document = _document(
        source_context,
        content,
        representation="JADX_JAVA",
        path="sources/com/example/Crypto.java",
    )
    _artifact(
        source_context,
        NormalizedArtifact.ArtifactType.CRYPTO_USAGE,
        [{
            "representation": "JADX_SOURCE",
            "semantic_key": "crypto:ECB_MODE",
            "search_terms": ["AES/ECB"],
            "confidence": "MEDIUM",
            "locator": {"dex_fallback": True},
        }],
    )
    finding = _finding(source_context, "MSAP-AND-028")

    summary = enrich_finding_source_references(
        source_context.audit,
        source_context.apk_file,
        content_service=StaticContentService({document.id: content}),
    )

    finding.refresh_from_db()
    assert summary["line_references_created"] == 2
    assert finding.requires_manual_validation is True
    assert set(finding.source_references.values_list("confidence", flat=True)) == {"LOW"}


@pytest.mark.django_db
def test_analyzer_provided_exact_matches_are_not_marked_ambiguous(source_context):
    content = (
        "package com.example.source;\n"
        "class Crypto {\n"
        ' void first() { Cipher.getInstance("AES/ECB/PKCS5Padding"); }\n'
        ' void second() { Cipher.getInstance("DES/CBC/PKCS5Padding"); }\n'
        "}\n"
    )
    document = _document(
        source_context,
        content,
        representation="JADX_JAVA",
        path="sources/com/example/source/Crypto.java",
    )
    document.class_name = "com.example.source.Crypto"
    document.save(update_fields=["class_name"])
    _artifact(
        source_context,
        NormalizedArtifact.ArtifactType.SOURCE_VERIFICATION,
        [
            {
                "representation": "JADX_JAVA",
                "semantic_key": "verified_risky_crypto",
                "logical_path": document.logical_path,
                "class_name": document.class_name,
                "start_line": line,
                "end_line": line,
                "confidence": "HIGH",
                "locator": {
                    "source_document_id": document.id,
                    "verified_source_match": True,
                    "ambiguous_match": False,
                },
            }
            for line in (3, 4)
        ],
    )
    finding = _finding(source_context, "MSAP-AND-028")

    summary = enrich_finding_source_references(
        source_context.audit,
        source_context.apk_file,
        content_service=StaticContentService({document.id: content}),
    )

    finding.refresh_from_db()
    assert summary["line_references_created"] == 2
    assert summary["ambiguous_findings"] == 0
    assert set(finding.source_references.values_list("confidence", flat=True)) == {"HIGH"}
    assert finding.requires_manual_validation is False


@pytest.mark.django_db
def test_source_verifier_creates_verified_findings_with_exact_lines(source_context):
    secret = "ClientProductionSecret-2026!"
    content = (
        "package com.example.source;\n"
        "class Vulnerable {\n"
        " void configure(WebSettings settings, SslErrorHandler handler) throws Exception {\n"
        '  String password = "ClientProductionSecret-2026!";\n'
        '  Cipher.getInstance("AES/ECB/PKCS5Padding");\n'
        '  SSLContext.getInstance("TLSv1");\n'
        '  new SecretKeySpec("0123456789abcdef".getBytes(), "AES");\n'
        '  new URL("http://api.example.invalid/v1");\n'
        "  settings.setAllowUniversalAccessFromFileURLs(true);\n"
        "  WebView.setWebContentsDebuggingEnabled(true);\n"
        "  settings.setSafeBrowsingEnabled(false);\n"
        "  settings.setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);\n"
        " }\n"
        " public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {\n"
        "  handler.proceed();\n"
        " }\n"
        "}\n"
    )
    document = _document(
        source_context,
        content,
        representation="JADX_JAVA",
        path="sources/com/example/source/Vulnerable.java",
    )
    document.class_name = "com.example.source.Vulnerable"
    document.package_name = "com.example.source"
    document.save(update_fields=["class_name", "package_name"])
    secret_fingerprint = sha256(secret.encode()).hexdigest()
    _artifact(
        source_context,
        NormalizedArtifact.ArtifactType.SECRETS,
        [],
        data={
            "matches": [
                {
                    "type": "CONTEXTUAL_SECRET_ASSIGNMENT",
                    "fingerprint_sha256": secret_fingerprint,
                    "source_value_fingerprint_sha256": secret_fingerprint,
                }
            ]
        },
    )
    _artifact(
        source_context,
        NormalizedArtifact.ArtifactType.CRYPTO_USAGE,
        [],
        data={"matches": []},
    )
    _artifact(
        source_context,
        NormalizedArtifact.ArtifactType.WEBVIEW_USAGE,
        [],
        data={"matches": []},
    )
    _artifact(
        source_context,
        NormalizedArtifact.ArtifactType.URLS_AND_ENDPOINTS,
        [],
        data={"urls": []},
    )
    _artifact(
        source_context,
        NormalizedArtifact.ArtifactType.MANIFEST,
        [],
        data={"application": {}, "components": [], "permissions": []},
    )

    verification = SourceVerificationService(
        content_service=StaticContentService({document.id: content})
    ).verify(source_context)
    evaluation = evaluate_masvs_rules(source_context.audit)
    enrichment = enrich_finding_source_references(
        source_context.audit,
        source_context.apk_file,
        content_service=StaticContentService({document.id: content}),
    )

    expected = {
        "MSAP-AND-026",
        "MSAP-AND-028",
        "MSAP-AND-030",
        "MSAP-AND-032",
        "MSAP-AND-033",
        "MSAP-AND-038",
        "MSAP-AND-039",
        "MSAP-AND-040",
        "MSAP-AND-041",
        "MSAP-AND-042",
    }
    assert verification.verified_matches == 10
    assert expected.issubset(
        set(Finding.objects.filter(audit=source_context.audit).values_list("rule_id", flat=True))
    )
    assert evaluation["failed"] >= len(expected)
    assert enrichment["ambiguous_findings"] == 0
    for finding in Finding.objects.filter(audit=source_context.audit, rule_id__in=expected):
        reference = finding.source_references.get(is_primary=True)
        assert reference.source_document_id == document.id
        assert reference.start_line is not None
        assert reference.end_line >= reference.start_line
        assert reference.confidence == "HIGH"
    key_excerpt = Finding.objects.get(
        audit=source_context.audit,
        rule_id="MSAP-AND-039",
    ).source_references.get(is_primary=True).excerpt
    assert "0123456789abcdef" not in key_excerpt


@pytest.mark.django_db
def test_dex_reference_without_verified_source_is_review_not_finding(source_context):
    _artifact(
        source_context,
        NormalizedArtifact.ArtifactType.CRYPTO_USAGE,
        [],
        data={"matches": [{"type": "ECB_MODE"}]},
    )

    evaluate_masvs_rules(source_context.audit)

    evaluation = RuleEvaluation.objects.get(
        audit=source_context.audit,
        rule_id="MSAP-AND-028",
    )
    assert evaluation.result == RuleEvaluation.Result.REVIEW_REQUIRED
    assert not Finding.objects.filter(
        audit=source_context.audit,
        rule_id="MSAP-AND-028",
    ).exists()


@pytest.mark.django_db
def test_manifest_component_class_context_does_not_filter_manifest_document(source_context):
    content = (
        "<manifest>\n"
        " <application>\n"
        "  <activity\n"
        '   android:name="com.example.source.ExportedActivity"\n'
        '   android:exported="true"\n'
        "  />\n"
        " </application>\n"
        "</manifest>\n"
    )
    document = _document(source_context, content)
    _artifact(
        source_context,
        NormalizedArtifact.ArtifactType.MANIFEST,
        [
            {
                "representation": "MANIFEST_XML",
                "semantic_key": "exported_activity_unprotected",
                "logical_path": "AndroidManifest.xml",
                "class_name": "com.example.source.ExportedActivity",
                "search_terms": ["<activity", "ExportedActivity", "android:exported"],
                "confidence": "HIGH",
                "locator": {"match_all": True},
            }
        ],
    )
    finding = _finding(source_context, "MSAP-AND-004")

    enrich_finding_source_references(
        source_context.audit,
        source_context.apk_file,
        content_service=StaticContentService({document.id: content}),
    )

    reference = finding.source_references.get()
    assert reference.source_document_id == document.id
    assert reference.start_line == 3
    assert reference.end_line == 5


@pytest.mark.django_db
def test_class_constraint_selects_the_correct_decompiled_document(source_context):
    wanted_content = "class Wanted { void run() { addJavascriptInterface(bridge, \"b\"); } }\n"
    other_content = "class Other { void run() { addJavascriptInterface(bridge, \"b\"); } }\n"
    wanted = _document(
        source_context,
        wanted_content,
        representation="JADX_JAVA",
        path="sources/com/example/Wanted.java",
    )
    wanted.class_name = "com.example.Wanted"
    wanted.save(update_fields=["class_name"])
    other = _document(
        source_context,
        other_content,
        representation="JADX_JAVA",
        path="sources/com/example/Other.java",
    )
    other.class_name = "com.example.Other"
    other.save(update_fields=["class_name"])
    _artifact(
        source_context,
        NormalizedArtifact.ArtifactType.WEBVIEW_USAGE,
        [{
            "representation": "JADX_SOURCE",
            "semantic_key": "webview:JAVASCRIPT_BRIDGE_REFERENCE",
            "class_name": "com.example.Wanted",
            "search_terms": ["addJavascriptInterface"],
            "confidence": "HIGH",
            "locator": {},
        }],
    )
    finding = _finding(source_context, "MSAP-AND-031")

    enrich_finding_source_references(
        source_context.audit,
        source_context.apk_file,
        content_service=StaticContentService({
            wanted.id: wanted_content,
            other.id: other_content,
        }),
    )

    reference = finding.source_references.get()
    assert reference.source_document_id == wanted.id
    assert reference.class_name == "com.example.Wanted"


@pytest.mark.django_db
def test_secret_excerpt_and_line_api_redact_value(source_context):
    secret = "sk_live_1234567890ABCDEFGHIJKLMNOP"
    content = f'class Secrets {{ String API_KEY = "{secret}"; }}\n'
    document = _document(
        source_context,
        content,
        representation="JADX_JAVA",
        path="sources/Secrets.java",
    )
    _artifact(
        source_context,
        NormalizedArtifact.ArtifactType.SECRETS,
        [{
            "representation": "JADX_SOURCE",
            "semantic_key": "secret:CONTEXTUAL_SECRET_ASSIGNMENT",
            "search_terms": [],
            "confidence": "MEDIUM",
            "locator": {
                "secret_fingerprint_sha256": sha256(secret.encode()).hexdigest(),
                "redact_excerpt": True,
            },
        }],
    )
    finding = _finding(source_context, "MSAP-AND-026")

    enrich_finding_source_references(
        source_context.audit,
        source_context.apk_file,
        content_service=StaticContentService({document.id: content}),
    )

    reference = finding.source_references.get()
    assert secret not in reference.excerpt
    assert "****" in reference.excerpt
    assert secret not in redact_source_line(content)
    neutral_high_entropy = "Ab9xQ2mN7pR4tV8yK3cD6fG1hJ5lZ0wS"
    assert neutral_high_entropy not in redact_source_line(
        f'String value = "{neutral_high_entropy}";'
    )


@pytest.mark.django_db
def test_missing_jadx_source_is_honest_dex_metadata_evidence(source_context):
    _artifact(
        source_context,
        NormalizedArtifact.ArtifactType.WEBVIEW_USAGE,
        [{
            "representation": "JADX_SOURCE",
            "semantic_key": "webview:JAVASCRIPT_BRIDGE_REFERENCE",
            "search_terms": ["addJavascriptInterface"],
            "confidence": "MEDIUM",
            "locator": {"dex_fallback": True},
        }],
    )
    finding = _finding(source_context, "MSAP-AND-031")

    enrich_finding_source_references(
        source_context.audit,
        source_context.apk_file,
        content_service=StaticContentService({}),
    )

    reference = finding.source_references.get()
    assert reference.source_lines_available is False
    assert reference.representation_type == "DEX_METADATA"
    assert reference.logical_path == "DEX-METADATA"
    assert reference.start_line is None
    assert "JADX decompiled source was unavailable" in reference.unavailable_reason


@pytest.mark.django_db
def test_source_api_auth_bounds_viewer_access_and_audit_filtering(
    source_context,
    django_user_model,
):
    content = "one\nString API_KEY = \"superSecret1234567890!\";\nthree\n"
    storage = MemoryStorage()
    document = _document(source_context, content)
    reference = document.storage_reference
    storage.objects[(reference.bucket, reference.object_key)] = content.encode()
    finding = _finding(source_context)
    FindingSourceReference.objects.create(
        finding=finding,
        source_document=document,
        representation_type=document.representation_type,
        logical_path=document.logical_path,
        start_line=2,
        end_line=2,
        excerpt=redact_source_line(content.splitlines()[1]),
        excerpt_sha256=sha256(redact_source_line(content.splitlines()[1]).encode()).hexdigest(),
        provenance="Decoded test representation.",
    )
    other_project = Project.objects.create(name="Other")
    other_audit = Audit.objects.create(project=other_project, name="Other audit")
    other_apk = APKFile.objects.create(audit=other_audit, sha256="b" * 64)
    SourceDocument.objects.create(
        audit=other_audit,
        apk_file=other_apk,
        representation_type="DEX_METADATA",
        logical_path="classes.dex",
        display_path="classes.dex",
        sha256="b" * 64,
        line_count=0,
        generated_by="test",
    )

    anonymous = APIClient()
    assert anonymous.get("/api/source-documents/").status_code in {401, 403}

    call_command("bootstrap_roles", verbosity=0)
    viewer = django_user_model.objects.create_user(username="source-viewer")
    viewer.groups.add(Group.objects.get(name=VIEWER_GROUP))
    client = APIClient()
    client.force_authenticate(viewer)
    with patch(
        "apps.evidence.services.source_content.MinIOStorageService",
        return_value=storage,
    ):
        list_response = client.get(
            f"/api/source-documents/?audit={source_context.audit.id}"
        )
        line_response = client.get(
            f"/api/source-documents/{document.id}/lines/?start=1&end=3"
        )
        too_large = client.get(
            f"/api/source-documents/{document.id}/lines/?start=1&end=201"
        )
        references = client.get(
            f"/api/findings/{finding.id}/source-references/"
        )

    assert list_response.status_code == 200
    assert [item["id"] for item in list_response.json()] == [document.id]
    assert line_response.status_code == 200
    assert line_response.json()["redaction_applied"] is True
    assert "superSecret" not in str(line_response.json())
    assert too_large.status_code == 400
    assert references.status_code == 200
    assert references.json()[0]["source_document"] == document.id
    assert "object_key" not in str(line_response.json())


@pytest.mark.django_db
def test_json_and_pdf_reports_include_line_and_non_line_evidence(source_context):
    content = "<manifest>\nandroid:debuggable=\"true\"\n</manifest>\n"
    document = _document(source_context, content)
    line_finding = _finding(source_context)
    non_line_finding = _finding(source_context, "MSAP-AND-021")
    FindingSourceReference.objects.create(
        finding=line_finding,
        source_document=document,
        representation_type=document.representation_type,
        logical_path=document.logical_path,
        start_line=2,
        end_line=2,
        excerpt=content.splitlines()[1],
        excerpt_sha256=sha256(content.splitlines()[1].encode()).hexdigest(),
        provenance="Lines refer to decoded AndroidManifest.xml.",
        is_primary=True,
    )
    FindingSourceReference.objects.create(
        finding=non_line_finding,
        representation_type="APK_SIGNING_METADATA",
        logical_path="APK-SIGNING-METADATA",
        provenance="Androguard signing metadata.",
        source_lines_available=False,
        unavailable_reason="Finding originates from APK signing block metadata.",
        is_primary=True,
    )

    report = generate_json_report(source_context.audit.id)
    pdf = generate_pdf_report(source_context.audit.id)

    line_data = next(item for item in report["findings"] if item["rule_id"] == "MSAP-AND-001")
    non_line_data = next(item for item in report["findings"] if item["rule_id"] == "MSAP-AND-021")
    assert line_data["source_evidence"][0]["start_line"] == 2
    assert line_data["source_evidence"][0]["source_document_sha256"] == document.sha256
    assert non_line_data["source_evidence"][0]["source_lines_available"] is False
    assert "signing block metadata" in non_line_data["source_evidence"][0]["reason"]
    pdf_elements = _finding_source_evidence(
        line_data["source_evidence"],
        _build_styles(),
    )
    pdf_text = " ".join(
        element.getPlainText()
        for element in pdf_elements
        if hasattr(element, "getPlainText")
    )
    assert "AndroidManifest.xml" in pdf_text
    assert "lines 2" in pdf_text
    assert "decoded AndroidManifest.xml" in pdf_text
    assert pdf.startswith(b"%PDF") and len(pdf) > 1000


def test_pdf_source_code_block_reserves_space_for_its_padding():
    lines = [f"{number:02d}  example source line" for number in range(1, 16)]
    styles = _build_styles()
    elements = _finding_source_evidence(
        [
            {
                "representation": "JADX_SOURCE",
                "path": "sources/example/Example.java",
                "start_line": 1,
                "end_line": len(lines),
                "excerpt": "\n".join(lines),
                "source_lines_available": True,
                "provenance": "JADX decompiled representation.",
            }
        ],
        styles,
    )

    code_block = next(element for element in elements if isinstance(element, Table))
    _, reserved_height = code_block.wrap(A4[0] - (36 * mm), A4[1])

    assert reserved_height > len(lines) * styles["source_code"].leading
