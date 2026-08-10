import json
from zipfile import ZipFile

import pytest

from apps.analyzers.services.advanced_static_analyzer import (
    _file_provider_paths,
    _secret_matches,
)
from apps.analyzers.services.safe_archive import UnsafeAPKArchive, validate_apk_archive
from apps.appsec_rules.services.masvs_evaluator import _evaluate_condition


def test_unsafe_archive_path_is_rejected(tmp_path):
    apk = tmp_path / "unsafe.apk"
    with ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", "<manifest />")
        archive.writestr("../escape.dex", b"dex")

    with pytest.raises(UnsafeAPKArchive, match="unsafe ZIP path"):
        validate_apk_archive(apk)


def test_secret_matches_never_persist_secret_value():
    secret = "password=ClientProductionSecret-2026!"

    matches = _secret_matches([secret])

    assert matches
    assert matches[0]["redacted"] is True
    assert "fingerprint_sha256" in matches[0]
    assert "ClientProductionSecret" not in json.dumps(matches)


def test_file_provider_root_path_is_detected_with_resource_provenance(tmp_path):
    apk = tmp_path / "file-provider.apk"
    manifest = b"""<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example">
      <application>
        <provider android:name="androidx.core.content.FileProvider" android:exported="false" android:grantUriPermissions="true">
          <meta-data android:name="android.support.FILE_PROVIDER_PATHS" android:resource="@xml/file_paths" />
        </provider>
      </application>
    </manifest>"""
    with ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", manifest)
        archive.writestr(
            "res/xml/file_paths.xml",
            b'<paths><root-path name="root" path="." /></paths>',
        )

    warnings = []
    with ZipFile(apk) as archive:
        matches = _file_provider_paths(apk, archive, warnings)

    assert warnings == []
    assert matches == [
        {
            "provider": "androidx.core.content.FileProvider",
            "provider_exported": False,
            "provider_permission": None,
            "grant_uri_permissions": True,
            "resource": "res/xml/file_paths.xml",
            "tag": "root-path",
            "name": "root",
            "path": ".",
            "oversharing": True,
        }
    ]


@pytest.mark.parametrize(
    ("condition", "artifacts"),
    [
        ("manifest_allow_backup", {"MANIFEST": {"application": {"allow_backup": True}}}),
        (
            "risky_crypto_reference",
            {"CRYPTO_USAGE": {"matches": [{"type": "ECB_MODE"}]}},
        ),
        (
            "contextual_secret",
            {"SECRETS": {"matches": [{"type": "CONTEXTUAL_SECRET_ASSIGNMENT"}]}},
        ),
        ("network_user_ca", {"NETWORK_SECURITY_CONFIG": {"user_ca_trust": True}}),
        (
            "exported_activity_unprotected",
            {"MANIFEST": {"components": [{"type": "activity", "exported": True}]}},
        ),
        ("unsigned_apk", {"SIGNING": {"signed": False, "malformed": False}}),
        ("manifest_debuggable", {"MANIFEST": {"application": {"debuggable": True}}}),
        (
            "privacy_permission_review",
            {"MANIFEST": {"permissions": ["android.permission.CAMERA"]}},
        ),
    ],
)
def test_representative_masvs_category_conditions_match(condition, artifacts):
    matched, evidence = _evaluate_condition(condition, artifacts)

    assert matched is True
    assert evidence
