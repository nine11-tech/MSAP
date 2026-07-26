import json
from zipfile import ZipFile

import pytest

from apps.analyzers.services.advanced_static_analyzer import _secret_matches
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
