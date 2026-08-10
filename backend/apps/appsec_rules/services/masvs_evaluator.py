from datetime import date
from pathlib import Path
from typing import Any

from django.conf import settings
from django.db import transaction

from apps.appsec_rules.models import RuleEvaluation
from apps.appsec_rules.services.rule_loader import load_masvs_rules
from apps.audits.models import Audit
from apps.apk_files.models import APKFile
from apps.evidence.models import Evidence
from apps.findings.models import Finding
from apps.normalization.models import NormalizedArtifact


EVALUATOR_VERSION = "2.0.0"
SENSITIVE_PERMISSIONS = {
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    "android.permission.CAMERA",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_CALL_LOG",
    "android.permission.READ_SMS",
}


@transaction.atomic
def evaluate_masvs_rules(
    audit: Audit | int,
    rules_path: str | Path | None = None,
) -> dict[str, int]:
    audit_id = audit.pk if isinstance(audit, Audit) else audit
    rules = load_masvs_rules(
        rules_path or Path(settings.ANALYZER_RULES_PATH) / "masvs_static_rules.yaml"
    )
    artifacts = _artifact_map(audit_id)
    summary = {
        "catalog_rules": len(rules),
        "evaluated_rules": 0,
        "passed": 0,
        "failed": 0,
        "review_required": 0,
        "not_evaluated": 0,
        "findings_created": 0,
        "findings_existing": 0,
        "evidence_created": 0,
    }
    catalog_rule_ids = {rule["id"] for rule in rules}
    Finding.objects.filter(audit_id=audit_id, rule_id__startswith="MSAP-AND-").exclude(
        rule_id__in=catalog_rule_ids
    ).delete()

    for rule in rules:
        missing = [name for name in rule["prerequisites"] if name not in artifacts]
        if missing:
            result = RuleEvaluation.Result.NOT_EVALUATED
            evidence_summary = f"Prerequisite artifact unavailable: {', '.join(missing)}"
        else:
            matched, evidence_summary = _evaluate_condition(rule["condition"], artifacts)
            if matched:
                result = (
                    RuleEvaluation.Result.REVIEW_REQUIRED
                    if rule["requires_manual_validation"]
                    else RuleEvaluation.Result.FAIL
                )
            elif rule.get("review_condition"):
                review_matched, review_summary = _evaluate_condition(
                    rule["review_condition"], artifacts
                )
                if review_matched:
                    result = RuleEvaluation.Result.REVIEW_REQUIRED
                    evidence_summary = review_summary
                else:
                    result = RuleEvaluation.Result.PASS
                    evidence_summary = review_summary
            else:
                result = RuleEvaluation.Result.PASS

        mapping_data = {
            "masvs_category": rule["masvs_category"],
            "masvs_controls": rule["masvs_controls"],
            "maswe_ids": rule["maswe_ids"],
            "mastg_references": rule["mastg_references"],
            "cwe_ids": rule.get("cwe_ids", []),
            "test_type": rule["test_type"],
            "applicable_android": rule.get("applicable_android", ""),
        }
        RuleEvaluation.objects.update_or_create(
            audit_id=audit_id,
            framework=RuleEvaluation.Framework.MASVS,
            rule_id=rule["id"],
            defaults={
                "result": result,
                "severity": rule["severity"].upper(),
                "confidence": rule["confidence"].upper(),
                "title": rule["title"],
                "mapping_data": mapping_data,
                "evidence_summary": evidence_summary,
                "remediation": rule["recommendation"],
                "requires_manual_validation": (
                    result == RuleEvaluation.Result.REVIEW_REQUIRED
                    or rule["requires_manual_validation"]
                ),
                "evaluator_version": EVALUATOR_VERSION,
            },
        )
        summary["evaluated_rules"] += int(result != RuleEvaluation.Result.NOT_EVALUATED)
        summary[_summary_key(result)] += 1

        if result != RuleEvaluation.Result.FAIL:
            Finding.objects.filter(audit_id=audit_id, rule_id=rule["id"]).delete()
            continue

        finding, created = Finding.objects.update_or_create(
            audit_id=audit_id,
            rule_id=rule["id"],
            defaults={
                "title": rule["title"],
                "severity": rule["severity"],
                "confidence": rule["confidence"],
                "standard": rule["standard"],
                "category": rule["masvs_category"],
                "description": rule["description"],
                "mapping_data": mapping_data,
                "recommendation": rule["recommendation"],
                "false_positive_guidance": rule["false_positive_guidance"],
                "requires_manual_validation": rule["requires_manual_validation"],
            },
        )
        summary["findings_created" if created else "findings_existing"] += 1
        evidence_created = _upsert_finding_evidence(
            audit_id=audit_id,
            finding=finding,
            evidence_type=rule["detection_type"],
            source=rule["source"],
            snippet=evidence_summary[:500],
            redacted="secret" in rule["condition"],
        )
        summary["evidence_created"] += int(evidence_created)

    return summary


def _summary_key(result: str) -> str:
    return {
        RuleEvaluation.Result.PASS: "passed",
        RuleEvaluation.Result.FAIL: "failed",
        RuleEvaluation.Result.REVIEW_REQUIRED: "review_required",
        RuleEvaluation.Result.NOT_EVALUATED: "not_evaluated",
        RuleEvaluation.Result.NOT_APPLICABLE: "not_evaluated",
    }[result]


def _artifact_map(audit_id: int) -> dict[str, dict]:
    artifacts: dict[str, dict] = {}
    apk_file = APKFile.objects.filter(audit_id=audit_id).order_by("-created_at", "-id").first()
    queryset = NormalizedArtifact.objects.filter(
        audit_id=audit_id,
        apk_file=apk_file,
    ).order_by("created_at", "id")
    for artifact in queryset:
        value = artifact.normalized_data if isinstance(artifact.normalized_data, dict) else {}
        data = value.get("data") if isinstance(value.get("data"), dict) else value
        status = value.get("extraction_status")
        if status in {"FAILED", "NOT_STARTED"}:
            continue
        artifacts[artifact.artifact_type] = data
    return artifacts


def _evaluate_condition(condition: str, artifacts: dict[str, dict]) -> tuple[bool, str]:
    manifest = artifacts.get("MANIFEST", {})
    application = manifest.get("application", {})
    components = manifest.get("components", [])
    permissions = {
        item.get("name") if isinstance(item, dict) else item
        for item in manifest.get("permissions", [])
    }
    declared_permissions = manifest.get("declared_permissions", [])
    network = artifacts.get("NETWORK_SECURITY_CONFIG", {})
    signing = artifacts.get("SIGNING", {})
    certificates = artifacts.get("CERTIFICATE", {}).get("certificates", [])
    secrets = artifacts.get("SECRETS", {}).get("matches", [])
    crypto = artifacts.get("CRYPTO_USAGE", {}).get("matches", [])
    webview = artifacts.get("WEBVIEW_USAGE", {}).get("matches", [])
    native = artifacts.get("NATIVE_LIBRARIES", {})
    references = artifacts.get("CODE_REFERENCES", {}).get("matches", [])
    source_matches = artifacts.get("SOURCE_VERIFICATION", {}).get("matches", [])
    resources = artifacts.get("RESOURCES", {})

    scalar_conditions = {
        "manifest_debuggable": (application.get("debuggable") is True, "application.debuggable=true"),
        "manifest_allow_backup": (
            application.get("allow_backup") is True
            and not application.get("full_backup_content")
            and not application.get("data_extraction_rules"),
            "application.allow_backup=true with no explicit backup exclusion resource",
        ),
        "manifest_cleartext": (
            application.get("uses_cleartext_traffic") is True,
            "application.uses_cleartext_traffic=true",
        ),
        "manifest_test_only": (application.get("test_only") is True, "application.test_only=true"),
        "request_legacy_storage": (
            application.get("request_legacy_external_storage") is True,
            "application.request_legacy_external_storage=true",
        ),
        "shared_user_id": (bool(manifest.get("shared_user_id")), "manifest.shared_user_id is declared"),
        "custom_task_affinity": (
            bool(application.get("task_affinity"))
            or any(item.get("task_affinity") for item in components if isinstance(item, dict)),
            "custom taskAffinity declaration observed",
        ),
        "network_user_ca": (network.get("user_ca_trust") is True, "user_ca_trust=true"),
        "network_debug_overrides": (network.get("debug_overrides") is True, "debug-overrides present"),
        "network_domain_cleartext": (
            any(item.get("cleartext_traffic_permitted") is True for item in network.get("domains", [])),
            "per-domain cleartextTrafficPermitted=true",
        ),
        "missing_pinning_review": (
            network.get("status") == "PARSED" and not network.get("pin_sets"),
            "no certificate pin-set observed; requirement is threat-model dependent",
        ),
        "unsigned_apk": (
            signing.get("signed") is False or signing.get("malformed") is True,
            "valid APK signature not confirmed",
        ),
        "invalid_certificate_dates": (
            any(item.get("expired") or item.get("not_yet_valid") for item in certificates),
            "signer certificate validity check failed",
        ),
        "debug_certificate": (
            any(item.get("debug_certificate_indicator") for item in certificates),
            "Android debug certificate indicator observed",
        ),
        "legacy_only_signing": (signing.get("legacy_only") is True, "only APK Signature Scheme v1 observed"),
        "native_hardening_review": (
            bool(native.get("libraries"))
            and any(
                item.get("hardening", {}).get("status") == "NOT_EVALUATED"
                for item in native.get("libraries", [])
            ),
            "native libraries present; hardening capability unavailable",
        ),
        "privacy_permission_review": (
            bool(permissions & SENSITIVE_PERMISSIONS),
            f"privacy-sensitive permissions: {', '.join(sorted(permissions & SENSITIVE_PERMISSIONS)[:8])}",
        ),
    }
    if condition in scalar_conditions:
        return scalar_conditions[condition]

    verified_source_conditions = {
        "verified_contextual_secret": {"verified_contextual_secret"},
        "verified_risky_crypto": {"verified_risky_crypto"},
        "verified_insecure_tls_protocol": {"verified_insecure_tls_protocol"},
        "verified_hardcoded_crypto_key": {"verified_hardcoded_crypto_key"},
        "verified_hardcoded_http_url": {"verified_hardcoded_http_url"},
        "verified_webview_file_access": {"verified_webview_file_access"},
        "verified_webview_debug": {"verified_webview_debug"},
        "verified_webview_ssl_proceed": {"verified_webview_ssl_proceed"},
        "verified_webview_mixed_content": {"verified_webview_mixed_content"},
    }
    if condition in verified_source_conditions:
        return _source_condition(
            source_matches,
            verified_source_conditions[condition],
            require_verified=True,
        )
    if condition == "webview_javascript_bridge_review":
        return _source_condition(source_matches, {condition}, require_verified=False)
    if condition == "insecure_random_review":
        return _source_condition(source_matches, {condition}, require_verified=False)
    if condition == "external_storage_api_review":
        return _source_condition(source_matches, {condition}, require_verified=False)
    if condition == "safebrowsing_disabled":
        metadata = application.get("metadata", [])
        manifest_disabled = any(
            isinstance(item, dict)
            and item.get("name") == "android.webkit.WebView.EnableSafeBrowsing"
            and str(item.get("value") or "").lower() == "false"
            for item in metadata
        )
        code_match, code_summary = _source_condition(
            source_matches,
            {"verified_safebrowsing_disabled"},
            require_verified=True,
        )
        if manifest_disabled:
            return True, "AndroidManifest.xml explicitly disables WebView Safe Browsing"
        return code_match, code_summary
    if condition == "broad_file_provider_path":
        matches = resources.get("file_provider_paths", [])
        risky = [item for item in matches if item.get("oversharing") is True]
        return bool(risky), f"broad FileProvider path declarations: {len(risky)}"

    if condition.startswith("exported_") and condition.endswith("_unprotected"):
        component_type = condition.removeprefix("exported_").removesuffix("_unprotected")
        matches = [
            item
            for item in components
            if isinstance(item, dict)
            and item.get("type") == component_type
            and item.get("exported") is True
            and not any(
                item.get(field)
                for field in ("permission", "read_permission", "write_permission")
            )
        ]
        return bool(matches), f"{len(matches)} exported {component_type}(s) without permission guard"
    if condition == "weak_custom_permission":
        matches = [
            item.get("name")
            for item in declared_permissions
            if isinstance(item, dict)
            and str(item.get("protection_level") or "").lower() not in {"signature", "signatureorsystem"}
        ]
        return bool(matches), f"weak custom permission declarations: {len(matches)}"
    if condition == "custom_uri_scheme":
        matches = [item for item in manifest.get("deep_links", []) if item.get("scheme") not in {"http", "https"}]
        return bool(matches), f"custom URI scheme declarations: {len(matches)}"
    if condition == "unverified_app_link":
        matches = [
            item
            for item in manifest.get("deep_links", [])
            if item.get("scheme") in {"http", "https"} and not item.get("auto_verify")
        ]
        return bool(matches), f"unverified HTTP(S) app links: {len(matches)}"
    if condition == "old_target_sdk":
        try:
            target = int(manifest.get("target_sdk"))
        except (TypeError, ValueError):
            return False, "target SDK not available"
        return target < 31, f"targetSdkVersion={target}"
    if condition == "expired_pin_set":
        today = date.today().isoformat()
        expirations = [
            item.get("expiration")
            for item in network.get("pin_sets", [])
            if item.get("expiration") and item["expiration"] < today
        ]
        return bool(expirations), f"expired pin-set declarations: {len(expirations)}"
    if condition == "weak_certificate_algorithm":
        weak = [
            item
            for item in certificates
            if any(
                token in str(item.get(field, "")).lower().replace("-", "")
                for field in ("signature_algorithm", "hash_algorithm")
                for token in ("md5", "sha1")
            )
        ]
        return bool(weak), f"weak signer algorithm references: {len(weak)}"
    if condition == "contextual_secret":
        matches = [item for item in secrets if item.get("type") != "HIGH_ENTROPY_CONSTANT"]
        return bool(matches), f"redacted contextual secret patterns: {len(matches)}"
    if condition == "entropy_secret_review":
        matches = [item for item in secrets if item.get("type") == "HIGH_ENTROPY_CONSTANT"]
        return bool(matches), f"redacted high-entropy constants: {len(matches)}"
    if condition == "risky_crypto_reference":
        risky = {"ECB_MODE", "DES", "RC4", "MD5_REFERENCE", "SHA1_REFERENCE", "WEAK_RANDOM_REFERENCE"}
        matches = [item for item in crypto if item.get("type") in risky]
        return bool(matches), f"risky cryptographic references: {len(matches)}"
    if condition == "permissive_tls_reference":
        matches = [item for item in crypto if item.get("type") == "PERMISSIVE_TRUST_REFERENCE"]
        return bool(matches), f"TrustManager/HostnameVerifier references: {len(matches)}"
    if condition == "insecure_tls_reference":
        matches = [item for item in crypto if item.get("type") == "INSECURE_TLS_REFERENCE"]
        return bool(matches), f"deprecated TLS/SSL references: {len(matches)}"
    if condition == "hardcoded_http_url_review":
        matches = [
            item
            for item in artifacts.get("URLS_AND_ENDPOINTS", {}).get("urls", [])
            if item.get("cleartext") is True
        ]
        return bool(matches), f"hardcoded cleartext URL observations: {len(matches)}"
    webview_types = {
        "webview_file_access": {"FILE_ACCESS_REFERENCE", "UNIVERSAL_FILE_ACCESS_REFERENCE"},
        "webview_js_bridge": {"JAVASCRIPT_BRIDGE_REFERENCE"},
        "webview_debug": {"WEBVIEW_DEBUG_REFERENCE"},
        "webview_ssl_handler": {"SSL_ERROR_HANDLER_REFERENCE"},
        "webview_mixed_content": {"MIXED_CONTENT_REFERENCE"},
    }
    if condition in webview_types:
        matches = [item for item in webview if item.get("type") in webview_types[condition]]
        return bool(matches), f"matched WebView references: {len(matches)}"
    if condition == "logging_reference_review":
        matches = [item for item in references if item.get("category") == "logging"]
        return bool(matches), f"logging API references: {len(matches)}"
    if condition == "insecure_random_reference_review":
        source_match, source_summary = _source_condition(
            source_matches,
            {"insecure_random_review"},
            require_verified=False,
        )
        dex_matches = [item for item in crypto if item.get("type") == "WEAK_RANDOM_REFERENCE"]
        if source_match:
            return True, source_summary
        return bool(dex_matches), f"java.util.Random references: {len(dex_matches)}"
    if condition == "external_storage_api_reference_review":
        source_match, source_summary = _source_condition(
            source_matches,
            {"external_storage_api_review"},
            require_verified=False,
        )
        dex_matches = [item for item in references if item.get("category") == "external_storage"]
        if source_match:
            return True, source_summary
        return bool(dex_matches), f"external storage API references: {len(dex_matches)}"
    return False, f"condition '{condition}' produced no match"


def _source_condition(
    matches: list[dict],
    semantic_keys: set[str],
    *,
    require_verified: bool,
) -> tuple[bool, str]:
    selected = [
        item
        for item in matches
        if isinstance(item, dict)
        and item.get("semantic_key") in semantic_keys
        and (not require_verified or item.get("verified") is True)
    ]
    locations = [
        f"{item.get('logical_path')}:{item.get('start_line')}-{item.get('end_line')}"
        for item in selected[:5]
    ]
    suffix = f" at {', '.join(locations)}" if locations else ""
    return bool(selected), f"source observations: {len(selected)}{suffix}"


def _upsert_finding_evidence(
    *,
    audit_id: int,
    finding: Finding,
    evidence_type: str,
    source: str,
    snippet: str,
    redacted: bool,
) -> bool:
    existing = list(
        Evidence.objects.filter(
            audit_id=audit_id,
            finding=finding,
            indicator=None,
            evidence_type=evidence_type,
            source=source,
        ).order_by("id")
    )
    if existing:
        evidence = existing[0]
        evidence.snippet = snippet
        evidence.redacted = redacted
        evidence.save(update_fields=["snippet", "redacted"])
        if len(existing) > 1:
            Evidence.objects.filter(id__in=[item.id for item in existing[1:]]).delete()
        return False
    Evidence.objects.create(
        audit_id=audit_id,
        finding=finding,
        evidence_type=evidence_type,
        source=source,
        snippet=snippet,
        redacted=redacted,
    )
    return True
