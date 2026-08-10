from __future__ import annotations

import re
from collections import defaultdict
from hashlib import sha256
from pathlib import Path

from django.conf import settings
from django.db import transaction

from apps.appsec_rules.services.rule_loader import load_masvs_rules
from apps.apk_files.models import APKFile
from apps.audits.models import Audit
from apps.evidence.models import FindingSourceReference, SourceDocument
from apps.evidence.services.source_content import (
    SourceDocumentContentError,
    SourceDocumentContentService,
    redact_source_line,
)
from apps.findings.models import Finding
from apps.normalization.models import NormalizedArtifact


RISKY_CRYPTO_TYPES = {
    "ECB_MODE",
    "DES",
    "RC4",
    "MD5_REFERENCE",
    "SHA1_REFERENCE",
    "WEAK_RANDOM_REFERENCE",
}
WEBVIEW_TYPES = {
    "webview_file_access": {
        "FILE_ACCESS_REFERENCE",
        "UNIVERSAL_FILE_ACCESS_REFERENCE",
    },
    "webview_js_bridge": {"JAVASCRIPT_BRIDGE_REFERENCE"},
    "webview_debug": {"WEBVIEW_DEBUG_REFERENCE"},
    "webview_ssl_handler": {"SSL_ERROR_HANDLER_REFERENCE"},
}
SIGNING_CONDITIONS = {"unsigned_apk", "legacy_only_signing"}
CERTIFICATE_CONDITIONS = {
    "invalid_certificate_dates",
    "debug_certificate",
    "weak_certificate_algorithm",
}
JADX_REPRESENTATIONS = {
    SourceDocument.RepresentationType.JADX_SOURCE,
    SourceDocument.RepresentationType.JADX_JAVA,
    SourceDocument.RepresentationType.JADX_KOTLIN,
}
STRING_LITERAL = re.compile(r"([\"'])(.*?)(?<!\\)\1")
METHOD_SIGNATURE = re.compile(
    r"(?:public|private|protected|internal|static|final|synchronized|native|"
    r"abstract|override|open|suspend|fun|\s)+[\w<>, ?\[\].:@]+\s+(\w+)\s*\("
)


@transaction.atomic
def enrich_finding_source_references(
    audit: Audit,
    apk_file: APKFile,
    *,
    content_service: SourceDocumentContentService | None = None,
) -> dict:
    FindingSourceReference.objects.filter(finding__audit=audit).delete()
    rules = load_masvs_rules(
        Path(settings.ANALYZER_RULES_PATH) / "masvs_static_rules.yaml"
    )
    condition_by_rule = {rule["id"]: rule["condition"] for rule in rules}
    hints_by_semantic = _locator_hints(audit.id, apk_file.id)
    documents = list(
        SourceDocument.objects.filter(audit=audit, apk_file=apk_file)
        .select_related("storage_reference")
        .order_by("logical_path", "id")
    )
    resolver = _Resolver(
        audit=audit,
        apk_file=apk_file,
        documents=documents,
        content_service=content_service or SourceDocumentContentService(),
    )
    summary = {
        "findings_processed": 0,
        "line_references_created": 0,
        "non_line_references_created": 0,
        "ambiguous_findings": 0,
    }

    for finding in Finding.objects.filter(audit=audit).order_by("id"):
        condition = condition_by_rule.get(finding.rule_id, "")
        hints = _hints_for_condition(condition, hints_by_semantic)
        created = resolver.resolve(finding, condition, hints)
        if not created:
            created = [resolver.create_fallback(finding, condition, hints)]
        line_references = [item for item in created if item.source_lines_available]
        ambiguous_references = [
            item
            for item in line_references
            if isinstance(item.locator, dict) and item.locator.get("ambiguous_match")
        ]
        if ambiguous_references:
            FindingSourceReference.objects.filter(
                id__in=[item.id for item in ambiguous_references]
            ).update(confidence=FindingSourceReference.Confidence.LOW)
            finding.requires_manual_validation = True
            finding.save(update_fields=["requires_manual_validation"])
            summary["ambiguous_findings"] += 1
        summary["findings_processed"] += 1
        summary["line_references_created"] += len(line_references)
        summary["non_line_references_created"] += len(created) - len(line_references)
    return summary


def _locator_hints(audit_id: int, apk_file_id: int) -> dict[str, list[dict]]:
    index: dict[str, list[dict]] = defaultdict(list)
    for artifact in NormalizedArtifact.objects.filter(
        audit_id=audit_id,
        apk_file_id=apk_file_id,
    ).order_by("created_at", "id"):
        envelope = (
            artifact.normalized_data
            if isinstance(artifact.normalized_data, dict)
            else {}
        )
        data = envelope.get("data") if isinstance(envelope.get("data"), dict) else envelope
        for hint in data.get("_source_locators", []):
            if not isinstance(hint, dict) or not hint.get("semantic_key"):
                continue
            index[str(hint["semantic_key"])].append(hint)
    return index


def _hints_for_condition(condition: str, index: dict[str, list[dict]]) -> list[dict]:
    keys = [condition]
    if condition in {"contextual_secret", "verified_contextual_secret"}:
        keys = ["verified_contextual_secret"]
        keys.extend(
            key
            for key in index
            if key.startswith("secret:") and key != "secret:HIGH_ENTROPY_CONSTANT"
        )
    elif condition == "entropy_secret_review":
        keys = ["secret:HIGH_ENTROPY_CONSTANT"]
    elif condition in {"risky_crypto_reference", "verified_risky_crypto"}:
        keys = ["verified_risky_crypto"]
        keys.extend(f"crypto:{value}" for value in sorted(RISKY_CRYPTO_TYPES))
    elif condition == "permissive_tls_reference":
        keys = ["crypto:PERMISSIVE_TRUST_REFERENCE"]
    elif condition in WEBVIEW_TYPES:
        keys = [f"webview:{value}" for value in WEBVIEW_TYPES[condition]]
    elif condition == "verified_webview_file_access":
        keys = ["verified_webview_file_access"]
        keys.extend(f"webview:{value}" for value in WEBVIEW_TYPES["webview_file_access"])
    elif condition == "verified_webview_debug":
        keys = ["verified_webview_debug"]
        keys.extend(f"webview:{value}" for value in WEBVIEW_TYPES["webview_debug"])
    elif condition == "verified_webview_ssl_proceed":
        keys = ["verified_webview_ssl_proceed"]
        keys.extend(f"webview:{value}" for value in WEBVIEW_TYPES["webview_ssl_handler"])
    elif condition in SIGNING_CONDITIONS:
        keys = ["apk_signing_metadata"]
    elif condition in CERTIFICATE_CONDITIONS:
        keys = ["certificate_metadata"]
    elif condition == "safebrowsing_disabled":
        keys = ["safebrowsing_disabled", "verified_safebrowsing_disabled"]
    hints: list[dict] = []
    for key in keys:
        hints.extend(index.get(key, []))
    return hints


class _Resolver:
    def __init__(
        self,
        *,
        audit: Audit,
        apk_file: APKFile,
        documents: list[SourceDocument],
        content_service: SourceDocumentContentService,
    ):
        self.audit = audit
        self.apk_file = apk_file
        self.documents = documents
        self.content_service = content_service
        self.content_cache: dict[int, list[str]] = {}

    def resolve(
        self,
        finding: Finding,
        condition: str,
        hints: list[dict],
    ) -> list[FindingSourceReference]:
        created: list[FindingSourceReference] = []
        seen: set[tuple[int, int, int]] = set()
        for hint in hints:
            locator = hint.get("locator") if isinstance(hint.get("locator"), dict) else {}
            if locator.get("source_lines_available") is False:
                created.append(self._create_non_line(finding, hint))
                continue
            for document in self._candidate_documents(hint):
                matches = self._resolve_document(document, hint)
                ambiguity_override = locator.get("ambiguous_match")
                ambiguous = (
                    ambiguity_override
                    if isinstance(ambiguity_override, bool)
                    else len(matches) > 1
                )
                for start_line, end_line, anchor_line in matches[:5]:
                    identity = (document.id, start_line, end_line)
                    if identity in seen:
                        continue
                    seen.add(identity)
                    reference = self._create_line_reference(
                        finding,
                        document,
                        hint,
                        start_line,
                        end_line,
                        anchor_line,
                        ambiguous=ambiguous,
                        is_primary=not created,
                    )
                    created.append(reference)
                if len(created) >= 10:
                    return created
        return created

    def _candidate_documents(self, hint: dict) -> list[SourceDocument]:
        representation = str(hint.get("representation") or "")
        if representation == SourceDocument.RepresentationType.JADX_SOURCE:
            candidates = [
                item
                for item in self.documents
                if item.representation_type in JADX_REPRESENTATIONS
            ]
        else:
            candidates = [
                item for item in self.documents if item.representation_type == representation
            ]
        locator = hint.get("locator") if isinstance(hint.get("locator"), dict) else {}
        document_id = locator.get("source_document_id")
        if isinstance(document_id, int):
            candidates = [item for item in candidates if item.id == document_id]
        logical_path = str(hint.get("logical_path") or "").strip()
        if logical_path and not logical_path.endswith("/xml"):
            exact = [
                item
                for item in candidates
                if item.logical_path == logical_path
                or item.logical_path.endswith(logical_path.removeprefix("resources/"))
            ]
            candidates = exact
        class_name = str(hint.get("class_name") or "")
        if class_name and representation in JADX_REPRESENTATIONS:
            constrained = [item for item in candidates if item.class_name == class_name]
            candidates = constrained
        return candidates

    def _resolve_document(
        self,
        document: SourceDocument,
        hint: dict,
    ) -> list[tuple[int, int, int]]:
        lines = self._lines(document)
        if not lines:
            return []
        start_line = hint.get("start_line")
        end_line = hint.get("end_line")
        if isinstance(start_line, int) and isinstance(end_line, int):
            if 1 <= start_line <= end_line <= len(lines):
                return [(start_line, end_line, start_line)]
            return []

        locator = hint.get("locator") if isinstance(hint.get("locator"), dict) else {}
        fingerprint = str(locator.get("secret_fingerprint_sha256") or "")
        if fingerprint:
            fingerprints = {
                value
                for value in (
                    fingerprint,
                    str(locator.get("source_value_fingerprint_sha256") or ""),
                )
                if value
            }
            return [
                (number, number, number)
                for number, line in enumerate(lines, 1)
                if _line_has_secret_fingerprint(line, fingerprints)
            ]

        terms = [str(term) for term in hint.get("search_terms", []) if str(term)]
        if not terms:
            return []
        lowered_terms = [term.lower() for term in terms]
        matches: list[tuple[int, int, int]] = []
        for index, line in enumerate(lines):
            if lowered_terms[0] not in line.lower():
                continue
            window_start = max(0, index - 8)
            window_end = min(len(lines), index + 9)
            window = lines[window_start:window_end]
            joined = "\n".join(window).lower()
            if locator.get("match_all", False) and not all(
                term in joined for term in lowered_terms
            ):
                continue
            if not locator.get("match_all", False):
                matches.append((index + 1, index + 1, index + 1))
                continue
            positions = []
            for term in lowered_terms:
                candidates = [
                    number
                    for number in range(window_start, window_end)
                    if term in lines[number].lower()
                ]
                if candidates:
                    positions.append(min(candidates, key=lambda number: abs(number - index)))
            evidence_start = min(positions) + 1 if positions else index + 1
            evidence_end = max(positions) + 1 if positions else index + 1
            matches.append((evidence_start, evidence_end, index + 1))
        return matches

    def _create_line_reference(
        self,
        finding: Finding,
        document: SourceDocument,
        hint: dict,
        start_line: int,
        end_line: int,
        anchor_line: int,
        *,
        ambiguous: bool,
        is_primary: bool,
    ) -> FindingSourceReference:
        lines = self._lines(document)
        excerpt_start = max(1, min(start_line, anchor_line) - 4)
        excerpt_end = min(len(lines), max(end_line, anchor_line) + 5)
        if excerpt_end - excerpt_start + 1 > FindingSourceReference.MAX_EXCERPT_LINES:
            excerpt_end = excerpt_start + FindingSourceReference.MAX_EXCERPT_LINES - 1
        excerpt_lines = [
            redact_source_line(value)
            for value in lines[excerpt_start - 1 : excerpt_end]
        ]
        excerpt = "\n".join(excerpt_lines)
        method_name = str(hint.get("method_name") or "") or _method_name(
            lines,
            anchor_line,
        )
        confidence = str(hint.get("confidence") or "MEDIUM").upper()
        if ambiguous:
            confidence = FindingSourceReference.Confidence.LOW
        provenance_chain = {
            "apk_sha256": self.apk_file.sha256,
            "generated_by": document.generated_by,
            "tool_version": document.tool_version,
            "source_document_id": document.id,
            "source_document_sha256": document.sha256,
            "line_range": {"start": start_line, "end": end_line},
            "excerpt_sha256": sha256(excerpt.encode("utf-8")).hexdigest(),
            "finding_id": finding.id,
            "analyzer_evidence": hint.get("semantic_key"),
        }
        reference = FindingSourceReference(
            finding=finding,
            source_document=document,
            representation_type=document.representation_type,
            logical_path=document.logical_path,
            class_name=str(hint.get("class_name") or document.class_name),
            method_name=method_name,
            method_descriptor=str(hint.get("method_descriptor") or ""),
            symbol_name=str(hint.get("symbol") or ""),
            start_line=start_line,
            end_line=end_line,
            excerpt=excerpt,
            excerpt_sha256=provenance_chain["excerpt_sha256"],
            locator={
                **(
                    hint.get("locator")
                    if isinstance(hint.get("locator"), dict)
                    else {}
                ),
                "semantic_key": hint.get("semantic_key"),
                "excerpt_start_line": excerpt_start,
                "excerpt_end_line": excerpt_end,
                "ambiguous_match": ambiguous,
                "provenance_chain": provenance_chain,
            },
            confidence=confidence,
            is_primary=is_primary,
            provenance=str(
                document.metadata.get("provenance_note")
                or "MSAP generated and indexed representation."
            ),
            source_lines_available=True,
        )
        reference.full_clean()
        reference.save()
        return reference

    def _create_non_line(
        self,
        finding: Finding,
        hint: dict,
    ) -> FindingSourceReference:
        locator = hint.get("locator") if isinstance(hint.get("locator"), dict) else {}
        reason = str(locator.get("reason") or "Source lines are not applicable.")
        reference = FindingSourceReference(
            finding=finding,
            representation_type=str(
                hint.get("representation") or SourceDocument.RepresentationType.OTHER_TEXT
            ),
            logical_path=str(hint.get("logical_path") or "APK-METADATA"),
            class_name=str(hint.get("class_name") or ""),
            method_name=str(hint.get("method_name") or ""),
            method_descriptor=str(hint.get("method_descriptor") or ""),
            symbol_name=str(hint.get("symbol") or ""),
            start_offset=hint.get("start_offset"),
            end_offset=hint.get("end_offset"),
            locator={
                **locator,
                "semantic_key": hint.get("semantic_key"),
                "provenance_chain": {
                    "apk_sha256": self.apk_file.sha256,
                    "analyzer_evidence": hint.get("semantic_key"),
                    "finding_id": finding.id,
                },
            },
            confidence=str(hint.get("confidence") or "MEDIUM").upper(),
            is_primary=not finding.source_references.exists(),
            provenance="Bounded APK metadata produced during this assessment.",
            source_lines_available=False,
            unavailable_reason=reason,
        )
        reference.full_clean()
        reference.save()
        return reference

    def create_fallback(
        self,
        finding: Finding,
        condition: str,
        hints: list[dict],
    ) -> FindingSourceReference:
        if condition in SIGNING_CONDITIONS:
            representation = SourceDocument.RepresentationType.APK_SIGNING_METADATA
            path = "APK-SIGNING-METADATA"
            reason = "Finding originates from APK signing block metadata."
        elif condition in CERTIFICATE_CONDITIONS:
            representation = SourceDocument.RepresentationType.CERTIFICATE_METADATA
            path = "APK-SIGNER-CERTIFICATE"
            reason = "Finding originates from APK signer certificate metadata."
        elif condition == "native_hardening_review":
            representation = SourceDocument.RepresentationType.NATIVE_SYMBOL
            path = "native/library.so"
            reason = "Finding originates from native binary hardening metadata."
        elif condition.startswith("network_") or condition in {
            "expired_pin_set",
            "missing_pinning_review",
        }:
            representation = SourceDocument.RepresentationType.NETWORK_SECURITY_XML
            path = (
                str(hints[0].get("logical_path"))
                if hints and hints[0].get("logical_path")
                else "resources/res/xml/network-security-metadata"
            )
            reason = (
                "Decoded network security XML was unavailable; the finding is "
                "supported by parsed resource metadata without source lines."
            )
        elif condition == "broad_file_provider_path":
            representation = SourceDocument.RepresentationType.RESOURCE_XML
            path = (
                str(hints[0].get("logical_path"))
                if hints and hints[0].get("logical_path")
                else "resources/res/xml/file-provider-paths"
            )
            reason = (
                "Decoded FileProvider path XML was unavailable; the finding is "
                "supported by parsed resource metadata without source lines."
            )
        elif condition.startswith("manifest_") or condition.startswith("exported_") or condition in {
            "request_legacy_storage",
            "weak_custom_permission",
            "shared_user_id",
            "custom_task_affinity",
            "custom_uri_scheme",
            "unverified_app_link",
            "old_target_sdk",
            "privacy_permission_review",
            "safebrowsing_disabled",
        }:
            representation = SourceDocument.RepresentationType.MANIFEST_XML
            path = "AndroidManifest.xml"
            reason = (
                "Decoded AndroidManifest.xml source lines were unavailable; the "
                "finding is supported by parsed manifest metadata."
            )
        else:
            representation = SourceDocument.RepresentationType.DEX_METADATA
            path = "DEX-METADATA"
            reason = (
                "JADX decompiled source was unavailable or no unambiguous line "
                "could be resolved; the finding originates from bounded metadata "
                "aggregated from the APK classes*.dex entries, whose exact member "
                "was not retained by this analyzer version."
            )
        return self._create_non_line(
            finding,
            {
                "representation": representation,
                "semantic_key": condition,
                "logical_path": path,
                "confidence": "LOW" if hints else "MEDIUM",
                "locator": {
                    "source_lines_available": False,
                    "reason": reason,
                    "unresolved_locator_count": len(hints),
                },
            },
        )

    def _lines(self, document: SourceDocument) -> list[str]:
        if document.id not in self.content_cache:
            try:
                self.content_cache[document.id] = self.content_service.read_text(
                    document
                ).splitlines()
            except SourceDocumentContentError:
                self.content_cache[document.id] = []
        return self.content_cache[document.id]


def _line_has_secret_fingerprint(line: str, fingerprints: set[str]) -> bool:
    candidates = [match.group(2) for match in STRING_LITERAL.finditer(line)]
    candidates.extend(
        match.group(0) for match in re.finditer(r"(?:AKIA|ASIA)[A-Z0-9]{16}", line)
    )
    return any(
        sha256(candidate.encode("utf-8", errors="ignore")).hexdigest()
        in fingerprints
        for candidate in candidates
    )


def _method_name(lines: list[str], anchor_line: int) -> str:
    lower = max(0, anchor_line - 40)
    for index in range(anchor_line - 1, lower - 1, -1):
        match = METHOD_SIGNATURE.search(lines[index])
        if match:
            return match.group(1)
    return ""
