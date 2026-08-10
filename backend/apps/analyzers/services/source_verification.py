from __future__ import annotations

import re
from bisect import bisect_right
from dataclasses import dataclass
from hashlib import sha256

from django.conf import settings
from django.db import transaction

from apps.analyzers.services.base import AnalyzerContext
from apps.evidence.models import SourceDocument
from apps.evidence.services.source_content import (
    SourceDocumentContentError,
    SourceDocumentContentService,
)
from apps.normalization.models import NormalizedArtifact


SOURCE_VERIFIER_VERSION = "1.0.0"
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
CALL_FLAGS = re.IGNORECASE | re.MULTILINE


@dataclass(frozen=True)
class SourceVerificationResult:
    status: str
    documents_scanned: int
    verified_matches: int
    review_observations: int
    first_party_package: str
    warnings: tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "documents_scanned": self.documents_scanned,
            "verified_matches": self.verified_matches,
            "review_observations": self.review_observations,
            "first_party_package": self.first_party_package,
            "warnings": list(self.warnings),
        }


class SourceVerificationService:
    """Confirm source-level conditions against first-party JADX documents.

    DEX references remain useful review signals, but only observations produced by
    this service may satisfy a ``verified_*`` rule condition. Each observation is
    tied to an exact generated document and line range.
    """

    def __init__(
        self,
        *,
        content_service: SourceDocumentContentService | None = None,
    ):
        self.content_service = content_service or SourceDocumentContentService()
        self.max_matches = settings.MSAP_MAX_NORMALIZED_MATCHES

    @transaction.atomic
    def verify(self, context: AnalyzerContext) -> SourceVerificationResult:
        package_name = str(context.apk_file.package_name or "").strip()
        documents = list(
            SourceDocument.objects.filter(
                audit=context.audit,
                apk_file=context.apk_file,
                representation_type__in=JADX_REPRESENTATIONS,
            )
            .select_related("storage_reference")
            .order_by("logical_path", "id")
        )
        first_party = [
            document
            for document in documents
            if _is_first_party_document(document, package_name)
        ]
        warnings: list[str] = []
        if not package_name:
            warnings.append(
                "Package identity is unavailable; JADX code was not classified as first-party."
            )
        elif documents and not first_party:
            warnings.append(
                "No JADX document matched the analyzed package namespace."
            )

        matches: list[dict] = []
        seen: set[tuple[str, int, int, int]] = set()
        for document in first_party:
            if len(matches) >= self.max_matches:
                break
            try:
                content = self.content_service.read_text(document)
            except SourceDocumentContentError:
                warnings.append(
                    f"Source document {document.id} failed integrity-checked reading."
                )
                continue
            self._scan_document(document, content, matches, seen)

        self._confirm_secret_locations(context, first_party, matches, seen)
        matches.sort(
            key=lambda item: (
                item["logical_path"],
                item["start_line"],
                item["end_line"],
                item["semantic_key"],
            )
        )
        matches = matches[: self.max_matches]
        locators = [_locator_for_match(item) for item in matches]
        status = "COMPLETED" if first_party else "SOURCE_UNAVAILABLE"
        data = {
            "verification_status": status,
            "verifier_version": SOURCE_VERIFIER_VERSION,
            "first_party_package": package_name,
            "documents_scanned": len(first_party),
            "matches": matches,
            "_source_locators": locators,
            "trust_boundary": (
                "Only exact first-party JADX call/configuration observations are marked verified. "
                "Reference-only DEX matches remain review signals."
            ),
        }
        NormalizedArtifact.objects.update_or_create(
            audit=context.audit,
            apk_file=context.apk_file,
            artifact_type=NormalizedArtifact.ArtifactType.SOURCE_VERIFICATION,
            source="source_verification",
            defaults={
                "normalized_data": {
                    "schema_version": "2.0",
                    "analyzer_name": "source_verification",
                    "analyzer_version": SOURCE_VERIFIER_VERSION,
                    "source": "indexed first-party JADX documents",
                    "extraction_status": status,
                    "warnings": warnings,
                    "data": data,
                },
                "storage_reference": None,
            },
        )
        return SourceVerificationResult(
            status=status,
            documents_scanned=len(first_party),
            verified_matches=sum(item["verified"] for item in matches),
            review_observations=sum(not item["verified"] for item in matches),
            first_party_package=package_name,
            warnings=tuple(warnings),
        )

    def _scan_document(
        self,
        document: SourceDocument,
        content: str,
        matches: list[dict],
        seen: set[tuple[str, int, int, int]],
    ) -> None:
        starts = _line_starts(content)

        for call in re.finditer(
            r"\bCipher\s*\.\s*getInstance\s*\(\s*([\"'])"
            r"(?P<value>[^\"'\r\n]{1,128})\1",
            content,
            CALL_FLAGS,
        ):
            transformation = call.group("value").strip()
            if _broken_cipher(transformation):
                self._add(
                    document,
                    content,
                    starts,
                    call,
                    "verified_risky_crypto",
                    "Broken symmetric cipher or mode",
                    matches,
                    seen,
                    detail={"transformation": transformation},
                )

        self._scan_regex(
            document,
            content,
            starts,
            re.compile(
                r"\b(?:SSLContext|SSLSocketFactory)\s*\.\s*getInstance\s*\(\s*"
                r"([\"'])(?:SSLv?3|TLSv1(?:\.0)?)\1",
                CALL_FLAGS,
            ),
            "verified_insecure_tls_protocol",
            "Deprecated TLS/SSL protocol explicitly selected",
            matches,
            seen,
        )
        self._scan_regex(
            document,
            content,
            starts,
            re.compile(
                r"\bsetEnabledProtocols\s*\(\s*(?:new\s+String\s*\[\]\s*)?"
                r"\{?[^;]{0,240}([\"'])(?:SSLv?3|TLSv1(?:\.0)?)\1",
                CALL_FLAGS,
            ),
            "verified_insecure_tls_protocol",
            "Deprecated TLS/SSL protocol explicitly enabled",
            matches,
            seen,
        )
        self._scan_regex(
            document,
            content,
            starts,
            re.compile(
                r"\bsetAllow(?:FileAccess|FileAccessFromFileURLs|"
                r"UniversalAccessFromFileURLs)\s*\(\s*true\s*\)",
                CALL_FLAGS,
            ),
            "verified_webview_file_access",
            "WebView local/universal file access explicitly enabled",
            matches,
            seen,
        )
        self._scan_regex(
            document,
            content,
            starts,
            re.compile(r"\bsetWebContentsDebuggingEnabled\s*\(\s*true\s*\)", CALL_FLAGS),
            "verified_webview_debug",
            "WebView debugging explicitly enabled",
            matches,
            seen,
        )
        self._scan_regex(
            document,
            content,
            starts,
            re.compile(r"\bsetSafeBrowsingEnabled\s*\(\s*false\s*\)", CALL_FLAGS),
            "verified_safebrowsing_disabled",
            "WebView Safe Browsing explicitly disabled",
            matches,
            seen,
        )
        self._scan_regex(
            document,
            content,
            starts,
            re.compile(
                r"\bsetMixedContentMode\s*\(\s*(?:WebSettings\s*\.\s*)?"
                r"MIXED_CONTENT_ALWAYS_ALLOW\s*\)",
                CALL_FLAGS,
            ),
            "verified_webview_mixed_content",
            "WebView mixed content set to always allow",
            matches,
            seen,
        )
        self._scan_regex(
            document,
            content,
            starts,
            re.compile(r"\baddJavascriptInterface\s*\(", CALL_FLAGS),
            "webview_javascript_bridge_review",
            "JavaScript bridge exposed; loaded origins require validation",
            matches,
            seen,
            verified=False,
        )
        self._scan_regex(
            document,
            content,
            starts,
            re.compile(r"\bnew\s+(?:java\s*\.\s*util\s*\.)?Random\s*\(", CALL_FLAGS),
            "insecure_random_review",
            "java.util.Random construction requires security-context validation",
            matches,
            seen,
            verified=False,
        )
        self._scan_regex(
            document,
            content,
            starts,
            re.compile(
                r"\b(?:getExternalStorageDirectory|getExternalStoragePublicDirectory|"
                r"getExternalFilesDir|getExternalCacheDir)\s*\(",
                CALL_FLAGS,
            ),
            "external_storage_api_review",
            "External/shared storage API reference",
            matches,
            seen,
            verified=False,
        )
        self._scan_regex(
            document,
            content,
            starts,
            re.compile(
                r"\b(?:new\s+URL|Uri\s*\.\s*parse|loadUrl|\.\s*url|\.\s*baseUrl)"
                r"\s*\(\s*([\"'])http://[^\"'\s<>]{3,500}\1",
                CALL_FLAGS,
            ),
            "verified_hardcoded_http_url",
            "Hardcoded cleartext URL passed directly to a URL/network API",
            matches,
            seen,
        )
        self._scan_regex(
            document,
            content,
            starts,
            re.compile(
                r"\bnew\s+SecretKeySpec\s*\(\s*([\"'])[^\"'\r\n]{4,256}\1"
                r"\s*\.\s*getBytes\s*\(",
                CALL_FLAGS,
            ),
            "verified_hardcoded_crypto_key",
            "Hardcoded string converted directly into a SecretKeySpec",
            matches,
            seen,
            redact_excerpt=True,
        )
        self._scan_ssl_error_handlers(document, content, starts, matches, seen)

    def _scan_ssl_error_handlers(
        self,
        document: SourceDocument,
        content: str,
        starts: list[int],
        matches: list[dict],
        seen: set[tuple[str, int, int, int]],
    ) -> None:
        for signature in re.finditer(r"\bonReceivedSslError\s*\([^)]*\)", content, CALL_FLAGS):
            opening = content.find("{", signature.end())
            if opening < 0 or opening - signature.end() > 300:
                continue
            closing = _balanced_block_end(content, opening)
            block_end = closing if closing is not None else min(len(content), opening + 6000)
            body = content[opening:block_end]
            proceed = re.search(r"\b\w+\s*\.\s*proceed\s*\(\s*\)", body, CALL_FLAGS)
            if not proceed:
                continue
            absolute_start = opening + proceed.start()
            absolute_end = opening + proceed.end()
            self._add_span(
                document,
                content,
                starts,
                absolute_start,
                absolute_end,
                "verified_webview_ssl_proceed",
                "SslErrorHandler.proceed() invoked from onReceivedSslError",
                matches,
                seen,
            )

    def _confirm_secret_locations(
        self,
        context: AnalyzerContext,
        documents: list[SourceDocument],
        matches: list[dict],
        seen: set[tuple[str, int, int, int]],
    ) -> None:
        artifact = NormalizedArtifact.objects.filter(
            audit=context.audit,
            apk_file=context.apk_file,
            artifact_type=NormalizedArtifact.ArtifactType.SECRETS,
        ).first()
        if not artifact:
            return
        envelope = artifact.normalized_data if isinstance(artifact.normalized_data, dict) else {}
        data = envelope.get("data") if isinstance(envelope.get("data"), dict) else envelope
        fingerprints: list[set[str]] = []
        for item in data.get("matches", []):
            if not isinstance(item, dict) or item.get("type") == "HIGH_ENTROPY_CONSTANT":
                continue
            values = {
                str(item.get("fingerprint_sha256") or ""),
                str(item.get("source_value_fingerprint_sha256") or ""),
            }
            values.discard("")
            if values:
                fingerprints.append(values)
        if not fingerprints:
            return

        for document in documents:
            if len(matches) >= self.max_matches:
                break
            try:
                content = self.content_service.read_text(document)
            except SourceDocumentContentError:
                continue
            starts = _line_starts(content)
            for line_number, line in enumerate(content.splitlines(), 1):
                literals = [match.group(2) for match in STRING_LITERAL.finditer(line)]
                literal_hashes = {
                    sha256(value.encode("utf-8", errors="ignore")).hexdigest()
                    for value in literals
                }
                if not any(literal_hashes & values for values in fingerprints):
                    continue
                start = starts[line_number - 1]
                end = start + len(line)
                self._add_span(
                    document,
                    content,
                    starts,
                    start,
                    end,
                    "verified_contextual_secret",
                    "Hardcoded secret fingerprint confirmed in first-party JADX source",
                    matches,
                    seen,
                    redact_excerpt=True,
                )

    def _scan_regex(
        self,
        document: SourceDocument,
        content: str,
        starts: list[int],
        pattern: re.Pattern,
        semantic_key: str,
        kind: str,
        matches: list[dict],
        seen: set[tuple[str, int, int, int]],
        *,
        verified: bool = True,
        redact_excerpt: bool = False,
    ) -> None:
        for call in pattern.finditer(content):
            self._add(
                document,
                content,
                starts,
                call,
                semantic_key,
                kind,
                matches,
                seen,
                verified=verified,
                redact_excerpt=redact_excerpt,
            )
            if len(matches) >= self.max_matches:
                return

    def _add(
        self,
        document: SourceDocument,
        content: str,
        starts: list[int],
        call: re.Match,
        semantic_key: str,
        kind: str,
        matches: list[dict],
        seen: set[tuple[str, int, int, int]],
        **kwargs,
    ) -> None:
        self._add_span(
            document,
            content,
            starts,
            call.start(),
            call.end(),
            semantic_key,
            kind,
            matches,
            seen,
            **kwargs,
        )

    def _add_span(
        self,
        document: SourceDocument,
        content: str,
        starts: list[int],
        start_offset: int,
        end_offset: int,
        semantic_key: str,
        kind: str,
        matches: list[dict],
        seen: set[tuple[str, int, int, int]],
        *,
        detail: dict | None = None,
        verified: bool = True,
        redact_excerpt: bool = False,
    ) -> None:
        start_line = _line_number(starts, start_offset)
        end_line = _line_number(starts, max(start_offset, end_offset - 1))
        identity = (semantic_key, document.id, start_line, end_line)
        if identity in seen or len(matches) >= self.max_matches:
            return
        seen.add(identity)
        lines = content.splitlines()
        matches.append(
            {
                "semantic_key": semantic_key,
                "kind": kind,
                "verified": verified,
                "document_id": document.id,
                "representation": document.representation_type,
                "logical_path": document.logical_path,
                "class_name": document.class_name,
                "method_name": _method_name(lines, start_line),
                "start_line": start_line,
                "end_line": end_line,
                "confidence": "HIGH" if verified else "MEDIUM",
                "redact_excerpt": redact_excerpt,
                "detail": detail or {},
            }
        )


def _locator_for_match(match: dict) -> dict:
    return {
        "representation": match["representation"],
        "semantic_key": match["semantic_key"],
        "logical_path": match["logical_path"],
        "class_name": match["class_name"],
        "method_name": match["method_name"],
        "search_terms": [],
        "start_line": match["start_line"],
        "end_line": match["end_line"],
        "confidence": match["confidence"],
        "locator": {
            "source_document_id": match["document_id"],
            "verified_source_match": match["verified"],
            "finding_cause": match["kind"],
            "redact_excerpt": match["redact_excerpt"],
            "ambiguous_match": False,
        },
    }


def _is_first_party_document(document: SourceDocument, package_name: str) -> bool:
    if not package_name:
        return False
    class_name = str(document.class_name or "")
    if class_name == package_name or class_name.startswith(f"{package_name}."):
        return True
    package_path = package_name.replace(".", "/")
    return document.logical_path.startswith(f"sources/{package_path}/")


def _broken_cipher(transformation: str) -> bool:
    normalized = transformation.upper().replace(" ", "")
    algorithm = normalized.split("/", 1)[0]
    if algorithm == "RSA":
        return False
    if algorithm in {"DES", "DESEDE", "TRIPLEDES", "RC2", "RC4", "ARCFOUR"}:
        return True
    if algorithm == "AES" and "/" not in normalized:
        return True
    return "/ECB/" in f"/{normalized.strip('/')}/"


def _line_starts(content: str) -> list[int]:
    starts = [0]
    starts.extend(match.end() for match in re.finditer(r"\n", content))
    return starts


def _line_number(starts: list[int], offset: int) -> int:
    return max(1, bisect_right(starts, offset))


def _balanced_block_end(content: str, opening: int) -> int | None:
    depth = 0
    quote = ""
    escaped = False
    for index in range(opening, min(len(content), opening + 20_000)):
        char = content[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in {'"', "'"}:
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index + 1
    return None


def _method_name(lines: list[str], anchor_line: int) -> str:
    lower = max(0, anchor_line - 60)
    for index in range(anchor_line - 1, lower - 1, -1):
        match = METHOD_SIGNATURE.search(lines[index])
        if match:
            return match.group(1)
    return ""
