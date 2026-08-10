from collections import Counter
from contextlib import nullcontext
from datetime import datetime, timezone
from hashlib import sha256
from math import log2
from pathlib import Path
from re import compile as regex
from urllib.parse import urlsplit, urlunsplit
from zipfile import ZipFile
from xml.etree import ElementTree

import yaml
from androguard.core.apk import APK
from androguard.core.dex import DEX
from django.conf import settings

from apps.analyzers.models import RawAnalyzerResult
from apps.analyzers.services.base import AnalyzerContext, AnalyzerResult
from apps.analyzers.services.safe_archive import (
    UnsafeAPKArchive,
    validate_apk_archive,
)
from apps.analyzers.services.manifest_metadata_adapter import (
    ManifestMetadataAdapter,
    ManifestParsingError,
)
from apps.evidence.models import SourceDocument
from apps.normalization.models import NormalizedArtifact
from apps.normalization.services.schemas import (
    NormalizedArtifactPayload,
    SourceLocatorHint,
)
from apps.storage.services.file_provider import (
    APKChecksumMismatchError,
    APKDownloadError,
    APKFileProvider,
    APKFileUnavailableError,
    FileProvider,
)


URL_PATTERN = regex(r"(?i)\b(?:https?|wss?|ftp)://[^\s\"'<>]{4,500}")
AWS_KEY_PATTERN = regex(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
BEARER_PATTERN = regex(r"(?i)\bbearer\s+[a-z0-9._~+/=-]{20,}")
PASSWORD_PATTERN = regex(
    r"(?i)\b(?:password|passwd|pwd|api[_-]?key|secret|token)\s*[:=]\s*[\"']?([^\s\"']{8,})"
)
PRIVATE_KEY_PATTERN = regex(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
BASIC_AUTH_URL_PATTERN = regex(r"(?i)\bhttps?://[^/\s:@]+:[^/\s@]+@")
SECRET_TEST_VALUES = {
    "password",
    "changeme",
    "change-me",
    "example",
    "test",
    "dummy",
    "placeholder",
}
REFERENCE_PATTERNS = {
    "dynamic_loading": (
        "DexClassLoader",
        "PathClassLoader",
        "InMemoryDexClassLoader",
        "loadDex",
    ),
    "reflection": (
        "Class;->forName",
        "reflect/Method;->invoke",
        "getDeclaredMethod",
        "getDeclaredField",
    ),
    "native_loading": ("System;->loadLibrary", "System;->load"),
    "command_execution": (
        "Runtime;->exec",
        "ProcessBuilder",
        "java/lang/Process",
    ),
    "clipboard": ("ClipboardManager", "getPrimaryClip", "addPrimaryClipChangedListener"),
    "screen_capture": ("MediaProjectionManager", "ImageReader", "screencap"),
    "package_installation": ("REQUEST_INSTALL_PACKAGES", "PackageInstaller"),
    "logging": ("android/util/Log", "Timber;->", "Logger;->"),
    "external_storage": (
        "getExternalStorageDirectory",
        "getExternalStoragePublicDirectory",
        "getExternalFilesDir",
        "getExternalCacheDir",
    ),
    "webview": ("android/webkit/WebView", "android/webkit/WebSettings"),
}
CRYPTO_PATTERNS = {
    "ECB_MODE": ("AES/ECB", "/ECB/"),
    "DES": ("DES/", "DESede", "TripleDES"),
    "RC4": ("RC4", "ARCFOUR"),
    "MD5_REFERENCE": ("MessageDigest;->getInstance", "MD5"),
    "SHA1_REFERENCE": ("SHA-1", "SHA1"),
    "INSECURE_TLS_REFERENCE": ("TLSv1\"", "TLSv1.0", "SSLv3"),
    "PERMISSIVE_TRUST_REFERENCE": (
        "X509TrustManager",
        "checkServerTrusted",
        "HostnameVerifier",
    ),
    "WEAK_RANDOM_REFERENCE": ("java/util/Random",),
}
WEBVIEW_PATTERNS = {
    "JAVASCRIPT_ENABLE_REFERENCE": ("setJavaScriptEnabled",),
    "JAVASCRIPT_BRIDGE_REFERENCE": ("addJavascriptInterface",),
    "FILE_ACCESS_REFERENCE": ("setAllowFileAccess",),
    "UNIVERSAL_FILE_ACCESS_REFERENCE": ("setAllowUniversalAccessFromFileURLs",),
    "MIXED_CONTENT_REFERENCE": ("setMixedContentMode",),
    "SSL_ERROR_HANDLER_REFERENCE": ("onReceivedSslError", "SslErrorHandler;->proceed"),
    "WEBVIEW_DEBUG_REFERENCE": ("setWebContentsDebuggingEnabled",),
    "URL_LOADING_REFERENCE": ("loadUrl", "shouldOverrideUrlLoading"),
}
SUSPICIOUS_FILENAMES = {
    "su",
    "busybox",
    "frida-gadget.so",
    "payload.dex",
    "update.bin",
    "rat.jar",
}


class AdvancedStaticAnalyzer:
    name = "advanced_static_analyzer"
    version = "1.0.0"
    description = (
        "Bounded package, signing, DEX, secrets, crypto, WebView, native, "
        "dependency, endpoint, and resilience inspection."
    )
    enabled = True
    available = True
    optional = False

    def __init__(self, file_provider: FileProvider | None = None):
        self.file_provider = file_provider or APKFileProvider()

    def supports(self, context: AnalyzerContext) -> bool:
        return context.apk_file.storage_reference_id is not None

    def run(self, context: AnalyzerContext) -> AnalyzerResult:
        try:
            with self._open_local_copy(context.apk_file) as local_path:
                artifacts, summary = self._analyze(Path(local_path))
        except APKFileUnavailableError as exc:
            return self._result(RawAnalyzerResult.Status.SKIPPED, str(exc))
        except (APKChecksumMismatchError, APKDownloadError, UnsafeAPKArchive) as exc:
            return self._result(RawAnalyzerResult.Status.FAILED, str(exc))
        except Exception:
            return self._result(
                RawAnalyzerResult.Status.FAILED,
                "Advanced static APK inspection failed safely.",
            )
        return AnalyzerResult(
            analyzer_name=self.name,
            analyzer_version=self.version,
            status=RawAnalyzerResult.Status.COMPLETED,
            raw_summary=summary,
            normalized_artifacts=artifacts,
        )

    def _analyze(self, path: Path) -> tuple[list[NormalizedArtifactPayload], dict]:
        archive_summary = validate_apk_archive(path)
        warnings: list[str] = []
        strings: list[str] = []
        class_names: list[str] = []
        method_references: list[str] = []
        dex_failures = 0

        with ZipFile(path) as archive:
            entries = archive.infolist()
            extension_counts = Counter(
                Path(item.filename).suffix.lower() or "[none]" for item in entries
            )
            for dex_name in archive_summary.dex_entries:
                info = archive.getinfo(dex_name)
                if info.file_size > settings.MSAP_MAX_DEX_BYTES:
                    warnings.append(f"{dex_name}: skipped because it exceeds DEX limit")
                    dex_failures += 1
                    continue
                try:
                    dex = DEX(archive.read(info))
                    strings.extend(
                        value
                        for value in dex.get_strings()[:250_000]
                        if isinstance(value, str) and len(value) <= 4096
                    )
                    class_names.extend(dex.get_classes_names())
                    for method in dex.get_methods()[:500_000]:
                        method_references.append(
                            f"{method.get_class_name()}->{method.get_name()}"
                        )
                except Exception:
                    dex_failures += 1
                    warnings.append(f"{dex_name}: DEX metadata parsing failed")

            combined_references = strings + class_names + method_references
            matched_references = _matched_references(combined_references)
            urls = _urls(strings)
            secrets = _secret_matches(strings)
            crypto = _pattern_matches(combined_references, CRYPTO_PATTERNS)
            webview = _pattern_matches(combined_references, WEBVIEW_PATTERNS)
            native = _native_inventory(archive_summary.native_entries)
            sdk_inventory = _sdk_inventory(class_names)
            network_security = _network_security_config(archive, warnings)
            file_provider_paths = _file_provider_paths(path, archive, warnings)
            signing, certificates = _signing_metadata(path, warnings)

        suspicious_names = sorted(
            {
                Path(item.filename).name.lower()
                for item in entries
                if Path(item.filename).name.lower() in SUSPICIOUS_FILENAMES
            }
        )
        short_class_count = sum(
            1
            for name in class_names
            if len(name.rsplit("/", 1)[-1].strip(";")) <= 2
        )
        obfuscation_ratio = (
            round(short_class_count / len(class_names), 3) if class_names else 0
        )
        relevant_strings = _relevant_string_fingerprints(
            strings,
            matched_references,
            urls,
        )

        artifact_data = {
            NormalizedArtifact.ArtifactType.PACKAGE_CONTENT: {
                "entry_count": archive_summary.entry_count,
                "compressed_bytes": archive_summary.compressed_bytes,
                "uncompressed_bytes": archive_summary.uncompressed_bytes,
                "max_compression_ratio": archive_summary.max_compression_ratio,
                "extension_counts": dict(extension_counts.most_common(40)),
                "suspicious_filenames": suspicious_names,
            },
            NormalizedArtifact.ArtifactType.DEX_METADATA: {
                "dex_count": len(archive_summary.dex_entries),
                "parsed_dex_count": len(archive_summary.dex_entries) - dex_failures,
                "failed_dex_count": dex_failures,
                "class_count": len(class_names),
                "method_reference_count": len(method_references),
                "string_count": len(strings),
                "package_namespaces": _package_namespaces(class_names),
            },
            NormalizedArtifact.ArtifactType.CODE_REFERENCES: {
                "matches": matched_references,
            },
            NormalizedArtifact.ArtifactType.STRINGS: {
                "string_count": len(strings),
                "relevant_string_fingerprints": relevant_strings,
                "full_strings_persisted": False,
            },
            NormalizedArtifact.ArtifactType.SECRETS: {
                "matches": secrets,
                "values_redacted": True,
            },
            NormalizedArtifact.ArtifactType.CRYPTO_USAGE: {
                "matches": crypto,
                "static_reference_only": True,
            },
            NormalizedArtifact.ArtifactType.WEBVIEW_USAGE: {
                "matches": webview,
                "static_reference_only": True,
            },
            NormalizedArtifact.ArtifactType.NATIVE_LIBRARIES: native,
            NormalizedArtifact.ArtifactType.THIRD_PARTY_SDKS: {
                "inventory": sdk_inventory,
                "inventory_kind": "probable dependency inventory",
                "complete_sbom": False,
            },
            NormalizedArtifact.ArtifactType.URLS_AND_ENDPOINTS: {
                "urls": urls,
                "query_values_persisted": False,
            },
            NormalizedArtifact.ArtifactType.NETWORK_SECURITY_CONFIG: network_security,
            NormalizedArtifact.ArtifactType.RESOURCES: {
                "file_provider_paths": file_provider_paths,
            },
            NormalizedArtifact.ArtifactType.SIGNING: signing,
            NormalizedArtifact.ArtifactType.CERTIFICATE: {
                "certificates": certificates,
            },
            NormalizedArtifact.ArtifactType.RESILIENCE_SIGNALS: {
                "obfuscation_ratio": obfuscation_ratio,
                "debugger_references": [
                    item
                    for item in matched_references
                    if "debug" in item["value"].lower()
                ],
                "root_or_hooking_references": _bounded_matches(
                    combined_references,
                    ("frida", "xposed", "substrate", "rootbeer", "magisk"),
                ),
                "interpretation": "Static resilience inventory; not evidence of malicious behavior.",
            },
        }
        payloads = [
            NormalizedArtifactPayload(
                artifact_type=artifact_type,
                source=self.name,
                normalized_data=_envelope(
                    analyzer_name=self.name,
                    analyzer_version=self.version,
                    source=_artifact_source(artifact_type),
                    data=data,
                    warnings=warnings if artifact_type in {
                        NormalizedArtifact.ArtifactType.DEX_METADATA,
                        NormalizedArtifact.ArtifactType.NETWORK_SECURITY_CONFIG,
                        NormalizedArtifact.ArtifactType.SIGNING,
                    } else [],
                ),
                source_locators=_source_locators_for_artifact(
                    artifact_type,
                    data,
                ),
            )
            for artifact_type, data in artifact_data.items()
        ]
        summary = {
            "real_apk_parsing": True,
            "entry_count": archive_summary.entry_count,
            "dex_count": len(archive_summary.dex_entries),
            "class_count": len(class_names),
            "method_reference_count": len(method_references),
            "secret_match_count": len(secrets),
            "url_count": len(urls),
            "native_library_count": len(archive_summary.native_entries),
            "probable_dependency_count": len(sdk_inventory),
            "artifact_count": len(payloads),
            "warning_count": len(warnings),
            "external_tools_executed": [],
            "apk_code_executed": False,
            "network_access_performed": False,
        }
        return payloads, summary

    def _open_local_copy(self, apk_file):
        method = getattr(self.file_provider, "open_apk_local_copy", None)
        if callable(method):
            return method(apk_file)
        local_path = self.file_provider.get_local_path_for_apk(apk_file)
        if local_path is None:
            raise APKFileUnavailableError("No local APK path is available.")
        return nullcontext(local_path)

    def _result(self, status: str, error_message: str) -> AnalyzerResult:
        return AnalyzerResult(
            analyzer_name=self.name,
            analyzer_version=self.version,
            status=status,
            raw_summary={
                "real_apk_parsing": False,
                "artifact_count": 0,
                "external_tools_executed": [],
                "apk_code_executed": False,
                "network_access_performed": False,
            },
            error_message=error_message,
        )


def _envelope(
    *,
    analyzer_name: str,
    analyzer_version: str,
    source: str,
    data: dict,
    warnings: list[str],
) -> dict:
    return {
        "schema_version": "2.0",
        "analyzer_name": analyzer_name,
        "analyzer_version": analyzer_version,
        "source": source,
        "extraction_status": "COMPLETED",
        "warnings": list(warnings),
        "data": data,
    }


def _artifact_source(artifact_type: str) -> str:
    return {
        "PACKAGE_CONTENT": "APK ZIP central directory",
        "DEX_METADATA": "classes*.dex",
        "CODE_REFERENCES": "DEX method and string references",
        "STRINGS": "DEX string table",
        "SECRETS": "DEX normalized strings",
        "CRYPTO_USAGE": "DEX method and string references",
        "WEBVIEW_USAGE": "DEX method and string references",
        "NATIVE_LIBRARIES": "APK lib/ entries",
        "THIRD_PARTY_SDKS": "DEX class namespaces",
        "URLS_AND_ENDPOINTS": "DEX normalized strings",
        "NETWORK_SECURITY_CONFIG": "APK res/xml resources",
        "SIGNING": "APK signing blocks",
        "CERTIFICATE": "APK signer certificates",
        "RESILIENCE_SIGNALS": "DEX class and method metadata",
        "RESOURCES": "Decoded APK resource XML",
    }.get(artifact_type, "APK")


def _matched_references(values: list[str]) -> list[dict]:
    matches = []
    for category, needles in REFERENCE_PATTERNS.items():
        for value in values:
            matched_needles = [
                needle for needle in needles if needle.lower() in value.lower()
            ]
            if matched_needles:
                matches.append(
                    {
                        "category": category,
                        "value": _bounded(value, 220),
                        "locator_terms": _source_search_terms(matched_needles),
                    }
                )
                if len(matches) >= settings.MSAP_MAX_NORMALIZED_MATCHES:
                    return matches
    return matches


def _pattern_matches(values: list[str], patterns: dict[str, tuple[str, ...]]) -> list[dict]:
    matches = []
    for category, needles in patterns.items():
        found = next(
            (
                (value, needle)
                for value in values
                for needle in needles
                if needle.lower() in value.lower()
            ),
            None,
        )
        if found:
            value, needle = found
            matches.append(
                {
                    "type": category,
                    "reference": _bounded(value, 220),
                    "locator_terms": _source_search_terms([needle]),
                    "confidence": "MEDIUM",
                    "requires_manual_validation": True,
                }
            )
    return matches


def _source_search_terms(values: list[str]) -> list[str]:
    terms: list[str] = []
    for value in values:
        candidates = []
        if ";->" in value:
            candidates.append(value.split(";->", 1)[1])
        if "/" in value:
            candidates.append(value.rsplit("/", 1)[-1].split(";", 1)[0])
        candidates.append(value)
        for candidate in candidates:
            clean = candidate.strip('L;"')
            if clean and clean not in terms:
                terms.append(clean)
    return terms[:4]


def _source_locators_for_artifact(
    artifact_type: str,
    data: dict,
) -> tuple[SourceLocatorHint, ...]:
    hints: list[SourceLocatorHint] = []

    def code_hint(semantic_key: str, match: dict, *, redacted: bool = False) -> None:
        hints.append(
            SourceLocatorHint(
                representation=SourceDocument.RepresentationType.JADX_SOURCE,
                semantic_key=semantic_key,
                search_terms=tuple(match.get("locator_terms") or ()),
                confidence=str(match.get("confidence") or "MEDIUM").upper(),
                locator={
                    "dex_fallback": True,
                    "redact_excerpt": redacted,
                    **(
                        {
                            "secret_fingerprint_sha256": match.get(
                                "fingerprint_sha256"
                            ),
                            "source_value_fingerprint_sha256": match.get(
                                "source_value_fingerprint_sha256"
                            ),
                        }
                        if redacted
                        else {}
                    ),
                },
            )
        )

    if artifact_type == NormalizedArtifact.ArtifactType.SECRETS:
        for match in data.get("matches", []):
            code_hint(f"secret:{match.get('type')}", match, redacted=True)
    elif artifact_type == NormalizedArtifact.ArtifactType.CRYPTO_USAGE:
        for match in data.get("matches", []):
            code_hint(f"crypto:{match.get('type')}", match)
    elif artifact_type == NormalizedArtifact.ArtifactType.WEBVIEW_USAGE:
        for match in data.get("matches", []):
            code_hint(f"webview:{match.get('type')}", match)
    elif artifact_type == NormalizedArtifact.ArtifactType.CODE_REFERENCES:
        for match in data.get("matches", []):
            if match.get("category") == "logging":
                code_hint("logging_reference_review", match)
    elif artifact_type == NormalizedArtifact.ArtifactType.NETWORK_SECURITY_CONFIG:
        resource = str(data.get("resource") or "")
        path = f"resources/{resource}" if resource else "resources/res/xml"
        network_terms = {
            "network_user_ca": ("certificates", 'src="user"'),
            "network_debug_overrides": ("<debug-overrides",),
            "expired_pin_set": ("<pin-set", "expiration"),
            "network_domain_cleartext": (
                "<domain-config",
                "cleartextTrafficPermitted",
            ),
            "missing_pinning_review": ("<network-security-config",),
        }
        for semantic_key, terms in network_terms.items():
            hints.append(
                SourceLocatorHint(
                    representation=(
                        SourceDocument.RepresentationType.NETWORK_SECURITY_XML
                    ),
                    semantic_key=semantic_key,
                    logical_path=path,
                    search_terms=terms,
                    confidence="HIGH",
                    locator={"match_all": True},
                )
            )
    elif artifact_type == NormalizedArtifact.ArtifactType.RESOURCES:
        for match in data.get("file_provider_paths", []):
            if not match.get("oversharing"):
                continue
            tag = str(match.get("tag") or "path")
            terms = [f"<{tag}"]
            path_value = str(match.get("path") or "")
            if path_value:
                terms.append(f'path="{path_value}"')
            hints.append(
                SourceLocatorHint(
                    representation=SourceDocument.RepresentationType.RESOURCE_XML,
                    semantic_key="broad_file_provider_path",
                    logical_path=f"resources/{match.get('resource')}",
                    search_terms=tuple(terms),
                    confidence="HIGH",
                    locator={
                        "match_all": True,
                        "provider": match.get("provider"),
                        "oversharing_path_kind": tag,
                    },
                )
            )
    elif artifact_type == NormalizedArtifact.ArtifactType.NATIVE_LIBRARIES:
        for library in data.get("libraries", [])[:20]:
            hints.append(
                SourceLocatorHint(
                    representation=SourceDocument.RepresentationType.NATIVE_SYMBOL,
                    semantic_key="native_hardening_review",
                    logical_path=str(library.get("path") or "native/library.so"),
                    confidence="HIGH",
                    locator={
                        "source_lines_available": False,
                        "reason": (
                            "Finding originates from native binary inventory and "
                            "hardening metadata."
                        ),
                    },
                )
            )
    elif artifact_type == NormalizedArtifact.ArtifactType.SIGNING:
        hints.append(
            SourceLocatorHint(
                representation=SourceDocument.RepresentationType.APK_SIGNING_METADATA,
                semantic_key="apk_signing_metadata",
                logical_path="APK-SIGNING-METADATA",
                confidence="HIGH",
                locator={
                    "source_lines_available": False,
                    "reason": "Finding originates from APK signing block metadata.",
                },
            )
        )
    elif artifact_type == NormalizedArtifact.ArtifactType.CERTIFICATE:
        hints.append(
            SourceLocatorHint(
                representation=SourceDocument.RepresentationType.CERTIFICATE_METADATA,
                semantic_key="certificate_metadata",
                logical_path="APK-SIGNER-CERTIFICATE",
                confidence="HIGH",
                locator={
                    "source_lines_available": False,
                    "reason": "Finding originates from APK signer certificate metadata.",
                },
            )
        )
    return tuple(hints)


def _urls(strings: list[str]) -> list[dict]:
    results = {}
    for value in strings:
        for match in URL_PATTERN.findall(value):
            sanitized = _sanitize_url(match)
            if sanitized:
                results[sanitized] = {
                    "url": sanitized,
                    "scheme": urlsplit(sanitized).scheme.lower(),
                    "cleartext": urlsplit(sanitized).scheme.lower() in {"http", "ftp"},
                    "embedded_credentials": bool(BASIC_AUTH_URL_PATTERN.search(match)),
                }
            if len(results) >= settings.MSAP_MAX_NORMALIZED_MATCHES:
                break
    return list(results.values())


def _sanitize_url(value: str) -> str | None:
    try:
        parts = urlsplit(value.rstrip(".,);]"))
        if not parts.hostname:
            return None
        port = f":{parts.port}" if parts.port else ""
        host = parts.hostname[:255]
        return _bounded(
            urlunsplit((parts.scheme.lower(), f"{host}{port}", parts.path[:300], "", "")),
            500,
        )
    except (ValueError, UnicodeError):
        return None


def _secret_matches(strings: list[str]) -> list[dict]:
    matches = []
    for value in strings:
        match_type = None
        candidate = value
        if PRIVATE_KEY_PATTERN.search(value):
            match_type = "PRIVATE_KEY_BLOCK"
        elif AWS_KEY_PATTERN.search(value):
            match_type = "CLOUD_ACCESS_KEY"
        elif BEARER_PATTERN.search(value):
            match_type = "BEARER_TOKEN"
        elif BASIC_AUTH_URL_PATTERN.search(value):
            match_type = "EMBEDDED_BASIC_AUTH_URL"
        elif password_match := PASSWORD_PATTERN.search(value):
            candidate = password_match.group(1)
            if candidate.lower() in SECRET_TEST_VALUES:
                continue
            match_type = "CONTEXTUAL_SECRET_ASSIGNMENT"
        elif _high_entropy_candidate(value):
            match_type = "HIGH_ENTROPY_CONSTANT"
        if not match_type:
            continue
        digest = sha256(candidate.encode("utf-8", errors="ignore")).hexdigest()
        matches.append(
            {
                "type": match_type,
                "fingerprint_sha256": digest,
                "source_value_fingerprint_sha256": sha256(
                    value.encode("utf-8", errors="ignore")
                ).hexdigest(),
                "length": len(candidate),
                "redacted": True,
                "confidence": (
                    "LOW" if match_type == "HIGH_ENTROPY_CONSTANT" else "MEDIUM"
                ),
                "requires_manual_validation": True,
            }
        )
        if len(matches) >= settings.MSAP_MAX_NORMALIZED_MATCHES:
            break
    return matches


def _high_entropy_candidate(value: str) -> bool:
    if not 24 <= len(value) <= 128 or any(char.isspace() for char in value):
        return False
    if value.lower() in SECRET_TEST_VALUES or value.startswith(("http", "Landroid/")):
        return False
    counts = Counter(value)
    entropy = -sum(
        (count / len(value)) * log2(count / len(value))
        for count in counts.values()
    )
    return entropy >= 4.3 and any(char.isdigit() for char in value)


def _native_inventory(entries: tuple[str, ...]) -> dict:
    libraries = []
    for entry in entries:
        parts = entry.split("/")
        libraries.append(
            {
                "path": _bounded(entry, 300),
                "architecture": parts[1] if len(parts) > 2 else "unknown",
                "name": parts[-1],
                "hardening": {
                    "status": "NOT_EVALUATED",
                    "reason": "LIEF capability is not installed.",
                },
            }
        )
    names = Counter(item["name"] for item in libraries)
    return {
        "libraries": libraries[: settings.MSAP_MAX_NORMALIZED_MATCHES],
        "architectures": sorted({item["architecture"] for item in libraries}),
        "duplicate_names": sorted(name for name, count in names.items() if count > 1),
        "lief_available": False,
    }


def _sdk_inventory(class_names: list[str]) -> list[dict]:
    path = Path(settings.ANALYZER_RULES_PATH) / "third_party_sdks.yaml"
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return []
    inventory = []
    for item in document.get("sdks", []):
        prefixes = item.get("prefixes", [])
        count = sum(
            1
            for class_name in class_names
            if any(prefix in class_name for prefix in prefixes)
        )
        if count:
            inventory.append(
                {
                    "name": item.get("name"),
                    "category": item.get("category"),
                    "matched_class_count": count,
                    "version": None,
                    "confidence": "MEDIUM",
                }
            )
    return inventory


def _network_security_config(archive: ZipFile, warnings: list[str]) -> dict:
    candidates = [
        item
        for item in archive.infolist()
        if item.filename.startswith("res/xml/")
        and "network_security" in item.filename.lower()
        and item.file_size <= 1024 * 1024
    ]
    if not candidates:
        return {
            "status": "NOT_FOUND",
            "cleartext_traffic_permitted": None,
            "domains": [],
            "trust_anchors": [],
            "debug_overrides": False,
            "pin_sets": [],
        }
    raw = archive.read(candidates[0])
    try:
        if raw.lstrip().startswith(b"<"):
            if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
                raise ElementTree.ParseError("Prohibited XML declaration")
            root = ElementTree.fromstring(raw)
            decoded_by = "plain APK resource XML"
        else:
            from androguard.core.axml import AXMLPrinter

            printer = AXMLPrinter(raw)
            if not printer.is_valid():
                raise ElementTree.ParseError("Invalid Android binary XML")
            root = printer.get_xml_obj()
            if root is None:
                raise ElementTree.ParseError("Android binary XML has no root")
            decoded_by = "Androguard binary XML decoder"
    except Exception:
        warnings.append("Network security configuration XML is malformed.")
        return {
            "status": "MALFORMED",
            "resource": candidates[0].filename,
            "decoded_by": "unavailable",
        }

    domains = []
    trust_anchors = []
    pin_sets = []
    for element in root.iter():
        tag = element.tag.rsplit("}", 1)[-1]
        if tag == "certificates":
            trust_anchors.append({"src": element.get("src"), "override_pins": element.get("overridePins") == "true"})
        elif tag == "pin-set":
            pins = [
                {"algorithm": pin.get("digest"), "value_persisted": False}
                for pin in element
                if pin.tag.rsplit("}", 1)[-1] == "pin"
            ]
            pin_sets.append({"expiration": element.get("expiration"), "pins": pins})
    for domain_config in (
        item for item in root.iter() if item.tag.rsplit("}", 1)[-1] == "domain-config"
    ):
        cleartext_value = domain_config.get("cleartextTrafficPermitted")
        for element in domain_config:
            if element.tag.rsplit("}", 1)[-1] != "domain":
                continue
            domains.append(
                {
                    "domain": _bounded((element.text or "").strip(), 255),
                    "include_subdomains": element.get("includeSubdomains") == "true",
                    "cleartext_traffic_permitted": (
                        cleartext_value == "true" if cleartext_value is not None else None
                    ),
                }
            )
    base = next(
        (item for item in root if item.tag.rsplit("}", 1)[-1] == "base-config"),
        None,
    )
    return {
        "status": "PARSED",
        "resource": candidates[0].filename,
        "decoded_by": decoded_by,
        "cleartext_traffic_permitted": (
            base.get("cleartextTrafficPermitted") == "true" if base is not None and base.get("cleartextTrafficPermitted") is not None else None
        ),
        "domains": domains,
        "trust_anchors": trust_anchors,
        "system_ca_trust": any(item.get("src") == "system" for item in trust_anchors),
        "user_ca_trust": any(item.get("src") == "user" for item in trust_anchors),
        "custom_ca_resources": sorted(
            item["src"] for item in trust_anchors if item.get("src", "").startswith("@")
        ),
        "debug_overrides": any(
            item.tag.rsplit("}", 1)[-1] == "debug-overrides" for item in root
        ),
        "pin_sets": pin_sets,
    }


def _file_provider_paths(
    apk_path: Path,
    archive: ZipFile,
    warnings: list[str],
) -> list[dict]:
    try:
        manifest = ManifestMetadataAdapter().parse(apk_path)
    except ManifestParsingError:
        warnings.append("FileProvider configuration could not be linked to the manifest.")
        return []

    providers = [
        item
        for item in manifest.components
        if item.get("type") == "provider"
        and str(item.get("name") or "").endswith("FileProvider")
    ]
    if not providers:
        return []

    archive_names = {item.filename for item in archive.infolist()}
    results: list[dict] = []
    for provider in providers:
        resource_names: list[str] = []
        for metadata in provider.get("metadata", []):
            if metadata.get("name") not in {
                "android.support.FILE_PROVIDER_PATHS",
                "androidx.core.FILE_PROVIDER_PATHS",
            }:
                continue
            resource = str(metadata.get("resource") or "")
            if resource.startswith("@xml/"):
                resource_names.append(f"res/xml/{resource.removeprefix('@xml/')}.xml")
        if not resource_names:
            resource_names = [
                name
                for name in sorted(archive_names)
                if name.startswith("res/xml/") and name.endswith(".xml")
            ]

        for resource_name in resource_names:
            if resource_name not in archive_names:
                continue
            try:
                raw = archive.read(resource_name)
                if raw.lstrip().startswith(b"<"):
                    if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
                        continue
                    root = ElementTree.fromstring(raw)
                else:
                    from androguard.core.axml import AXMLPrinter

                    printer = AXMLPrinter(raw)
                    if not printer.is_valid():
                        continue
                    root = printer.get_xml_obj()
                if root is None or root.tag.rsplit("}", 1)[-1] != "paths":
                    continue
            except Exception:
                warnings.append(f"{resource_name}: FileProvider path XML could not be decoded")
                continue

            for element in root:
                tag = element.tag.rsplit("}", 1)[-1]
                path_value = str(element.get("path") or "")
                oversharing = tag == "root-path" or path_value.strip() in {"", ".", "/"}
                results.append(
                    {
                        "provider": provider.get("name"),
                        "provider_exported": provider.get("exported"),
                        "provider_permission": provider.get("permission"),
                        "grant_uri_permissions": provider.get("grant_uri_permissions"),
                        "resource": resource_name,
                        "tag": tag,
                        "name": str(element.get("name") or "")[:128],
                        "path": path_value[:512],
                        "oversharing": oversharing,
                    }
                )
    deduplicated = {
        (
            item["provider"],
            item["resource"],
            item["tag"],
            item["name"],
            item["path"],
        ): item
        for item in results
    }
    return list(deduplicated.values())[: settings.MSAP_MAX_NORMALIZED_MATCHES]


def _signing_metadata(path: Path, warnings: list[str]) -> tuple[dict, list[dict]]:
    try:
        apk = APK(str(path), skip_analysis=True)
        signed = apk.is_signed()
        schemes = {
            "v1": apk.is_signed_v1(),
            "v2": apk.is_signed_v2(),
            "v3": apk.is_signed_v3(),
        }
        certificates = []
        for cert in apk.get_certificates():
            valid_from = _certificate_date(cert, "not_valid_before")
            valid_until = _certificate_date(cert, "not_valid_after")
            now = datetime.now(timezone.utc)
            certificates.append(
                {
                    "subject": _certificate_name(cert, "subject"),
                    "issuer": _certificate_name(cert, "issuer"),
                    "serial": str(getattr(cert, "serial_number", "")),
                    "valid_from": valid_from.isoformat() if valid_from else None,
                    "valid_until": valid_until.isoformat() if valid_until else None,
                    "not_yet_valid": bool(valid_from and valid_from > now),
                    "expired": bool(valid_until and valid_until < now),
                    "signature_algorithm": str(getattr(cert, "signature_algo", "")),
                    "hash_algorithm": str(getattr(cert, "hash_algo", "")),
                    "sha256": getattr(cert, "sha256", b"").hex(),
                    "debug_certificate_indicator": "android debug" in _certificate_name(cert, "subject").lower(),
                }
            )
        return {
            "signed": signed,
            "schemes": schemes,
            "signer_count": len(certificates),
            "legacy_only": bool(schemes["v1"] and not schemes["v2"] and not schemes["v3"]),
            "malformed": False,
        }, certificates
    except Exception:
        warnings.append("APK signing metadata could not be parsed.")
        return {
            "signed": False,
            "schemes": {"v1": False, "v2": False, "v3": False},
            "signer_count": 0,
            "legacy_only": False,
            "malformed": True,
        }, []


def _certificate_date(cert, attribute: str):
    value = getattr(cert, attribute, None)
    native = getattr(value, "native", value)
    if isinstance(native, datetime):
        return native if native.tzinfo else native.replace(tzinfo=timezone.utc)
    return None


def _certificate_name(cert, attribute: str) -> str:
    value = getattr(cert, attribute, None)
    return _bounded(str(getattr(value, "human_friendly", value) or ""), 500)


def _package_namespaces(class_names: list[str]) -> list[dict]:
    counts = Counter()
    for class_name in class_names:
        clean = class_name.strip("L;")
        parts = clean.split("/")
        if len(parts) >= 2:
            counts[".".join(parts[: min(3, len(parts) - 1)])] += 1
    return [
        {"namespace": name, "class_count": count}
        for name, count in counts.most_common(100)
    ]


def _relevant_string_fingerprints(
    strings: list[str],
    references: list[dict],
    urls: list[dict],
) -> list[dict]:
    values = {item["value"] for item in references}
    values.update(item["url"] for item in urls)
    return [
        {
            "fingerprint_sha256": sha256(value.encode("utf-8", errors="ignore")).hexdigest(),
            "length": len(value),
            "category": "matched_reference",
        }
        for value in list(values)[: settings.MSAP_MAX_NORMALIZED_MATCHES]
    ]


def _bounded_matches(values: list[str], needles: tuple[str, ...]) -> list[str]:
    results = []
    for value in values:
        if any(needle in value.lower() for needle in needles):
            results.append(_bounded(value, 220))
            if len(results) >= 100:
                break
    return results


def _bounded(value: str, limit: int) -> str:
    return value if len(value) <= limit else f"{value[: limit - 3]}..."
