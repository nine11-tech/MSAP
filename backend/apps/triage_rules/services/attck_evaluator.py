from pathlib import Path
import re
from hashlib import sha256
from typing import Any

from django.conf import settings
from django.db import transaction

from apps.appsec_rules.models import RuleEvaluation
from apps.apk_files.models import APKFile
from apps.audits.models import Audit
from apps.evidence.models import Evidence, SourceDocument
from apps.evidence.services.source_content import (
    SourceDocumentContentError,
    SourceDocumentContentService,
    redact_source_line,
)
from apps.indicators.models import SuspiciousIndicator
from apps.normalization.models import NormalizedArtifact
from apps.triage_rules.services.triage_rule_loader import load_attck_triage_rules


EVALUATOR_VERSION = "2.1.0"
JADX_REPRESENTATIONS = {
    SourceDocument.RepresentationType.JADX_SOURCE,
    SourceDocument.RepresentationType.JADX_JAVA,
    SourceDocument.RepresentationType.JADX_KOTLIN,
}
METHOD_SIGNATURE = re.compile(
    r"(?:public|private|protected|internal|static|final|synchronized|native|"
    r"abstract|override|open|suspend|fun|\s)+[\w<>, ?\[\].:@]+\s+(\w+)\s*\("
)


@transaction.atomic
def evaluate_attck_indicators(
    audit: Audit | int,
    rules_path: str | Path | None = None,
    *,
    content_service: SourceDocumentContentService | None = None,
) -> dict[str, int]:
    audit_id = audit.pk if isinstance(audit, Audit) else audit
    rules = load_attck_triage_rules(
        rules_path
        or Path(settings.ANALYZER_RULES_PATH) / "attck_mobile_triage_rules.yaml"
    )
    artifacts = _artifact_map(audit_id)
    source_resolver = _IndicatorSourceResolver(
        audit_id,
        artifacts,
        content_service=content_service,
    )
    summary = {
        "catalog_indicators": len(rules),
        "evaluated_indicators": 0,
        "matched_indicators": 0,
        "not_evaluated": 0,
        "indicators_created": 0,
        "indicators_existing": 0,
        "evidence_created": 0,
    }

    for rule in rules:
        missing = [name for name in rule["prerequisites"] if name not in artifacts]
        if missing:
            result = RuleEvaluation.Result.NOT_EVALUATED
            snippet = f"Prerequisite artifact unavailable: {', '.join(missing)}"
            matched = False
            summary["not_evaluated"] += 1
        else:
            matched, snippet = _match(rule, artifacts)
            result = (
                RuleEvaluation.Result.REVIEW_REQUIRED
                if matched
                else RuleEvaluation.Result.NOT_APPLICABLE
            )
            summary["evaluated_indicators"] += 1
            summary["matched_indicators"] += int(matched)

        mappings = {
            "technique_id": rule["technique_id"],
            "technique_name": rule["technique_name"],
            "tactic": rule["tactic"],
            "mapping_rationale": rule["mapping_rationale"],
            "auditor_explanation": rule["auditor_explanation"],
            "dynamic_verification_scenario": rule[
                "dynamic_verification_scenario"
            ],
            "non_malware_verdict_note": rule["non_malware_verdict_note"],
        }
        RuleEvaluation.objects.update_or_create(
            audit_id=audit_id,
            framework=RuleEvaluation.Framework.ATTACK_MOBILE,
            rule_id=rule["id"],
            defaults={
                "result": result,
                "severity": rule["severity"].upper(),
                "confidence": rule["confidence"].upper(),
                "title": rule["title"],
                "mapping_data": mappings,
                "evidence_summary": snippet,
                "remediation": "",
                "requires_manual_validation": True,
                "evaluator_version": EVALUATOR_VERSION,
            },
        )

        if not matched:
            SuspiciousIndicator.objects.filter(
                audit_id=audit_id, indicator_id=rule["id"]
            ).delete()
            continue

        indicator, created = SuspiciousIndicator.objects.update_or_create(
            audit_id=audit_id,
            indicator_id=rule["id"],
            defaults={
                "title": rule["title"],
                "tactic": rule["tactic"],
                "technique_id": rule["technique_id"],
                "technique_name": rule["technique_name"],
                "severity": rule["severity"],
                "confidence": rule["confidence"],
                "triage_interpretation": rule["triage_interpretation"],
                "auditor_explanation": rule["auditor_explanation"],
                "dynamic_verification_scenario": rule[
                    "dynamic_verification_scenario"
                ],
                "source_evidence": source_resolver.resolve(rule),
                "mapping_rationale": rule["mapping_rationale"],
                "false_positive_considerations": rule[
                    "false_positive_considerations"
                ],
                "requires_manual_validation": True,
                "non_malware_verdict_note": rule["non_malware_verdict_note"],
            },
        )
        summary["indicators_created" if created else "indicators_existing"] += 1
        _, evidence_created = Evidence.objects.get_or_create(
            audit_id=audit_id,
            finding=None,
            indicator=indicator,
            evidence_type=rule["detection_type"],
            source=rule["source"],
            snippet=snippet[:500],
            redacted=False,
        )
        summary["evidence_created"] += int(evidence_created)

    return summary


def _artifact_map(audit_id: int) -> dict[str, dict]:
    artifacts: dict[str, dict] = {}
    for artifact in NormalizedArtifact.objects.filter(audit_id=audit_id).order_by(
        "created_at", "id"
    ):
        value = artifact.normalized_data if isinstance(artifact.normalized_data, dict) else {}
        data = value.get("data") if isinstance(value.get("data"), dict) else value
        if value.get("extraction_status") in {"FAILED", "NOT_STARTED"}:
            continue
        artifacts[artifact.artifact_type] = data
    return artifacts


def _match(rule: dict[str, Any], artifacts: dict[str, dict]) -> tuple[bool, str]:
    manifest = artifacts.get("MANIFEST", {})
    permissions = {
        item.get("name") if isinstance(item, dict) else item
        for item in manifest.get("permissions", [])
    }
    components = [
        item for item in manifest.get("components", []) if isinstance(item, dict)
    ]
    values = set(rule.get("values", []))
    condition = rule["condition"]

    if condition == "permission_any":
        matches = sorted(permissions & values)
        return bool(matches), f"declared permission capability: {', '.join(matches)}"
    if condition in {"accessibility_service", "device_admin", "vpn_service"}:
        condition_keywords = {
            "accessibility_service": ("accessibility",),
            "device_admin": ("device_admin", "deviceadmin"),
            "vpn_service": ("vpnservice", "bind_vpn_service"),
        }[condition]
        matches = []
        for component in components:
            serialized = " ".join(
                str(component.get(field, ""))
                for field in ("name", "permission", "metadata", "intent_filters")
            )
            if any(value.lower() in serialized.lower() for value in values) or any(
                keyword in serialized.lower() for keyword in condition_keywords
            ):
                matches.append(component.get("name", "unnamed component"))
        return bool(matches), f"matched component capability declarations: {len(matches)}"
    if condition == "code_reference_category":
        matches = [
            item
            for item in artifacts.get("CODE_REFERENCES", {}).get("matches", [])
            if item.get("category") in values
        ]
        return bool(matches), _reference_summary(matches, "code")
    if condition == "native_libraries":
        libraries = artifacts.get("NATIVE_LIBRARIES", {}).get("libraries", [])
        return bool(libraries), f"native library inventory count: {len(libraries)}"
    if condition == "any_crypto_reference":
        matches = artifacts.get("CRYPTO_USAGE", {}).get("matches", [])
        return bool(matches), _reference_summary(matches, "cryptographic")
    return False, f"condition '{condition}' produced no triage match"


def _reference_summary(matches: list[dict], label: str) -> str:
    categories = sorted(
        {
            str(item.get("category") or item.get("type"))
            for item in matches
            if item.get("category") or item.get("type")
        }
    )
    return f"{label} reference categories: {', '.join(categories[:12])}"


class _IndicatorSourceResolver:
    """Resolve ATT&CK capability signals to bounded generated-source lines."""

    def __init__(
        self,
        audit_id: int,
        artifacts: dict[str, dict],
        *,
        content_service: SourceDocumentContentService | None = None,
    ):
        self.audit_id = audit_id
        self.artifacts = artifacts
        self.content_service = content_service or SourceDocumentContentService()
        self.content_cache: dict[int, list[str]] = {}
        self.apk_file = (
            APKFile.objects.filter(audit_id=audit_id)
            .order_by("-created_at", "-id")
            .first()
        )
        documents = SourceDocument.objects.filter(audit_id=audit_id)
        if self.apk_file is not None:
            documents = documents.filter(apk_file=self.apk_file)
        self.documents = list(documents.order_by("logical_path", "id"))

    def resolve(self, rule: dict[str, Any]) -> list[dict]:
        condition = rule["condition"]
        if condition == "native_libraries":
            libraries = self.artifacts.get("NATIVE_LIBRARIES", {}).get(
                "libraries", []
            )
            path = (
                str(libraries[0].get("path") or "native/library.so")
                if libraries
                else "native/library.so"
            )
            return [
                self._unavailable(
                    SourceDocument.RepresentationType.NATIVE_SYMBOL,
                    path,
                    "Source lines are not applicable; this signal originates "
                    "from the native library inventory.",
                )
            ]

        terms, representations = self._search_plan(rule)
        candidates: list[tuple[SourceDocument, int, str]] = []
        seen: set[tuple[int, int]] = set()
        for document in self._candidate_documents(representations):
            lines = self._lines(document)
            for line_number, line in enumerate(lines, 1):
                if not any(term.lower() in line.lower() for term in terms):
                    continue
                identity = (document.id, line_number)
                if identity in seen:
                    continue
                seen.add(identity)
                candidates.append((document, line_number, line))

        if candidates:
            ambiguous = len(candidates) > 1
            return [
                self._line_evidence(
                    document,
                    line_number,
                    line,
                    ambiguous=ambiguous,
                    is_primary=index == 0,
                    candidate_count=len(candidates),
                )
                for index, (document, line_number, line) in enumerate(candidates[:3])
            ]

        if representations == {SourceDocument.RepresentationType.MANIFEST_XML}:
            return [
                self._unavailable(
                    SourceDocument.RepresentationType.MANIFEST_XML,
                    "AndroidManifest.xml",
                    "The parsed manifest supports this signal, but an exact "
                    "decoded manifest line could not be resolved.",
                )
            ]
        return [
            self._unavailable(
                SourceDocument.RepresentationType.DEX_METADATA,
                "DEX-METADATA",
                "The DEX reference supports this signal, but no exact JADX "
                "source line could be resolved.",
            )
        ]

    def _search_plan(self, rule: dict[str, Any]) -> tuple[list[str], set[str]]:
        condition = rule["condition"]
        values = {str(value) for value in rule.get("values", [])}
        if condition == "permission_any":
            permissions = {
                item.get("name") if isinstance(item, dict) else item
                for item in self.artifacts.get("MANIFEST", {}).get("permissions", [])
            }
            return sorted(str(item) for item in permissions & values), {
                SourceDocument.RepresentationType.MANIFEST_XML
            }
        if condition in {"accessibility_service", "device_admin", "vpn_service"}:
            components = _matching_components(rule, self.artifacts.get("MANIFEST", {}))
            terms = [str(item.get("name") or "") for item in components]
            terms.extend(values)
            return [term for term in terms if term], {
                SourceDocument.RepresentationType.MANIFEST_XML
            }
        if condition == "code_reference_category":
            matches = [
                item
                for item in self.artifacts.get("CODE_REFERENCES", {}).get("matches", [])
                if item.get("category") in values
            ]
            return _locator_terms(matches), JADX_REPRESENTATIONS
        if condition == "any_crypto_reference":
            matches = self.artifacts.get("CRYPTO_USAGE", {}).get("matches", [])
            return _locator_terms(matches), JADX_REPRESENTATIONS
        return [], JADX_REPRESENTATIONS

    def _candidate_documents(self, representations: set[str]) -> list[SourceDocument]:
        candidates = [
            document
            for document in self.documents
            if document.representation_type in representations
        ]
        package_name = str(self.apk_file.package_name or "") if self.apk_file else ""
        return sorted(
            candidates,
            key=lambda document: (
                not _is_first_party_document(document, package_name),
                document.logical_path,
                document.id,
            ),
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

    def _line_evidence(
        self,
        document: SourceDocument,
        line_number: int,
        line: str,
        *,
        ambiguous: bool,
        is_primary: bool,
        candidate_count: int,
    ) -> dict:
        excerpt = redact_source_line(line)[:1000]
        return {
            "source_document": document.id,
            "representation": document.representation_type,
            "representation_label": document.get_representation_type_display(),
            "path": document.logical_path,
            "class_name": document.class_name,
            "method_name": _method_name(self._lines(document), line_number),
            "start_line": line_number,
            "end_line": line_number,
            "excerpt": excerpt,
            "excerpt_sha256": sha256(excerpt.encode("utf-8")).hexdigest(),
            "source_document_sha256": document.sha256,
            "confidence": "LOW" if ambiguous else "HIGH",
            "is_primary": is_primary,
            "source_lines_available": True,
            "provenance": str(
                document.metadata.get("provenance_note")
                or "Line numbers refer to the MSAP-generated decompiled or decoded representation."
            ),
            "candidate_count": candidate_count,
            "manual_validation_required": ambiguous,
        }

    @staticmethod
    def _unavailable(representation: str, path: str, reason: str) -> dict:
        return {
            "source_document": None,
            "representation": representation,
            "representation_label": SourceDocument.RepresentationType(
                representation
            ).label,
            "path": path,
            "class_name": "",
            "method_name": "",
            "start_line": None,
            "end_line": None,
            "excerpt": "",
            "confidence": "MEDIUM",
            "is_primary": True,
            "source_lines_available": False,
            "provenance": "Bounded static APK evidence produced during this assessment.",
            "reason": reason,
        }


def _matching_components(rule: dict[str, Any], manifest: dict) -> list[dict]:
    condition_keywords = {
        "accessibility_service": ("accessibility",),
        "device_admin": ("device_admin", "deviceadmin"),
        "vpn_service": ("vpnservice", "bind_vpn_service"),
    }[rule["condition"]]
    values = {str(value).lower() for value in rule.get("values", [])}
    matches = []
    for component in manifest.get("components", []):
        if not isinstance(component, dict):
            continue
        serialized = " ".join(
            str(component.get(field, ""))
            for field in ("name", "permission", "metadata", "intent_filters")
        ).lower()
        if any(value in serialized for value in values) or any(
            keyword in serialized for keyword in condition_keywords
        ):
            matches.append(component)
    return matches


def _locator_terms(matches: list[dict]) -> list[str]:
    terms = []
    for match in matches:
        for term in match.get("locator_terms", []):
            value = str(term).strip()
            if value and value not in terms:
                terms.append(value)
    return terms[:12]


def _is_first_party_document(document: SourceDocument, package_name: str) -> bool:
    if not package_name:
        return False
    return document.class_name == package_name or document.class_name.startswith(
        f"{package_name}."
    )


def _method_name(lines: list[str], anchor_line: int) -> str:
    for index in range(anchor_line - 1, max(-1, anchor_line - 41), -1):
        match = METHOD_SIGNATURE.search(lines[index])
        if match:
            return match.group(1)
    return ""
