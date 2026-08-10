from __future__ import annotations

import re
from collections import Counter
from hashlib import sha256
from math import log2
from pathlib import Path
from tempfile import TemporaryDirectory

from django.conf import settings

from apps.evidence.models import SourceDocument
from apps.storage.models import ObjectStorageReference
from apps.storage.services.minio_storage import MinIOStorageService


class SourceDocumentContentError(RuntimeError):
    pass


class SourceDocumentContentService:
    def __init__(self, storage_service: MinIOStorageService | None = None):
        self.storage_service = storage_service

    def read_text(self, document: SourceDocument) -> str:
        reference = document.storage_reference
        if reference is None or reference.audit_id != document.audit_id:
            raise SourceDocumentContentError(
                "Source document has no valid audit-scoped storage object."
            )
        if reference.object_type != ObjectStorageReference.ObjectType.SOURCE_DOCUMENT:
            raise SourceDocumentContentError("Storage object is not a source document.")
        if reference.storage_status not in {
            ObjectStorageReference.StorageStatus.UPLOADED,
            ObjectStorageReference.StorageStatus.VERIFIED,
        }:
            raise SourceDocumentContentError("Source document object is unavailable.")
        if (
            reference.size_bytes is not None
            and reference.size_bytes > settings.MSAP_SOURCE_INDEX_MAX_DOCUMENT_BYTES
        ):
            raise SourceDocumentContentError("Source document exceeds the read limit.")

        with TemporaryDirectory(
            prefix="msap-source-read-",
            dir=getattr(settings, "MSAP_TEMP_DIR", "") or None,
        ) as temporary_directory:
            path = Path(temporary_directory) / "document.txt"
            try:
                if self.storage_service is None:
                    self.storage_service = MinIOStorageService()
                self.storage_service.download_file(
                    reference.bucket,
                    reference.object_key,
                    path,
                )
                content = path.read_bytes()
            except Exception as exc:
                raise SourceDocumentContentError(
                    "Source document could not be read from object storage."
                ) from exc

        if len(content) > settings.MSAP_SOURCE_INDEX_MAX_DOCUMENT_BYTES:
            raise SourceDocumentContentError("Source document exceeds the read limit.")
        if sha256(content).hexdigest() != document.sha256:
            raise SourceDocumentContentError("Source document checksum verification failed.")
        try:
            return content.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SourceDocumentContentError("Source document is not valid UTF-8.") from exc

    def read_lines(
        self,
        document: SourceDocument,
        start_line: int,
        end_line: int,
    ) -> list[dict]:
        maximum = settings.MSAP_SOURCE_LINE_RANGE_LIMIT
        if start_line < 1 or end_line < start_line:
            raise ValueError("Invalid source line range.")
        if end_line - start_line + 1 > maximum:
            raise ValueError(f"A maximum of {maximum} source lines may be requested.")
        if end_line > document.line_count:
            raise ValueError("Requested line range exceeds the source document.")
        lines = self.read_text(document).splitlines()
        return [
            {"number": number, "text": redact_source_line(lines[number - 1])}
            for number in range(start_line, end_line + 1)
        ]


SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)(\b(?:password|passwd|pwd|api[_-]?key|secret|token|access[_-]?key)\b"
    r"[^\n=:{]{0,40}[:=]\s*)([\"']?)([^\s\"';,}]{6,})([\"']?)"
)
AWS_ACCESS_KEY = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
BEARER_TOKEN = re.compile(r"(?i)(\bbearer\s+)([a-z0-9._~+/=-]{12,})")
QUOTED_VALUE = re.compile(r"([\"'])([^\"'\n]{20,128})\1")
HARDCODED_KEY_ARGUMENT = re.compile(
    r"(?i)(\bnew\s+SecretKeySpec\s*\(\s*)([\"'])([^\"'\n]{4,256})(\2)"
)


def redact_source_line(line: str) -> str:
    if "PRIVATE KEY" in line.upper():
        return re.sub(
            r"(?i)(-----BEGIN )(.*?)(PRIVATE KEY-----)",
            r"\1[REDACTED] \3",
            line,
        )

    def assignment_replacement(match: re.Match) -> str:
        quote = match.group(2) or match.group(4)
        return f"{match.group(1)}{quote}{_masked(match.group(3))}{quote}"

    value = SENSITIVE_ASSIGNMENT.sub(assignment_replacement, line)
    value = AWS_ACCESS_KEY.sub(lambda match: _masked(match.group(0)), value)
    value = BEARER_TOKEN.sub(
        lambda match: f"{match.group(1)}{_masked(match.group(2))}",
        value,
    )
    value = HARDCODED_KEY_ARGUMENT.sub(
        lambda match: (
            f"{match.group(1)}{match.group(2)}"
            f"{_masked(match.group(3))}{match.group(4)}"
        ),
        value,
    )

    def quoted_replacement(match: re.Match) -> str:
        candidate = match.group(2)
        if _looks_high_entropy(candidate):
            return f"{match.group(1)}{_masked(candidate)}{match.group(1)}"
        return match.group(0)

    return QUOTED_VALUE.sub(quoted_replacement, value)


def _masked(value: str) -> str:
    if len(value) <= 8:
        return "****"
    return f"{value[:3]}****{value[-3:]}"


def _looks_high_entropy(value: str) -> bool:
    if (
        not 24 <= len(value) <= 128
        or any(char.isspace() for char in value)
        or value.startswith(("http", "Landroid/"))
    ):
        return False
    counts = Counter(value)
    entropy = -sum(
        (count / len(value)) * log2(count / len(value))
        for count in counts.values()
    )
    return entropy >= 4.3 and any(char.isdigit() for char in value)
