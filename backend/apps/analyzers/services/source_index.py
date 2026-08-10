from __future__ import annotations

import re
import subprocess
from contextlib import nullcontext
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory
from zipfile import ZipFile
from xml.etree import ElementTree

from django.conf import settings

from apps.analyzers.services.base import AnalyzerContext
from apps.analyzers.services.manifest_metadata_adapter import (
    ManifestMetadataAdapter,
    ManifestParsingError,
    render_decoded_xml,
)
from apps.analyzers.services.optional_tools import JADX_CAPABILITY
from apps.analyzers.services.safe_archive import validate_apk_archive
from apps.evidence.models import SourceDocument
from apps.storage.models import ObjectStorageReference
from apps.storage.services.file_provider import APKFileProvider, FileProvider
from apps.storage.services.minio_storage import MinIOStorageService


SOURCE_RENDERER_VERSION = "msap-xml-lines/1"
TEXT_SUFFIXES = {".java", ".kt", ".xml", ".smali"}


@dataclass
class SourceIndexResult:
    status: str
    documents_created: int = 0
    documents_reused: int = 0
    documents_skipped: int = 0
    total_bytes: int = 0
    jadx_status: str = "NOT_REQUESTED"
    warnings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "documents_created": self.documents_created,
            "documents_reused": self.documents_reused,
            "documents_skipped": self.documents_skipped,
            "total_bytes": self.total_bytes,
            "jadx_status": self.jadx_status,
            "warnings": list(self.warnings),
        }


class SourceIndexService:
    """Build bounded generated-source documents from validated APK bytes."""

    def __init__(
        self,
        *,
        file_provider: FileProvider | None = None,
        storage_service: MinIOStorageService | None = None,
        executable_resolver=None,
        command_runner=subprocess.run,
    ):
        self.file_provider = file_provider or APKFileProvider()
        self.storage_service = storage_service or MinIOStorageService()
        self.executable_resolver = executable_resolver or (
            lambda executable: JADX_CAPABILITY.executable_path()
        )
        self.command_runner = command_runner
        self.max_documents = settings.MSAP_SOURCE_INDEX_MAX_DOCUMENTS
        self.max_document_bytes = settings.MSAP_SOURCE_INDEX_MAX_DOCUMENT_BYTES
        self.max_total_bytes = settings.MSAP_SOURCE_INDEX_MAX_TOTAL_BYTES

    def index(self, context: AnalyzerContext) -> SourceIndexResult:
        if not settings.MSAP_SOURCE_INDEX_ENABLED:
            return SourceIndexResult(status="DISABLED")
        with self._open_local_copy(context.apk_file) as apk_path:
            return self.index_local_path(context, Path(apk_path))

    def index_local_path(
        self,
        context: AnalyzerContext,
        apk_path: Path,
    ) -> SourceIndexResult:
        validate_apk_archive(apk_path)
        SourceDocument.objects.filter(audit=context.audit).exclude(
            apk_file=context.apk_file
        ).delete()
        result = SourceIndexResult(status="COMPLETED")
        seen: set[tuple[str, str]] = set()

        with TemporaryDirectory(
            prefix="msap-source-index-",
            dir=getattr(settings, "MSAP_TEMP_DIR", "") or None,
        ) as temporary_directory:
            workdir = Path(temporary_directory)
            self._index_manifest(context, apk_path, workdir, result, seen)
            self._index_plain_resource_xml(
                context,
                apk_path,
                workdir,
                result,
                seen,
            )
            self._index_jadx(context, apk_path, workdir, result, seen)

        for document in SourceDocument.objects.filter(
            audit=context.audit,
            apk_file=context.apk_file,
        ):
            if (document.representation_type, document.logical_path) not in seen:
                document.delete()

        if result.documents_created + result.documents_reused == 0:
            result.status = "SOURCE_UNAVAILABLE"
        return result

    def _index_manifest(
        self,
        context: AnalyzerContext,
        apk_path: Path,
        workdir: Path,
        result: SourceIndexResult,
        seen: set[tuple[str, str]],
    ) -> None:
        try:
            content = ManifestMetadataAdapter().decode_xml(apk_path)
        except ManifestParsingError:
            result.warnings.append(
                "Decoded AndroidManifest.xml could not be indexed."
            )
            return
        self._persist_text(
            context=context,
            workdir=workdir,
            result=result,
            seen=seen,
            representation=SourceDocument.RepresentationType.MANIFEST_XML,
            logical_path="AndroidManifest.xml",
            display_path="Decoded AndroidManifest.xml",
            language="XML",
            content=content,
            generated_by="MSAP deterministic XML renderer (Androguard for binary XML)",
            tool_version=SOURCE_RENDERER_VERSION,
            metadata={
                "provenance_note": (
                    "Line numbers refer to the decoded AndroidManifest.xml "
                    "representation generated during this assessment."
                ),
            },
        )

    def _index_plain_resource_xml(
        self,
        context: AnalyzerContext,
        apk_path: Path,
        workdir: Path,
        result: SourceIndexResult,
        seen: set[tuple[str, str]],
    ) -> None:
        with ZipFile(apk_path) as archive:
            for item in archive.infolist():
                name = PurePosixPath(item.filename)
                if (
                    len(name.parts) < 3
                    or name.parts[0] != "res"
                    or name.suffix.lower() != ".xml"
                    or item.file_size <= 0
                    or item.file_size > self.max_document_bytes
                ):
                    continue
                try:
                    raw = archive.read(item)
                except (KeyError, OSError, RuntimeError):
                    result.documents_skipped += 1
                    continue
                try:
                    root, decoder = _decode_resource_xml(raw)
                    content = render_decoded_xml(root)
                except (ElementTree.ParseError, UnicodeError, ValueError, RuntimeError):
                    continue
                logical_path = f"resources/{name.as_posix()}"
                representation = self._resource_representation(logical_path)
                self._persist_text(
                    context=context,
                    workdir=workdir,
                    result=result,
                    seen=seen,
                    representation=representation,
                    logical_path=logical_path,
                    display_path=f"Decoded {name.as_posix()}",
                    language="XML",
                    content=content,
                    generated_by=decoder,
                    tool_version=SOURCE_RENDERER_VERSION,
                    metadata={
                        "apk_member": name.as_posix(),
                        "provenance_note": (
                            "Line numbers refer to decoded resource XML generated "
                            "during this assessment."
                        ),
                    },
                )

    def _index_jadx(
        self,
        context: AnalyzerContext,
        apk_path: Path,
        workdir: Path,
        result: SourceIndexResult,
        seen: set[tuple[str, str]],
    ) -> None:
        if not settings.MSAP_JADX_ENABLED:
            result.jadx_status = "DISABLED"
            return
        executable = self.executable_resolver("jadx")
        if not executable:
            result.jadx_status = "UNAVAILABLE"
            result.warnings.append(
                "JADX is unavailable; code findings will retain DEX metadata evidence."
            )
            return

        output_dir = workdir / "jadx"
        output_dir.mkdir(mode=0o700)
        command = [
            executable,
            "--no-debug-info",
            "--comments-level",
            "warn",
            "-d",
            str(output_dir),
            str(apk_path),
        ]
        try:
            completed = self.command_runner(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=settings.MSAP_SOURCE_INDEX_TIMEOUT_SECONDS,
                check=False,
            )
        except subprocess.TimeoutExpired:
            result.jadx_status = "TIMEOUT"
            result.warnings.append("JADX exceeded the configured execution timeout.")
            return
        except (OSError, subprocess.SubprocessError):
            result.jadx_status = "FAILED"
            result.warnings.append("JADX execution failed safely.")
            return

        if completed.returncode not in {0, 1}:
            result.jadx_status = "FAILED"
            result.warnings.append("JADX did not produce a usable source tree.")
            return

        tool_version = self._jadx_version(executable)
        result.jadx_status = "COMPLETED"
        for path in sorted(output_dir.rglob("*")):
            if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
                continue
            try:
                resolved = path.resolve()
                relative = resolved.relative_to(output_dir.resolve())
                size = resolved.stat().st_size
            except (OSError, RuntimeError, ValueError):
                result.documents_skipped += 1
                continue
            if size <= 0 or size > self.max_document_bytes:
                result.documents_skipped += 1
                continue
            logical_path = relative.as_posix()
            if logical_path == "resources/AndroidManifest.xml":
                continue
            try:
                content = resolved.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                result.documents_skipped += 1
                continue

            suffix = path.suffix.lower()
            if suffix in {".java", ".kt"}:
                representation = (
                    SourceDocument.RepresentationType.JADX_JAVA
                    if suffix == ".java"
                    else SourceDocument.RepresentationType.JADX_KOTLIN
                )
                language = "Java" if suffix == ".java" else "Kotlin"
                class_name, package_name = _source_identity(content, path.stem)
                display_path = logical_path
                provenance_note = (
                    "Line numbers refer to the JADX-decompiled representation "
                    "generated during this assessment and may differ from the "
                    "developer's original source tree."
                )
            elif suffix == ".smali":
                representation = SourceDocument.RepresentationType.SMALI
                language = "Smali"
                class_name, package_name = "", ""
                display_path = logical_path
                provenance_note = (
                    "Line numbers refer to the generated Smali representation "
                    "indexed during this assessment."
                )
            else:
                representation = self._resource_representation(logical_path)
                language = "XML"
                class_name, package_name = "", ""
                display_path = f"Decoded {logical_path.removeprefix('resources/')}"
                provenance_note = (
                    "Line numbers refer to decoded resource XML generated by "
                    "JADX during this assessment."
                )
                try:
                    content = render_decoded_xml(ElementTree.fromstring(content))
                except (ElementTree.ParseError, UnicodeError, ValueError):
                    pass

            self._persist_text(
                context=context,
                workdir=workdir,
                result=result,
                seen=seen,
                representation=representation,
                logical_path=logical_path,
                display_path=display_path,
                language=language,
                class_name=class_name,
                package_name=package_name,
                content=content,
                generated_by="JADX",
                tool_version=tool_version,
                metadata={
                    "jadx_exit_code": completed.returncode,
                    "generation_parameters": command[1:-2],
                    "provenance_note": provenance_note,
                },
            )

    def _persist_text(
        self,
        *,
        context: AnalyzerContext,
        workdir: Path,
        result: SourceIndexResult,
        seen: set[tuple[str, str]],
        representation: str,
        logical_path: str,
        display_path: str,
        language: str,
        content: str,
        generated_by: str,
        tool_version: str,
        class_name: str = "",
        package_name: str = "",
        metadata: dict | None = None,
    ) -> SourceDocument | None:
        safe_path = _safe_logical_path(logical_path)
        identity = (representation, safe_path)
        if identity in seen:
            return None
        encoded = content.encode("utf-8")
        if (
            not encoded
            or len(encoded) > self.max_document_bytes
            or result.total_bytes + len(encoded) > self.max_total_bytes
            or result.documents_created + result.documents_reused >= self.max_documents
        ):
            result.documents_skipped += 1
            return None
        seen.add(identity)

        digest = sha256(encoded).hexdigest()
        existing = SourceDocument.objects.filter(
            audit=context.audit,
            apk_file=context.apk_file,
            representation_type=representation,
            logical_path=safe_path,
            sha256=digest,
            storage_reference__storage_status__in={
                ObjectStorageReference.StorageStatus.UPLOADED,
                ObjectStorageReference.StorageStatus.VERIFIED,
            },
        ).first()
        if existing:
            result.documents_reused += 1
            result.total_bytes += len(encoded)
            return existing

        local_name = f"source-{result.documents_created:05d}{Path(safe_path).suffix}"
        local_path = workdir / local_name
        local_path.write_bytes(encoded)
        bucket = settings.MINIO_BUCKET_ARTIFACTS
        object_key = self.storage_service.build_object_key(
            context.audit.project_id,
            context.audit.id,
            ObjectStorageReference.ObjectType.SOURCE_DOCUMENT,
            Path(safe_path).name,
        )
        storage_reference = ObjectStorageReference.objects.create(
            bucket=bucket,
            object_key=object_key,
            object_type=ObjectStorageReference.ObjectType.SOURCE_DOCUMENT,
            storage_status=ObjectStorageReference.StorageStatus.PENDING_UPLOAD,
            content_type="text/plain; charset=utf-8",
            size_bytes=len(encoded),
            sha256=digest,
            audit=context.audit,
            project=context.audit.project,
            access_scope=ObjectStorageReference.AccessScope.AUDIT,
        )
        try:
            self.storage_service.upload_file(
                bucket,
                object_key,
                local_path,
                "text/plain; charset=utf-8",
            )
        except Exception:
            storage_reference.storage_status = ObjectStorageReference.StorageStatus.FAILED
            storage_reference.save(update_fields=["storage_status", "updated_at"])
            result.documents_skipped += 1
            result.warnings.append(f"Source storage failed for {safe_path}.")
            seen.discard(identity)
            return None

        storage_reference.storage_status = ObjectStorageReference.StorageStatus.VERIFIED
        storage_reference.save(update_fields=["storage_status", "updated_at"])
        document, _ = SourceDocument.objects.update_or_create(
            audit=context.audit,
            apk_file=context.apk_file,
            representation_type=representation,
            logical_path=safe_path,
            defaults={
                "display_path": display_path,
                "language": language,
                "class_name": class_name,
                "package_name": package_name,
                "sha256": digest,
                "line_count": len(content.splitlines()),
                "generated_by": generated_by,
                "tool_version": tool_version,
                "storage_reference": storage_reference,
                "metadata": {
                    "apk_sha256": context.apk_file.sha256,
                    **(metadata or {}),
                },
            },
        )
        document.full_clean()
        result.documents_created += 1
        result.total_bytes += len(encoded)
        return document

    def _jadx_version(self, executable: str) -> str:
        try:
            completed = self.command_runner(
                [executable, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return "unknown"
        return str(completed.stdout or completed.stderr or "unknown").strip()[:128]

    @staticmethod
    def _resource_representation(logical_path: str) -> str:
        return (
            SourceDocument.RepresentationType.NETWORK_SECURITY_XML
            if "network_security" in logical_path.lower()
            else SourceDocument.RepresentationType.RESOURCE_XML
        )

    def _open_local_copy(self, apk_file):
        method = getattr(self.file_provider, "open_apk_local_copy", None)
        if callable(method):
            return method(apk_file)
        local_path = self.file_provider.get_local_path_for_apk(apk_file)
        if local_path is None:
            raise ValueError("No local APK path is available for source indexing.")
        return nullcontext(local_path)


def _safe_logical_path(value: str) -> str:
    path = PurePosixPath(value)
    if not value or path.is_absolute() or ".." in path.parts or "\\" in value:
        raise ValueError("Unsafe source document path.")
    return path.as_posix()


def _source_identity(content: str, fallback_class: str) -> tuple[str, str]:
    package_match = re.search(r"(?m)^\s*package\s+([\w.]+)\s*[;{]", content)
    package_name = package_match.group(1) if package_match else ""
    class_match = re.search(
        r"(?m)^\s*(?:public\s+|private\s+|protected\s+|internal\s+|final\s+|"
        r"abstract\s+|open\s+|data\s+)*(?:class|interface|object|enum)\s+(\w+)",
        content,
    )
    class_leaf = class_match.group(1) if class_match else fallback_class
    return (
        f"{package_name}.{class_leaf}" if package_name else class_leaf,
        package_name,
    )


def _decode_resource_xml(raw: bytes):
    stripped = raw.lstrip()
    if stripped.startswith(b"<"):
        if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
            raise ValueError("Prohibited XML declaration.")
        return ElementTree.fromstring(raw), "MSAP deterministic resource XML renderer"
    try:
        from androguard.core.axml import AXMLPrinter
    except ImportError as exc:
        raise RuntimeError("Androguard binary XML decoder is unavailable.") from exc
    try:
        printer = AXMLPrinter(raw)
        if not printer.is_valid():
            raise ValueError("Invalid Android binary XML.")
        root = printer.get_xml_obj()
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError("Android binary XML could not be decoded.") from exc
    if root is None:
        raise ValueError("Android binary XML has no root element.")
    return root, "MSAP/Androguard resource XML decoder"
