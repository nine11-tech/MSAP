from collections.abc import Iterator
from contextlib import contextmanager
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import ContextManager, Protocol

from django.conf import settings

from apps.apk_files.models import APKFile
from apps.storage.models import ObjectStorageReference
from apps.storage.services.minio_storage import MinIOStorageService


class FileProviderError(RuntimeError):
    """Base error for obtaining analyzer-safe local APK bytes."""


class APKFileUnavailableError(FileProviderError):
    """Raised when no local or downloadable APK object is available."""


class APKDownloadError(FileProviderError):
    """Raised when object storage cannot provide the requested APK."""


class APKChecksumMismatchError(FileProviderError):
    """Raised when downloaded APK bytes do not match stored metadata."""


class FileProvider(Protocol):
    """Resolve APK bytes without coupling analyzers to an object store client."""

    def get_local_path_for_apk(self, apk_file: APKFile) -> Path | None:
        """Return a durable local mirror path, when one is configured."""

    def open_apk_local_copy(self, apk_file: APKFile) -> ContextManager[Path]:
        """Provide a local path whose owned temporary bytes are cleaned on exit."""


class APKFileProvider:
    """Use a development mirror or a checksum-verified temporary MinIO copy."""

    allowed_local_environments = frozenset({"development", "test", "testing"})
    downloadable_storage_statuses = frozenset(
        {
            ObjectStorageReference.StorageStatus.UPLOADED,
            ObjectStorageReference.StorageStatus.VERIFIED,
        }
    )

    def __init__(
        self,
        local_root: str | Path | None = None,
        environment: str | None = None,
        storage_service: MinIOStorageService | None = None,
        temp_dir: str | Path | None = None,
        verify_sha256: bool | None = None,
    ):
        configured_root = (
            local_root
            if local_root is not None
            else getattr(settings, "MSAP_LOCAL_APK_ROOT", "")
        )
        self.local_root = Path(configured_root).resolve() if configured_root else None
        self.environment = (
            environment
            if environment is not None
            else getattr(settings, "MSAP_ENVIRONMENT", "development")
        ).lower()
        configured_temp_dir = (
            temp_dir
            if temp_dir is not None
            else getattr(settings, "MSAP_TEMP_DIR", "")
        )
        self.temp_dir = (
            Path(configured_temp_dir).resolve() if configured_temp_dir else None
        )
        self.verify_sha256 = (
            verify_sha256
            if verify_sha256 is not None
            else getattr(settings, "MSAP_VERIFY_DOWNLOADED_APK_SHA256", True)
        )
        self._storage_service = storage_service

    def get_local_path_for_apk(self, apk_file: APKFile) -> Path | None:
        """Resolve a development/test mirror without taking ownership of it."""
        if (
            self.environment not in self.allowed_local_environments
            or self.local_root is None
        ):
            return None

        storage_reference = apk_file.storage_reference
        if storage_reference is None or not storage_reference.object_key:
            return None

        candidates = (
            self.local_root / storage_reference.bucket / storage_reference.object_key,
            self.local_root / storage_reference.object_key,
        )
        for candidate in candidates:
            try:
                resolved_candidate = candidate.resolve()
                resolved_candidate.relative_to(self.local_root)
            except (OSError, RuntimeError, ValueError):
                continue
            if resolved_candidate.is_file():
                return resolved_candidate

        return None

    @contextmanager
    def open_apk_local_copy(self, apk_file: APKFile) -> Iterator[Path]:
        """Yield local APK bytes and delete any downloaded copy on context exit."""
        local_path = self.get_local_path_for_apk(apk_file)
        if local_path is not None:
            yield local_path
            return

        storage_reference = apk_file.storage_reference
        if (
            storage_reference is None
            or not storage_reference.bucket
            or not storage_reference.object_key
        ):
            raise APKFileUnavailableError(
                "APK file has no downloadable object storage reference."
            )

        storage_status = getattr(storage_reference, "storage_status", None)
        if (
            storage_status is not None
            and storage_status not in self.downloadable_storage_statuses
        ):
            raise APKFileUnavailableError(
                "APK object is not marked as uploaded or verified."
            )

        try:
            temporary_directory_context = TemporaryDirectory(
                prefix="msap-apk-",
                dir=self.temp_dir,
            )
        except OSError as exc:
            raise APKDownloadError(
                "A secure temporary APK file could not be created."
            ) from exc

        with temporary_directory_context as temporary_directory:
            temporary_path = Path(temporary_directory) / "downloaded.apk"
            try:
                self._get_storage_service().download_file(
                    storage_reference.bucket,
                    storage_reference.object_key,
                    temporary_path,
                )
            except Exception as exc:
                raise APKDownloadError(
                    "APK could not be downloaded from object storage."
                ) from exc

            if not temporary_path.is_file():
                raise APKDownloadError(
                    "Object storage did not produce a local APK file."
                )

            self._verify_downloaded_checksum(
                temporary_path,
                apk_file.sha256,
                storage_reference.sha256,
            )
            yield temporary_path

    def _get_storage_service(self) -> MinIOStorageService:
        if self._storage_service is None:
            self._storage_service = MinIOStorageService()
        return self._storage_service

    def _verify_downloaded_checksum(
        self,
        apk_path: Path,
        apk_sha256: str,
        storage_sha256: str,
    ) -> None:
        expected_checksums = {
            checksum.strip().lower()
            for checksum in (apk_sha256, storage_sha256)
            if checksum and checksum.strip()
        }
        if not self.verify_sha256 or not expected_checksums:
            return

        digest = sha256()
        try:
            with apk_path.open("rb") as downloaded_apk:
                for chunk in iter(lambda: downloaded_apk.read(1024 * 1024), b""):
                    digest.update(chunk)
        except OSError as exc:
            raise APKDownloadError(
                "Downloaded APK checksum could not be calculated."
            ) from exc

        if any(digest.hexdigest() != expected for expected in expected_checksums):
            raise APKChecksumMismatchError(
                "Downloaded APK checksum does not match expected SHA-256."
            )


class DevelopmentFileProvider(APKFileProvider):
    """Backward-compatible name for the default APK file provider."""
