from pathlib import Path
from typing import Protocol

from django.conf import settings

from apps.apk_files.models import APKFile


class FileProvider(Protocol):
    """Resolve APK bytes without coupling analyzers to an object store client."""

    def get_local_path_for_apk(self, apk_file: APKFile) -> Path | None:
        ...


class DevelopmentFileProvider:
    """Resolve APKs from an explicitly configured development/test mirror."""

    allowed_environments = frozenset({"development", "test", "testing"})

    def __init__(
        self,
        local_root: str | Path | None = None,
        environment: str | None = None,
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

    def get_local_path_for_apk(self, apk_file: APKFile) -> Path | None:
        if self.environment not in self.allowed_environments or self.local_root is None:
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
