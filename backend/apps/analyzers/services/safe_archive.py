from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from zipfile import BadZipFile, ZipFile, ZipInfo

from django.conf import settings


class UnsafeAPKArchive(ValueError):
    """Raised when an APK violates bounded ZIP safety policy."""


@dataclass(frozen=True)
class APKArchiveSummary:
    entry_count: int
    compressed_bytes: int
    uncompressed_bytes: int
    max_compression_ratio: float
    dex_entries: tuple[str, ...]
    native_entries: tuple[str, ...]


def validate_apk_archive(path: str | Path) -> APKArchiveSummary:
    apk_path = Path(path)
    if not apk_path.is_file():
        raise UnsafeAPKArchive("APK file is unavailable.")
    if apk_path.stat().st_size <= 0:
        raise UnsafeAPKArchive("APK file is empty.")
    if apk_path.stat().st_size > settings.MSAP_MAX_APK_SIZE_BYTES:
        raise UnsafeAPKArchive("APK exceeds the configured size limit.")

    try:
        with ZipFile(apk_path) as archive:
            entries = archive.infolist()
            if len(entries) > settings.MSAP_MAX_APK_ZIP_ENTRIES:
                raise UnsafeAPKArchive("APK contains too many ZIP entries.")
            total_compressed = 0
            total_uncompressed = 0
            max_ratio = 0.0
            dex_entries = []
            native_entries = []
            seen = set()
            for entry in entries:
                _validate_entry(entry)
                if entry.filename in seen:
                    raise UnsafeAPKArchive("APK contains duplicate ZIP entry names.")
                seen.add(entry.filename)
                total_compressed += entry.compress_size
                total_uncompressed += entry.file_size
                if total_uncompressed > settings.MSAP_MAX_APK_UNCOMPRESSED_BYTES:
                    raise UnsafeAPKArchive(
                        "APK uncompressed content exceeds the configured limit."
                    )
                ratio = entry.file_size / max(entry.compress_size, 1)
                max_ratio = max(max_ratio, ratio)
                if ratio > settings.MSAP_MAX_APK_COMPRESSION_RATIO:
                    raise UnsafeAPKArchive(
                        "APK contains a suspicious compression ratio."
                    )
                if entry.filename.endswith(".dex"):
                    dex_entries.append(entry.filename)
                if entry.filename.startswith("lib/") and entry.filename.endswith(".so"):
                    native_entries.append(entry.filename)
    except UnsafeAPKArchive:
        raise
    except (BadZipFile, OSError, RuntimeError, NotImplementedError) as exc:
        raise UnsafeAPKArchive("APK is not a readable ZIP archive.") from exc

    if "AndroidManifest.xml" not in seen:
        raise UnsafeAPKArchive("APK does not contain AndroidManifest.xml.")
    return APKArchiveSummary(
        entry_count=len(entries),
        compressed_bytes=total_compressed,
        uncompressed_bytes=total_uncompressed,
        max_compression_ratio=round(max_ratio, 2),
        dex_entries=tuple(sorted(dex_entries)),
        native_entries=tuple(sorted(native_entries)),
    )


def _validate_entry(entry: ZipInfo) -> None:
    name = entry.filename.replace("\\", "/")
    path = PurePosixPath(name)
    if (
        not name
        or name.startswith("/")
        or "\x00" in name
        or ".." in path.parts
        or (path.parts and ":" in path.parts[0])
    ):
        raise UnsafeAPKArchive("APK contains an unsafe ZIP path.")
    unix_mode = (entry.external_attr >> 16) & 0o170000
    if unix_mode == 0o120000:
        raise UnsafeAPKArchive("APK contains a symbolic-link ZIP entry.")
    if entry.flag_bits & 0x1:
        raise UnsafeAPKArchive("APK contains encrypted ZIP entries.")
    if entry.file_size > settings.MSAP_MAX_APK_ENTRY_BYTES:
        raise UnsafeAPKArchive("APK contains an oversized ZIP entry.")
