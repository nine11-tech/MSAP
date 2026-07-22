from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from apps.storage.models import ObjectStorageReference
from apps.storage.services.file_provider import (
    APKChecksumMismatchError,
    APKDownloadError,
    APKFileProvider,
)


def _apk_file(expected_sha256: str = ""):
    storage_reference = SimpleNamespace(
        bucket="msap-apk-uploads",
        object_key="projects/1/audits/1/controlled.apk",
        storage_status=ObjectStorageReference.StorageStatus.UPLOADED,
        sha256=expected_sha256,
    )
    return SimpleNamespace(
        id=1,
        sha256=expected_sha256,
        storage_reference=storage_reference,
    )


def _downloading_storage_service(downloaded_bytes: bytes):
    storage_service = Mock()
    storage_service.download_file.side_effect = (
        lambda bucket, object_key, destination: Path(destination).write_bytes(
            downloaded_bytes
        )
    )
    return storage_service


def test_provider_downloads_to_temporary_apk_and_cleans_it(tmp_path):
    downloaded_bytes = b"small controlled APK fixture bytes"
    expected_sha256 = sha256(downloaded_bytes).hexdigest()
    apk_file = _apk_file(expected_sha256)
    storage_service = _downloading_storage_service(downloaded_bytes)
    provider = APKFileProvider(
        local_root=None,
        environment="production",
        storage_service=storage_service,
        temp_dir=tmp_path,
    )

    with provider.open_apk_local_copy(apk_file) as apk_path:
        downloaded_path = apk_path
        assert downloaded_path.is_file()
        assert downloaded_path.suffix == ".apk"
        assert downloaded_path.read_bytes() == downloaded_bytes
        assert downloaded_path.parent.parent == tmp_path

    assert not downloaded_path.exists()
    assert not downloaded_path.parent.exists()
    storage_service.download_file.assert_called_once_with(
        apk_file.storage_reference.bucket,
        apk_file.storage_reference.object_key,
        downloaded_path,
    )


def test_provider_accepts_matching_storage_reference_checksum(tmp_path):
    downloaded_bytes = b"checksum verified bytes"
    apk_file = _apk_file()
    apk_file.storage_reference.sha256 = sha256(downloaded_bytes).hexdigest().upper()
    provider = APKFileProvider(
        local_root=None,
        environment="production",
        storage_service=_downloading_storage_service(downloaded_bytes),
        temp_dir=tmp_path,
    )

    with provider.open_apk_local_copy(apk_file) as apk_path:
        assert apk_path.read_bytes() == downloaded_bytes


def test_provider_rejects_checksum_mismatch_and_cleans_temp_file(tmp_path):
    apk_file = _apk_file("0" * 64)
    provider = APKFileProvider(
        local_root=None,
        environment="production",
        storage_service=_downloading_storage_service(b"different bytes"),
        temp_dir=tmp_path,
    )

    with pytest.raises(
        APKChecksumMismatchError,
        match="does not match expected SHA-256",
    ):
        with provider.open_apk_local_copy(apk_file):
            pytest.fail("checksum mismatch must happen before the path is yielded")

    assert list(tmp_path.iterdir()) == []


def test_provider_wraps_download_failure_and_cleans_temp_directory(tmp_path):
    storage_service = Mock()
    storage_service.download_file.side_effect = RuntimeError("secret-bearing error")
    provider = APKFileProvider(
        local_root=None,
        environment="production",
        storage_service=storage_service,
        temp_dir=tmp_path,
    )

    with pytest.raises(
        APKDownloadError,
        match="could not be downloaded from object storage",
    ):
        with provider.open_apk_local_copy(_apk_file()):
            pytest.fail("download failure must happen before the path is yielded")

    assert list(tmp_path.iterdir()) == []
