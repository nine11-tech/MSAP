from contextlib import nullcontext
from pathlib import Path

from apps.analyzers.models import RawAnalyzerResult
from apps.analyzers.services.base import AnalyzerContext, AnalyzerResult
from apps.analyzers.services.manifest_metadata_adapter import (
    ManifestMetadataAdapter,
    ManifestParsingError,
)
from apps.normalization.services.schemas import (
    SourceLocatorHint,
    components_payload,
    manifest_payload,
    permissions_payload,
)
from apps.evidence.models import SourceDocument
from apps.storage.services.file_provider import (
    APKChecksumMismatchError,
    APKDownloadError,
    APKFileProvider,
    APKFileUnavailableError,
    FileProvider,
)


class ManifestMetadataAnalyzer:
    name = "manifest_metadata_analyzer"
    version = "0.2.0"
    description = (
        "Safely extracts and normalizes metadata from an APK AndroidManifest.xml."
    )
    enabled = True

    def __init__(
        self,
        file_provider: FileProvider | None = None,
        manifest_adapter: ManifestMetadataAdapter | None = None,
    ):
        self.file_provider = file_provider or APKFileProvider()
        self.manifest_adapter = manifest_adapter or ManifestMetadataAdapter()

    def supports(self, context: AnalyzerContext) -> bool:
        return context.apk_file.storage_reference_id is not None

    def run(self, context: AnalyzerContext) -> AnalyzerResult:
        apk_file = context.apk_file
        try:
            with self._open_local_copy(apk_file) as local_path:
                metadata = self.manifest_adapter.parse(Path(local_path))
        except APKFileUnavailableError as exc:
            return self._skipped_result(apk_file.id, str(exc))
        except APKChecksumMismatchError as exc:
            return self._failed_result(apk_file.id, str(exc))
        except APKDownloadError as exc:
            return self._failed_result(apk_file.id, str(exc))
        except ManifestParsingError as exc:
            return self._failed_result(apk_file.id, str(exc))
        except Exception:
            return self._failed_result(
                apk_file.id,
                "AndroidManifest.xml parsing failed unexpectedly.",
            )

        updated_fields = []
        if metadata.package_name:
            apk_file.package_name = metadata.package_name
            updated_fields.append("package_name")
        if metadata.version_name:
            apk_file.version_name = metadata.version_name
            updated_fields.append("version_name")
        if updated_fields:
            apk_file.save(update_fields=updated_fields)

        return AnalyzerResult(
            analyzer_name=self.name,
            analyzer_version=self.version,
            status=RawAnalyzerResult.Status.COMPLETED,
            raw_summary={
                "apk_file_id": apk_file.id,
                "package_name": metadata.package_name,
                "version_name": metadata.version_name,
                "permission_count": len(metadata.permissions),
                "component_count": len(metadata.components),
                "parsing_status": "PARSED",
                "real_apk_parsing": True,
            },
            normalized_artifacts=[
                manifest_payload(
                    source=self.name,
                    package_name=metadata.package_name,
                    version_name=metadata.version_name,
                    version_code=metadata.version_code,
                    min_sdk=metadata.min_sdk,
                    target_sdk=metadata.target_sdk,
                    compile_sdk=metadata.compile_sdk,
                    permissions=metadata.permissions,
                    declared_permissions=metadata.declared_permissions,
                    features=metadata.features,
                    components=metadata.components,
                    deep_links=metadata.deep_links,
                    application=metadata.application,
                    shared_user_id=metadata.shared_user_id,
                    parsing_status="PARSED",
                    source_locators=_manifest_source_locators(metadata),
                ),
                permissions_payload(
                    source=self.name,
                    permissions=metadata.permissions,
                    declared_permissions=metadata.declared_permissions,
                ),
                components_payload(
                    source=self.name,
                    components=metadata.components,
                    deep_links=metadata.deep_links,
                ),
            ],
        )

    def _open_local_copy(self, apk_file):
        open_local_copy = getattr(self.file_provider, "open_apk_local_copy", None)
        if callable(open_local_copy):
            return open_local_copy(apk_file)

        local_path = self.file_provider.get_local_path_for_apk(apk_file)
        if local_path is None:
            raise APKFileUnavailableError("No local APK path is available.")
        return nullcontext(local_path)

    def _skipped_result(self, apk_file_id: int, message: str) -> AnalyzerResult:
        return AnalyzerResult(
            analyzer_name=self.name,
            analyzer_version=self.version,
            status=RawAnalyzerResult.Status.SKIPPED,
            raw_summary={
                "apk_file_id": apk_file_id,
                "parsing_status": "SKIPPED_NO_LOCAL_PATH",
                "real_apk_parsing": False,
            },
            error_message=message,
        )

    def _failed_result(self, apk_file_id: int, message: str) -> AnalyzerResult:
        return AnalyzerResult(
            analyzer_name=self.name,
            analyzer_version=self.version,
            status=RawAnalyzerResult.Status.FAILED,
            raw_summary={
                "apk_file_id": apk_file_id,
                "parsing_status": "FAILED",
                "real_apk_parsing": False,
            },
            error_message=message,
        )


def _manifest_source_locators(metadata) -> tuple[SourceLocatorHint, ...]:
    representation = SourceDocument.RepresentationType.MANIFEST_XML
    path = "AndroidManifest.xml"
    hints: list[SourceLocatorHint] = []

    def add(
        semantic_key: str,
        *terms: str,
        locator: dict | None = None,
        class_name: str = "",
    ) -> None:
        clean_terms = tuple(term for term in terms if term)
        hints.append(
            SourceLocatorHint(
                representation=representation,
                semantic_key=semantic_key,
                logical_path=path,
                class_name=class_name,
                search_terms=clean_terms,
                confidence="HIGH",
                locator={"match_all": True, **(locator or {})},
            )
        )

    application_attributes = {
        "manifest_debuggable": ("android:debuggable", "true"),
        "manifest_allow_backup": ("android:allowBackup", "true"),
        "manifest_cleartext": ("android:usesCleartextTraffic", "true"),
        "manifest_test_only": ("android:testOnly", "true"),
        "request_legacy_storage": (
            "android:requestLegacyExternalStorage",
            "true",
        ),
    }
    for semantic_key, terms in application_attributes.items():
        add(semantic_key, *terms)
    add("shared_user_id", "android:sharedUserId")
    add("custom_task_affinity", "android:taskAffinity")
    add("old_target_sdk", "android:targetSdkVersion")
    for metadata_item in metadata.application.get("metadata", []):
        if (
            metadata_item.get("name") == "android.webkit.WebView.EnableSafeBrowsing"
            and str(metadata_item.get("value") or "").lower() == "false"
        ):
            add(
                "safebrowsing_disabled",
                "android.webkit.WebView.EnableSafeBrowsing",
                "false",
            )

    for component in metadata.components:
        component_type = component.get("type")
        if not component.get("exported") or component_type not in {
            "activity",
            "service",
            "receiver",
            "provider",
        }:
            continue
        if any(
            component.get(field)
            for field in ("permission", "read_permission", "write_permission")
        ):
            continue
        component_name = str(component.get("name") or "")
        add(
            f"exported_{component_type}_unprotected",
            f"<{component_type}",
            component_name.rsplit(".", 1)[-1],
            "android:exported",
            class_name=component_name,
        )

    for permission in metadata.declared_permissions:
        protection = str(permission.get("protection_level") or "").lower()
        if protection not in {"signature", "signatureorsystem"}:
            add(
                "weak_custom_permission",
                "<permission",
                str(permission.get("name") or ""),
            )
    for deep_link in metadata.deep_links:
        scheme = str(deep_link.get("scheme") or "")
        if scheme and scheme not in {"http", "https"}:
            add("custom_uri_scheme", "android:scheme", scheme)
        if scheme in {"http", "https"} and not deep_link.get("auto_verify"):
            add(
                "unverified_app_link",
                "android:scheme",
                scheme,
                str(deep_link.get("host") or ""),
            )
    for permission in metadata.permissions:
        if permission in {
            "android.permission.READ_CALENDAR",
            "android.permission.WRITE_CALENDAR",
            "android.permission.CAMERA",
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_CONTACTS",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_BACKGROUND_LOCATION",
            "android.permission.RECORD_AUDIO",
            "android.permission.READ_CALL_LOG",
            "android.permission.READ_SMS",
        }:
            add("privacy_permission_review", "<uses-permission", permission)
    return tuple(hints)
