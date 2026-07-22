from dataclasses import dataclass, field
from pathlib import Path
from xml.etree import ElementTree
from zipfile import BadZipFile, ZipFile

from django.conf import settings


ANDROID_NAMESPACE = "http://schemas.android.com/apk/res/android"
ANDROID_ATTRIBUTE_PREFIX = f"{{{ANDROID_NAMESPACE}}}"
MANIFEST_MEMBER = "AndroidManifest.xml"


class ManifestParsingError(ValueError):
    """Raised when an APK manifest cannot be read safely or parsed."""


@dataclass(frozen=True)
class ManifestMetadata:
    package_name: str | None = None
    version_name: str | None = None
    version_code: str | None = None
    min_sdk: str | None = None
    target_sdk: str | None = None
    permissions: list[str] = field(default_factory=list)
    components: list[dict] = field(default_factory=list)
    application: dict = field(
        default_factory=lambda: {
            "debuggable": None,
            "allow_backup": None,
            "uses_cleartext_traffic": None,
        }
    )


class ManifestMetadataAdapter:
    """Extract a bounded AndroidManifest.xml payload from an APK ZIP.

    Plain XML is supported for small development fixtures. Compiled Android
    binary XML is decoded with Androguard, which is imported only when needed.
    """

    def __init__(
        self,
        max_apk_size_bytes: int | None = None,
        max_manifest_size_bytes: int | None = None,
        max_zip_entries: int | None = None,
    ):
        self.max_apk_size_bytes = (
            max_apk_size_bytes or settings.MSAP_MAX_APK_SIZE_BYTES
        )
        self.max_manifest_size_bytes = max_manifest_size_bytes or getattr(
            settings,
            "MSAP_MAX_MANIFEST_SIZE_BYTES",
            4 * 1024 * 1024,
        )
        self.max_zip_entries = max_zip_entries or getattr(
            settings,
            "MSAP_MAX_APK_ZIP_ENTRIES",
            10_000,
        )

    def parse(self, apk_path: str | Path) -> ManifestMetadata:
        path = Path(apk_path)
        manifest_bytes = self._read_manifest(path)
        root = self._parse_manifest_xml(manifest_bytes)
        return self._extract_metadata(root)

    def _read_manifest(self, apk_path: Path) -> bytes:
        if not apk_path.is_file():
            raise ManifestParsingError("Local APK file does not exist.")

        try:
            apk_size = apk_path.stat().st_size
        except OSError as exc:
            raise ManifestParsingError(
                "Local APK file metadata could not be read."
            ) from exc

        if apk_size <= 0:
            raise ManifestParsingError("Local APK file is empty.")
        if apk_size > self.max_apk_size_bytes:
            raise ManifestParsingError("Local APK exceeds the configured size limit.")

        try:
            with ZipFile(apk_path) as apk_zip:
                if len(apk_zip.infolist()) > self.max_zip_entries:
                    raise ManifestParsingError("APK contains too many ZIP entries.")
                try:
                    manifest_info = apk_zip.getinfo(MANIFEST_MEMBER)
                except KeyError as exc:
                    raise ManifestParsingError(
                        "APK does not contain AndroidManifest.xml."
                    ) from exc
                if manifest_info.flag_bits & 0x1:
                    raise ManifestParsingError("AndroidManifest.xml is encrypted.")
                if manifest_info.file_size <= 0:
                    raise ManifestParsingError("AndroidManifest.xml is empty.")
                if manifest_info.file_size > self.max_manifest_size_bytes:
                    raise ManifestParsingError(
                        "AndroidManifest.xml exceeds the configured size limit."
                    )
                manifest_bytes = apk_zip.read(manifest_info)
        except ManifestParsingError:
            raise
        except (BadZipFile, OSError, RuntimeError, NotImplementedError) as exc:
            raise ManifestParsingError("Local APK is not a readable ZIP archive.") from exc

        if len(manifest_bytes) > self.max_manifest_size_bytes:
            raise ManifestParsingError(
                "AndroidManifest.xml exceeds the configured size limit."
            )
        return manifest_bytes

    def _parse_manifest_xml(self, manifest_bytes: bytes):
        stripped_manifest = manifest_bytes.lstrip()
        if stripped_manifest.startswith(b"<"):
            upper_manifest = stripped_manifest.upper()
            if b"<!DOCTYPE" in upper_manifest or b"<!ENTITY" in upper_manifest:
                raise ManifestParsingError(
                    "AndroidManifest.xml contains prohibited XML declarations."
                )
            try:
                root = ElementTree.fromstring(manifest_bytes)
            except ElementTree.ParseError as exc:
                raise ManifestParsingError("AndroidManifest.xml is malformed.") from exc
        else:
            try:
                from androguard.core.axml import AXMLPrinter
            except ImportError as exc:
                raise ManifestParsingError(
                    "Compiled AndroidManifest.xml parsing requires Androguard."
                ) from exc

            try:
                printer = AXMLPrinter(manifest_bytes)
                if not printer.is_valid():
                    raise ManifestParsingError(
                        "Compiled AndroidManifest.xml is invalid."
                    )
                root = printer.get_xml_obj()
            except ManifestParsingError:
                raise
            except Exception as exc:
                raise ManifestParsingError(
                    "Compiled AndroidManifest.xml could not be parsed."
                ) from exc

        if root is None or _local_name(root.tag) != "manifest":
            raise ManifestParsingError(
                "AndroidManifest.xml does not have a manifest root element."
            )
        return root

    def _extract_metadata(self, root) -> ManifestMetadata:
        package_name = _optional_string(root.get("package"))
        uses_sdk = _first_child(root, "uses-sdk")
        application_element = _first_child(root, "application")

        permissions = sorted(
            {
                permission
                for element in root.iter()
                if _local_name(element.tag)
                in {"uses-permission", "uses-permission-sdk-23"}
                if (
                    permission := _optional_string(
                        element.get(f"{ANDROID_ATTRIBUTE_PREFIX}name")
                        or element.get("name")
                    )
                )
            }
        )

        components = []
        component_types = {
            "activity": "activity",
            "activity-alias": "activity_alias",
            "service": "service",
            "receiver": "receiver",
            "provider": "provider",
        }
        if application_element is not None:
            for element in application_element:
                component_type = component_types.get(_local_name(element.tag))
                component_name = _optional_string(
                    element.get(f"{ANDROID_ATTRIBUTE_PREFIX}name")
                    or element.get("name")
                )
                if component_type and component_name:
                    components.append(
                        {
                            "type": component_type,
                            "name": _qualified_component_name(
                                package_name,
                                component_name,
                            ),
                        }
                    )
        components.sort(key=lambda item: (item["type"], item["name"]))

        application = {
            "debuggable": _application_boolean(application_element, "debuggable"),
            "allow_backup": _application_boolean(application_element, "allowBackup"),
            "uses_cleartext_traffic": _application_boolean(
                application_element,
                "usesCleartextTraffic",
            ),
        }

        return ManifestMetadata(
            package_name=package_name,
            version_name=_android_attribute(root, "versionName"),
            version_code=_android_attribute(root, "versionCode"),
            min_sdk=_android_attribute(uses_sdk, "minSdkVersion"),
            target_sdk=_android_attribute(uses_sdk, "targetSdkVersion"),
            permissions=permissions,
            components=components,
            application=application,
        )


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _first_child(element, child_name: str):
    if element is None:
        return None
    return next(
        (child for child in element if _local_name(child.tag) == child_name),
        None,
    )


def _android_attribute(element, attribute_name: str) -> str | None:
    if element is None:
        return None
    return _optional_string(
        element.get(f"{ANDROID_ATTRIBUTE_PREFIX}{attribute_name}")
        or element.get(attribute_name)
    )


def _application_boolean(application_element, attribute_name: str) -> bool | None:
    value = _android_attribute(application_element, attribute_name)
    if value is None:
        return None
    normalized_value = value.lower()
    if normalized_value in {"true", "1"}:
        return True
    if normalized_value in {"false", "0"}:
        return False
    return None


def _optional_string(value) -> str | None:
    if value is None:
        return None
    normalized_value = str(value).strip()
    return normalized_value or None


def _qualified_component_name(
    package_name: str | None,
    component_name: str,
) -> str:
    if not package_name:
        return component_name
    if component_name.startswith("."):
        return f"{package_name}{component_name}"
    if "." not in component_name:
        return f"{package_name}.{component_name}"
    return component_name
