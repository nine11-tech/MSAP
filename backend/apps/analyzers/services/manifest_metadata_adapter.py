from dataclasses import dataclass, field
from pathlib import Path
from xml.etree import ElementTree
from zipfile import BadZipFile, ZipFile

from django.conf import settings
from apps.analyzers.services.safe_archive import (
    UnsafeAPKArchive,
    validate_apk_archive,
)


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
    compile_sdk: str | None = None
    permissions: list[str] = field(default_factory=list)
    declared_permissions: list[dict] = field(default_factory=list)
    features: list[dict] = field(default_factory=list)
    components: list[dict] = field(default_factory=list)
    deep_links: list[dict] = field(default_factory=list)
    application: dict = field(
        default_factory=lambda: {
            "debuggable": None,
            "test_only": None,
            "allow_backup": None,
            "full_backup_content": None,
            "data_extraction_rules": None,
            "uses_cleartext_traffic": None,
            "network_security_config": None,
            "request_legacy_external_storage": None,
            "task_affinity": None,
            "application_class": None,
        }
    )
    shared_user_id: str | None = None


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
            validate_apk_archive(apk_path)
        except UnsafeAPKArchive as exc:
            raise ManifestParsingError(str(exc)) from exc

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
        declared_permissions = []
        for element in root:
            if _local_name(element.tag) != "permission":
                continue
            name = _android_attribute(element, "name")
            if name:
                declared_permissions.append(
                    {
                        "name": name,
                        "protection_level": _android_attribute(
                            element,
                            "protectionLevel",
                        ),
                    }
                )
        declared_permissions.sort(key=lambda item: item["name"])

        features = []
        for element in root:
            if _local_name(element.tag) != "uses-feature":
                continue
            name = _android_attribute(element, "name")
            if name:
                features.append(
                    {
                        "name": name,
                        "required": _boolean_attribute(element, "required"),
                        "version": _android_attribute(element, "version"),
                    }
                )
        features.sort(key=lambda item: item["name"])

        components = []
        deep_links = []
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
                    intent_filters = _intent_filters(element)
                    explicit_exported = _boolean_attribute(element, "exported")
                    if explicit_exported is None:
                        inferred_exported = bool(intent_filters)
                        exported_state = (
                            "INFERRED_TRUE" if inferred_exported else "INFERRED_FALSE"
                        )
                    else:
                        inferred_exported = explicit_exported
                        exported_state = (
                            "EXPLICIT_TRUE"
                            if explicit_exported
                            else "EXPLICIT_FALSE"
                        )
                    metadata = _metadata(element)
                    qualified_name = _qualified_component_name(
                        package_name,
                        component_name,
                    )
                    components.append(
                        {
                            "type": component_type,
                            "name": qualified_name,
                            "exported": inferred_exported,
                            "exported_state": exported_state,
                            "permission": _android_attribute(element, "permission"),
                            "read_permission": _android_attribute(
                                element,
                                "readPermission",
                            ),
                            "write_permission": _android_attribute(
                                element,
                                "writePermission",
                            ),
                            "authorities": _android_attribute(
                                element,
                                "authorities",
                            ),
                            "grant_uri_permissions": _boolean_attribute(
                                element,
                                "grantUriPermissions",
                            ),
                            "task_affinity": _android_attribute(
                                element,
                                "taskAffinity",
                            ),
                            "intent_filters": intent_filters,
                            "metadata": metadata,
                        }
                    )
                    for intent_filter in intent_filters:
                        for data in intent_filter["data"]:
                            if data.get("scheme"):
                                deep_links.append(
                                    {
                                        "component": qualified_name,
                                        **data,
                                        "auto_verify": intent_filter["auto_verify"],
                                    }
                                )
        components.sort(key=lambda item: (item["type"], item["name"]))

        application = {
            "debuggable": _application_boolean(application_element, "debuggable"),
            "test_only": _application_boolean(application_element, "testOnly"),
            "allow_backup": _application_boolean(application_element, "allowBackup"),
            "full_backup_content": _android_attribute(
                application_element,
                "fullBackupContent",
            ),
            "data_extraction_rules": _android_attribute(
                application_element,
                "dataExtractionRules",
            ),
            "uses_cleartext_traffic": _application_boolean(
                application_element,
                "usesCleartextTraffic",
            ),
            "network_security_config": _android_attribute(
                application_element,
                "networkSecurityConfig",
            ),
            "request_legacy_external_storage": _application_boolean(
                application_element,
                "requestLegacyExternalStorage",
            ),
            "task_affinity": _android_attribute(application_element, "taskAffinity"),
            "application_class": _android_attribute(application_element, "name"),
            "metadata": _metadata(application_element),
        }

        return ManifestMetadata(
            package_name=package_name,
            version_name=_android_attribute(root, "versionName"),
            version_code=_android_attribute(root, "versionCode"),
            min_sdk=_android_attribute(uses_sdk, "minSdkVersion"),
            target_sdk=_android_attribute(uses_sdk, "targetSdkVersion"),
            compile_sdk=_android_attribute(root, "compileSdkVersion"),
            permissions=permissions,
            declared_permissions=declared_permissions,
            features=features,
            components=components,
            deep_links=deep_links,
            application=application,
            shared_user_id=_android_attribute(root, "sharedUserId"),
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


def _boolean_attribute(element, attribute_name: str) -> bool | None:
    return _application_boolean(element, attribute_name)


def _metadata(element) -> list[dict]:
    if element is None:
        return []
    items = []
    for child in element:
        if _local_name(child.tag) != "meta-data":
            continue
        name = _android_attribute(child, "name")
        if name:
            items.append(
                {
                    "name": name,
                    "value": _android_attribute(child, "value"),
                    "resource": _android_attribute(child, "resource"),
                }
            )
    return sorted(items, key=lambda item: item["name"])


def _intent_filters(element) -> list[dict]:
    filters = []
    for child in element:
        if _local_name(child.tag) != "intent-filter":
            continue
        actions = []
        categories = []
        data_entries = []
        for item in child:
            kind = _local_name(item.tag)
            if kind == "action":
                name = _android_attribute(item, "name")
                if name:
                    actions.append(name)
            elif kind == "category":
                name = _android_attribute(item, "name")
                if name:
                    categories.append(name)
            elif kind == "data":
                data_entries.append(
                    {
                        "scheme": _android_attribute(item, "scheme"),
                        "host": _android_attribute(item, "host"),
                        "port": _android_attribute(item, "port"),
                        "path": _android_attribute(item, "path"),
                        "path_prefix": _android_attribute(item, "pathPrefix"),
                        "path_pattern": _android_attribute(item, "pathPattern"),
                        "mime_type": _android_attribute(item, "mimeType"),
                    }
                )
        filters.append(
            {
                "actions": sorted(actions),
                "categories": sorted(categories),
                "data": data_entries,
                "auto_verify": _boolean_attribute(child, "autoVerify"),
            }
        )
    return filters


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
