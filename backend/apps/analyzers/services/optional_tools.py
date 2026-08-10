from dataclasses import dataclass
from shutil import which

from django.conf import settings


@dataclass(frozen=True)
class OptionalToolCapability:
    name: str
    executable: str
    description: str
    enabled: bool = False

    def executable_path(self) -> str | None:
        return which(self.executable) if self.enabled else None

    def metadata(self) -> dict:
        path = which(self.executable)
        if not self.enabled:
            status = "DISABLED"
            reason = "Capability is disabled by configuration."
        else:
            status = "AVAILABLE" if path else "UNAVAILABLE"
            reason = "" if path else "Executable is not installed in the image."
        return {
            "name": self.name,
            "version": "external",
            "description": self.description,
            "enabled": self.enabled,
            "available": path is not None,
            "optional": True,
            "capability": self.executable,
            "status": status,
            "reason": reason,
        }


JADX_CAPABILITY = OptionalToolCapability(
    "jadx_adapter",
    "jadx",
    "Optional bounded JADX adapter; never downloaded during analysis.",
    enabled=getattr(settings, "MSAP_JADX_ENABLED", False),
)


OPTIONAL_TOOL_CAPABILITIES = (
    JADX_CAPABILITY,
    OptionalToolCapability(
        "apktool_adapter",
        "apktool",
        "Optional bounded apktool resource adapter; never downloaded during analysis.",
    ),
    OptionalToolCapability(
        "apkid_adapter",
        "apkid",
        "Optional bounded APKiD identification adapter.",
    ),
    OptionalToolCapability(
        "yara_adapter",
        "yara",
        "Optional repository-rule-only YARA adapter.",
    ),
)
