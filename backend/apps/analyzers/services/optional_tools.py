from dataclasses import dataclass
from shutil import which


@dataclass(frozen=True)
class OptionalToolCapability:
    name: str
    executable: str
    description: str
    enabled: bool = False

    def metadata(self) -> dict:
        path = which(self.executable)
        return {
            "name": self.name,
            "version": "external",
            "description": self.description,
            "enabled": self.enabled,
            "available": path is not None,
            "optional": True,
            "capability": self.executable,
            "status": "AVAILABLE" if path else "UNAVAILABLE",
            "reason": "" if path else "Executable is not installed in the image.",
        }


OPTIONAL_TOOL_CAPABILITIES = (
    OptionalToolCapability(
        "jadx_adapter",
        "jadx",
        "Optional bounded JADX adapter; never downloaded during analysis.",
    ),
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
