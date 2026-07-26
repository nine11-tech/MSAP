from apps.analyzers.services.base import AnalyzerContext, BaseAnalyzer, PlaceholderMetadataAnalyzer
from apps.analyzers.services.manifest_analyzer import ManifestMetadataAnalyzer
from apps.analyzers.services.advanced_static_analyzer import AdvancedStaticAnalyzer
from apps.analyzers.services.optional_tools import OPTIONAL_TOOL_CAPABILITIES


class AnalyzerRegistry:
    def __init__(self, analyzers: list[BaseAnalyzer] | None = None):
        self._analyzers = list(analyzers) if analyzers is not None else [
            PlaceholderMetadataAnalyzer(),
            ManifestMetadataAnalyzer(),
            AdvancedStaticAnalyzer(),
        ]

    def get_registered_analyzers(self) -> list[BaseAnalyzer]:
        return list(self._analyzers)

    def get_supported_analyzers(self, context: AnalyzerContext) -> list[BaseAnalyzer]:
        return [
            analyzer
            for analyzer in self._analyzers
            if getattr(analyzer, "enabled", True) and analyzer.supports(context)
        ]

    def get_analyzer_metadata(self) -> list[dict]:
        analyzers = [
            {
                "name": analyzer.name,
                "version": analyzer.version,
                "description": getattr(analyzer, "description", ""),
                "enabled": getattr(analyzer, "enabled", True),
                "available": getattr(analyzer, "available", True),
                "optional": getattr(analyzer, "optional", False),
                "status": (
                    "AVAILABLE"
                    if getattr(analyzer, "available", True)
                    else "UNAVAILABLE"
                ),
            }
            for analyzer in self._analyzers
        ]
        return analyzers + [
            capability.metadata() for capability in OPTIONAL_TOOL_CAPABILITIES
        ]
