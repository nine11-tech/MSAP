from apps.analyzers.services.base import AnalyzerContext, BaseAnalyzer, PlaceholderMetadataAnalyzer
from apps.analyzers.services.manifest_analyzer import ManifestMetadataAnalyzer


class AnalyzerRegistry:
    def __init__(self, analyzers: list[BaseAnalyzer] | None = None):
        self._analyzers = list(analyzers) if analyzers is not None else [
            PlaceholderMetadataAnalyzer(),
            ManifestMetadataAnalyzer(),
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
        return [
            {
                "name": analyzer.name,
                "version": analyzer.version,
                "description": getattr(analyzer, "description", ""),
                "enabled": getattr(analyzer, "enabled", True),
            }
            for analyzer in self._analyzers
        ]
