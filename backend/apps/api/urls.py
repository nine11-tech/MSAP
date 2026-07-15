from django.urls import path
from rest_framework.routers import DefaultRouter

from apps.api.views import (
    APKFileViewSet,
    AuditViewSet,
    ComplianceScoreViewSet,
    EvidenceViewSet,
    FindingViewSet,
    HealthView,
    NormalizedArtifactViewSet,
    ObjectStorageReferenceViewSet,
    ProjectViewSet,
    RawAnalyzerResultViewSet,
    ReportViewSet,
    RiskScoreViewSet,
    SuspiciousIndicatorViewSet,
)


router = DefaultRouter()
router.register("projects", ProjectViewSet, basename="project")
router.register("audits", AuditViewSet, basename="audit")
router.register("apk-files", APKFileViewSet, basename="apk-file")
router.register(
    "storage-references",
    ObjectStorageReferenceViewSet,
    basename="storage-reference",
)
router.register("findings", FindingViewSet, basename="finding")
router.register(
    "raw-analyzer-results",
    RawAnalyzerResultViewSet,
    basename="raw-analyzer-result",
)
router.register(
    "normalized-artifacts",
    NormalizedArtifactViewSet,
    basename="normalized-artifact",
)
router.register("indicators", SuspiciousIndicatorViewSet, basename="indicator")
router.register("evidence", EvidenceViewSet, basename="evidence")
router.register("risk-scores", RiskScoreViewSet, basename="risk-score")
router.register(
    "compliance-scores",
    ComplianceScoreViewSet,
    basename="compliance-score",
)
router.register("reports", ReportViewSet, basename="report")

urlpatterns = [
    path("health/", HealthView.as_view(), name="health"),
    *router.urls,
]
