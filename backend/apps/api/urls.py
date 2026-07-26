from django.urls import path
from rest_framework.routers import DefaultRouter

from apps.api.views import (
    APKFileViewSet,
    AnalyzerRegistryView,
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
    RuleEvaluationViewSet,
    SuspiciousIndicatorViewSet,
    SystemStatusView,
)
from apps.api.auth_views import (
    ChangePasswordView,
    CSRFView,
    LoginView,
    LogoutView,
    MeView,
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
router.register(
    "rule-evaluations",
    RuleEvaluationViewSet,
    basename="rule-evaluation",
)

urlpatterns = [
    path("health/", HealthView.as_view(), name="health"),
    path("auth/csrf/", CSRFView.as_view(), name="auth-csrf"),
    path("auth/login/", LoginView.as_view(), name="auth-login"),
    path("auth/logout/", LogoutView.as_view(), name="auth-logout"),
    path("auth/me/", MeView.as_view(), name="auth-me"),
    path(
        "auth/change-password/",
        ChangePasswordView.as_view(),
        name="auth-change-password",
    ),
    path("analyzers/", AnalyzerRegistryView.as_view(), name="analyzer-registry"),
    path("system/status/", SystemStatusView.as_view(), name="system-status"),
    *router.urls,
]
