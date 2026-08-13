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
    SourceDocumentViewSet,
    SystemStatusView,
)
from apps.api.auth_views import (
    ChangePasswordView,
    CSRFView,
    LoginView,
    LogoutView,
    MeView,
)
from apps.dynamic_analysis.views import (
    AgentRunViewSet,
    AgentRuntimeViewSet,
    AssessmentPlanViewSet,
    DynamicAnalysisJobViewSet,
    DynamicDeviceCapabilityViewSet,
    DynamicDeviceEventViewSet,
    DynamicDeviceLeaseViewSet,
    DynamicDevicePoolViewSet,
    DynamicDeviceViewSet,
    DynamicEmulatorSnapshotViewSet,
    DynamicHostAgentViewSet,
    DynamicSessionArtifactViewSet,
    DynamicSessionEventViewSet,
    DynamicSessionStageViewSet,
    DynamicSessionViewSet,
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
    "source-documents",
    SourceDocumentViewSet,
    basename="source-document",
)
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
router.register(
    "dynamic/device-pools",
    DynamicDevicePoolViewSet,
    basename="dynamic-device-pool",
)
router.register(
    "dynamic/devices",
    DynamicDeviceViewSet,
    basename="dynamic-device",
)
router.register(
    "dynamic/device-capabilities",
    DynamicDeviceCapabilityViewSet,
    basename="dynamic-device-capability",
)
router.register(
    "dynamic/emulator-snapshots",
    DynamicEmulatorSnapshotViewSet,
    basename="dynamic-emulator-snapshot",
)
router.register(
    "dynamic/device-leases",
    DynamicDeviceLeaseViewSet,
    basename="dynamic-device-lease",
)
router.register(
    "dynamic/device-events",
    DynamicDeviceEventViewSet,
    basename="dynamic-device-event",
)
router.register(
    "dynamic/jobs",
    DynamicAnalysisJobViewSet,
    basename="dynamic-analysis-job",
)
router.register(
    "dynamic/sessions",
    DynamicSessionViewSet,
    basename="dynamic-session",
)
router.register(
    "dynamic/session-stages",
    DynamicSessionStageViewSet,
    basename="dynamic-session-stage",
)
router.register(
    "dynamic/session-events",
    DynamicSessionEventViewSet,
    basename="dynamic-session-event",
)
router.register(
    "dynamic/session-artifacts",
    DynamicSessionArtifactViewSet,
    basename="dynamic-session-artifact",
)
router.register(
    "dynamic/agent/runtimes",
    AgentRuntimeViewSet,
    basename="agent-runtime",
)
router.register(
    "dynamic/agent/runs",
    AgentRunViewSet,
    basename="agent-run",
)
router.register(
    "dynamic/agent/plans",
    AssessmentPlanViewSet,
    basename="assessment-plan",
)
router.register(
    "dynamic/host-agent",
    DynamicHostAgentViewSet,
    basename="dynamic-host-agent",
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
