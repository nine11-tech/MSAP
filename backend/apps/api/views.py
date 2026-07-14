from drf_spectacular.utils import extend_schema, inline_serializer
from rest_framework import serializers, viewsets
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.api.serializers import (
    APKFileSerializer,
    AuditSerializer,
    ComplianceScoreSerializer,
    EvidenceSerializer,
    FindingSerializer,
    ObjectStorageReferenceSerializer,
    ProjectSerializer,
    ReportSerializer,
    RiskScoreSerializer,
    SuspiciousIndicatorSerializer,
)
from apps.apk_files.models import APKFile
from apps.audits.models import Audit
from apps.evidence.models import Evidence
from apps.findings.models import Finding
from apps.indicators.models import SuspiciousIndicator
from apps.projects.models import Project
from apps.reports.models import Report
from apps.scoring.models import ComplianceScore, RiskScore
from apps.storage.models import ObjectStorageReference


class HealthView(APIView):
    authentication_classes = []
    permission_classes = []

    @extend_schema(
        responses=inline_serializer(
            name="HealthResponse",
            fields={
                "status": serializers.CharField(),
                "service": serializers.CharField(),
            },
        )
    )
    def get(self, request):
        return Response({"status": "ok", "service": "msap-backend"})


class ProjectViewSet(viewsets.ModelViewSet):
    queryset = Project.objects.all()
    serializer_class = ProjectSerializer


class AuditViewSet(viewsets.ModelViewSet):
    queryset = Audit.objects.select_related("project").all()
    serializer_class = AuditSerializer


class APKFileViewSet(viewsets.ModelViewSet):
    queryset = APKFile.objects.select_related("audit", "storage_reference").all()
    serializer_class = APKFileSerializer


class ObjectStorageReferenceViewSet(viewsets.ModelViewSet):
    queryset = ObjectStorageReference.objects.select_related("project", "audit").all()
    serializer_class = ObjectStorageReferenceSerializer


class FindingViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Finding.objects.select_related("audit").all()
    serializer_class = FindingSerializer


class SuspiciousIndicatorViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = SuspiciousIndicator.objects.select_related("audit").all()
    serializer_class = SuspiciousIndicatorSerializer


class EvidenceViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Evidence.objects.select_related(
        "audit",
        "finding",
        "indicator",
        "storage_reference",
    ).all()
    serializer_class = EvidenceSerializer


class RiskScoreViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = RiskScore.objects.select_related("audit").all()
    serializer_class = RiskScoreSerializer


class ComplianceScoreViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = ComplianceScore.objects.select_related("audit").all()
    serializer_class = ComplianceScoreSerializer


class ReportViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Report.objects.select_related("audit", "storage_reference").all()
    serializer_class = ReportSerializer
