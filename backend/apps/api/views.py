from drf_spectacular.utils import extend_schema, inline_serializer
from django.conf import settings
from django.db import transaction
from rest_framework import serializers, status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.api.serializers import (
    APKFileSerializer,
    APKUploadConfirmRequestSerializer,
    APKUploadInitiateRequestSerializer,
    APKUploadInitiateResponseSerializer,
    AnalyzerMetadataSerializer,
    AnalysisJobSerializer,
    AuditSerializer,
    ComplianceScoreSerializer,
    EvidenceSerializer,
    FindingSerializer,
    ObjectStorageReferenceSerializer,
    NormalizedArtifactSerializer,
    ProjectSerializer,
    RawAnalyzerResultSerializer,
    ReportSerializer,
    RiskScoreSerializer,
    SuspiciousIndicatorSerializer,
)
from apps.analyzers.models import RawAnalyzerResult
from apps.analyzers.services.registry import AnalyzerRegistry
from apps.apk_files.models import APKFile
from apps.audits.models import AnalysisJob, Audit
from apps.audits.tasks import analyze_audit_placeholder
from apps.evidence.models import Evidence
from apps.findings.models import Finding
from apps.indicators.models import SuspiciousIndicator
from apps.normalization.models import NormalizedArtifact
from apps.projects.models import Project
from apps.reports.models import Report
from apps.reports.services.json_report import generate_json_report
from apps.scoring.models import ComplianceScore, RiskScore
from apps.storage.models import ObjectStorageReference
from apps.storage.services.minio_storage import MinIOStorageService


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


class AnalyzerRegistryView(APIView):
    @extend_schema(responses=AnalyzerMetadataSerializer(many=True))
    def get(self, request):
        return Response(AnalyzerRegistry().get_analyzer_metadata())


class ProjectViewSet(viewsets.ModelViewSet):
    queryset = Project.objects.all()
    serializer_class = ProjectSerializer


class AuditViewSet(viewsets.ModelViewSet):
    queryset = Audit.objects.select_related("project").all()
    serializer_class = AuditSerializer
    active_analysis_statuses = {
        Audit.Status.ANALYSIS_QUEUED,
        Audit.Status.ANALYSIS_RUNNING,
    }

    @extend_schema(
        request=APKUploadInitiateRequestSerializer,
        responses={201: APKUploadInitiateResponseSerializer},
    )
    @action(detail=True, methods=["post"], url_path="apk-upload/initiate")
    def initiate_apk_upload(self, request, pk=None):
        audit = self.get_object()
        serializer = APKUploadInitiateRequestSerializer(
            data=request.data,
            context={"max_size_bytes": settings.MSAP_MAX_APK_SIZE_BYTES},
        )
        serializer.is_valid(raise_exception=True)

        storage_service = MinIOStorageService()
        bucket = storage_service.get_apk_upload_bucket()
        object_key = storage_service.build_object_key(
            project_id=audit.project_id,
            audit_id=audit.id,
            object_type=ObjectStorageReference.ObjectType.APK_UPLOAD,
            filename=serializer.validated_data["filename"],
        )
        expires_in = settings.MSAP_PRESIGNED_URL_EXPIRES_SECONDS
        upload_url = storage_service.generate_presigned_upload_url(
            bucket=bucket,
            object_key=object_key,
            content_type=serializer.validated_data["content_type"],
            expires_in=expires_in,
        )

        with transaction.atomic():
            storage_reference = ObjectStorageReference.objects.create(
                project=audit.project,
                audit=audit,
                bucket=bucket,
                object_key=object_key,
                object_type=ObjectStorageReference.ObjectType.APK_UPLOAD,
                storage_status=ObjectStorageReference.StorageStatus.PENDING_UPLOAD,
                content_type=serializer.validated_data["content_type"],
                size_bytes=serializer.validated_data["size_bytes"],
                sha256=serializer.validated_data.get("sha256", ""),
            )
            apk_file = APKFile.objects.create(
                audit=audit,
                storage_reference=storage_reference,
                size_bytes=serializer.validated_data["size_bytes"],
                sha256=serializer.validated_data.get("sha256", ""),
            )

        response = {
            "apk_file_id": apk_file.id,
            "storage_reference_id": storage_reference.id,
            "bucket": bucket,
            "object_key": object_key,
            "upload_url": upload_url,
            "expires_in": expires_in,
            "required_headers": {
                "Content-Type": serializer.validated_data["content_type"],
            },
        }
        return Response(response, status=status.HTTP_201_CREATED)

    @extend_schema(
        responses=inline_serializer(
            name="AnalysisStartResponse",
            fields={
                "audit_id": serializers.IntegerField(),
                "analysis_job_id": serializers.IntegerField(),
                "task_id": serializers.CharField(),
                "status": serializers.CharField(),
            },
        )
    )
    @action(detail=True, methods=["post"], url_path="analysis/start")
    def start_analysis(self, request, pk=None):
        audit = self.get_object()

        if not audit.apk_files.exists():
            return Response(
                {"detail": "Audit must have at least one APK file before analysis."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        latest_job = audit.analysis_jobs.order_by("-created_at").first()
        active_job_statuses = {AnalysisJob.Status.QUEUED, AnalysisJob.Status.RUNNING}
        if audit.status in self.active_analysis_statuses or (
            latest_job is not None and latest_job.status in active_job_statuses
        ):
            return Response(
                {"detail": "Analysis is already queued or running for this audit."},
                status=status.HTTP_409_CONFLICT,
            )

        with transaction.atomic():
            audit = Audit.objects.select_for_update().get(id=audit.id)
            latest_job = audit.analysis_jobs.order_by("-created_at").first()
            if audit.status in self.active_analysis_statuses or (
                latest_job is not None and latest_job.status in active_job_statuses
            ):
                return Response(
                    {"detail": "Analysis is already queued or running for this audit."},
                    status=status.HTTP_409_CONFLICT,
                )

            analysis_job = AnalysisJob.objects.create(
                audit=audit,
                status=AnalysisJob.Status.QUEUED,
            )
            audit.status = Audit.Status.ANALYSIS_QUEUED
            audit.save(update_fields=["status", "updated_at"])

        task_result = analyze_audit_placeholder.delay(audit.id)
        analysis_job.task_id = task_result.id or ""
        analysis_job.save(update_fields=["task_id", "updated_at"])
        audit.refresh_from_db(fields=["status"])

        response = {
            "audit_id": audit.id,
            "analysis_job_id": analysis_job.id,
            "task_id": analysis_job.task_id,
            "status": audit.status,
        }
        return Response(response, status=status.HTTP_202_ACCEPTED)

    @extend_schema(
        responses=inline_serializer(
            name="AnalysisStatusResponse",
            fields={
                "audit_id": serializers.IntegerField(),
                "audit_status": serializers.CharField(),
                "latest_job": serializers.DictField(allow_null=True),
            },
        )
    )
    @action(detail=True, methods=["get"], url_path="analysis/status")
    def analysis_status(self, request, pk=None):
        audit = self.get_object()
        latest_job = audit.analysis_jobs.order_by("-created_at").first()

        response = {
            "audit_id": audit.id,
            "audit_status": audit.status,
            "latest_job": (
                AnalysisJobSerializer(latest_job).data
                if latest_job is not None
                else None
            ),
        }
        return Response(response)

    @extend_schema(responses=serializers.DictField())
    @action(detail=True, methods=["get"], url_path="report/json")
    def json_report(self, request, pk=None):
        audit = self.get_object()
        return Response(generate_json_report(audit.id))


class APKFileViewSet(viewsets.ModelViewSet):
    queryset = APKFile.objects.select_related("audit", "storage_reference").all()
    serializer_class = APKFileSerializer

    @extend_schema(
        request=APKUploadConfirmRequestSerializer,
        responses={200: APKFileSerializer},
    )
    @action(detail=True, methods=["post"], url_path="confirm-upload")
    def confirm_upload(self, request, pk=None):
        apk_file = self.get_object()
        serializer = APKUploadConfirmRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        storage_reference = apk_file.storage_reference
        if storage_reference is None:
            return Response(
                {"detail": "APK file has no storage reference."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if settings.MSAP_VERIFY_UPLOAD_WITH_HEAD:
            storage_service = MinIOStorageService()
            metadata = storage_service.head_object(
                storage_reference.bucket,
                storage_reference.object_key,
            )
            storage_reference.storage_status = (
                ObjectStorageReference.StorageStatus.VERIFIED
            )
            if not serializer.validated_data.get("size_bytes"):
                serializer.validated_data["size_bytes"] = metadata.get("ContentLength")
        else:
            storage_reference.storage_status = ObjectStorageReference.StorageStatus.UPLOADED

        if "size_bytes" in serializer.validated_data:
            apk_file.size_bytes = serializer.validated_data["size_bytes"]
            storage_reference.size_bytes = serializer.validated_data["size_bytes"]
        if "sha256" in serializer.validated_data:
            apk_file.sha256 = serializer.validated_data["sha256"]
            storage_reference.sha256 = serializer.validated_data["sha256"]

        storage_reference.save(
            update_fields=["storage_status", "size_bytes", "sha256", "updated_at"]
        )
        apk_file.save(update_fields=["size_bytes", "sha256"])

        return Response(APKFileSerializer(apk_file).data)


class ObjectStorageReferenceViewSet(viewsets.ModelViewSet):
    queryset = ObjectStorageReference.objects.select_related("project", "audit").all()
    serializer_class = ObjectStorageReferenceSerializer


class AuditScopedQuerysetMixin:
    def get_queryset(self):
        queryset = super().get_queryset()
        audit_id = self.request.query_params.get("audit")
        if audit_id:
            queryset = queryset.filter(audit_id=audit_id)
        return queryset


class FindingViewSet(AuditScopedQuerysetMixin, viewsets.ReadOnlyModelViewSet):
    queryset = Finding.objects.select_related("audit").all()
    serializer_class = FindingSerializer


class RawAnalyzerResultViewSet(
    AuditScopedQuerysetMixin,
    viewsets.ReadOnlyModelViewSet,
):
    queryset = RawAnalyzerResult.objects.select_related(
        "audit",
        "apk_file",
        "storage_reference",
    ).all()
    serializer_class = RawAnalyzerResultSerializer


class NormalizedArtifactViewSet(
    AuditScopedQuerysetMixin,
    viewsets.ReadOnlyModelViewSet,
):
    queryset = NormalizedArtifact.objects.select_related(
        "audit",
        "apk_file",
        "storage_reference",
    ).all()
    serializer_class = NormalizedArtifactSerializer


class SuspiciousIndicatorViewSet(
    AuditScopedQuerysetMixin,
    viewsets.ReadOnlyModelViewSet,
):
    queryset = SuspiciousIndicator.objects.select_related("audit").all()
    serializer_class = SuspiciousIndicatorSerializer


class EvidenceViewSet(AuditScopedQuerysetMixin, viewsets.ReadOnlyModelViewSet):
    queryset = Evidence.objects.select_related(
        "audit",
        "finding",
        "indicator",
        "storage_reference",
    ).all()
    serializer_class = EvidenceSerializer


class RiskScoreViewSet(AuditScopedQuerysetMixin, viewsets.ReadOnlyModelViewSet):
    queryset = RiskScore.objects.select_related("audit").all()
    serializer_class = RiskScoreSerializer


class ComplianceScoreViewSet(
    AuditScopedQuerysetMixin,
    viewsets.ReadOnlyModelViewSet,
):
    queryset = ComplianceScore.objects.select_related("audit").all()
    serializer_class = ComplianceScoreSerializer


class ReportViewSet(AuditScopedQuerysetMixin, viewsets.ReadOnlyModelViewSet):
    queryset = Report.objects.select_related("audit", "storage_reference").all()
    serializer_class = ReportSerializer
