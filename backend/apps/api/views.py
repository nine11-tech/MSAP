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


class ProjectViewSet(viewsets.ModelViewSet):
    queryset = Project.objects.all()
    serializer_class = ProjectSerializer


class AuditViewSet(viewsets.ModelViewSet):
    queryset = Audit.objects.select_related("project").all()
    serializer_class = AuditSerializer

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
        }
        return Response(response, status=status.HTTP_201_CREATED)


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
