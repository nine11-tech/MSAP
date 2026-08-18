import logging
from botocore.exceptions import BotoCoreError, ClientError

from drf_spectacular.utils import extend_schema, inline_serializer
from drf_spectacular.types import OpenApiTypes
from django.conf import settings
from django.db import transaction
from django.http import HttpResponse
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
    FindingSourceReferenceSerializer,
    FindingSerializer,
    ObjectStorageReferenceSerializer,
    NormalizedArtifactSerializer,
    ProjectSerializer,
    RawAnalyzerResultSerializer,
    ReportSerializer,
    RiskScoreSerializer,
    RuleEvaluationSerializer,
    SuspiciousIndicatorSerializer,
    SourceDocumentSerializer,
)
from apps.api.permissions import (
    IsMSAPAnalystOrAdmin,
    IsMSAPViewerOrAbove,
    IsReadOnlyViewerOrAbove,
)
from apps.api.renderers import PDFRenderer
from apps.api.roles import user_role
from apps.api.services.system_status import (
    collect_system_status,
    serialize_system_status,
)
from apps.analyzers.models import RawAnalyzerResult
from apps.analyzers.services.registry import AnalyzerRegistry
from apps.appsec_rules.models import RuleEvaluation
from apps.appsec_rules.services.coverage import calculate_rule_coverage
from apps.apk_files.models import APKFile
from apps.audits.models import AnalysisJob, Audit
from apps.audits.tasks import analyze_audit_placeholder
from apps.dynamic_analysis.serializers import FindingValidationMissionSerializer
from apps.dynamic_analysis.services.finding_validation_missions import (
    FindingValidationMissionError,
    generate_finding_validation_mission,
)
from apps.evidence.models import Evidence, SourceDocument
from apps.evidence.services.source_content import (
    SourceDocumentContentError,
    SourceDocumentContentService,
)
from apps.findings.models import Finding
from apps.indicators.models import SuspiciousIndicator
from apps.normalization.models import NormalizedArtifact
from apps.projects.models import Project
from apps.reports.models import Report
from apps.reports.services.json_report import generate_json_report
from apps.reports.services.pdf_report import build_pdf_filename, generate_pdf_report
from apps.scoring.models import ComplianceScore, RiskScore
from apps.storage.models import ObjectStorageReference
from apps.storage.services.minio_storage import MinIOStorageService


logger = logging.getLogger(__name__)


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
    permission_classes = [IsMSAPViewerOrAbove]

    @extend_schema(responses=AnalyzerMetadataSerializer(many=True))
    def get(self, request):
        return Response(AnalyzerRegistry().get_analyzer_metadata())


class SystemStatusView(APIView):
    permission_classes = [IsMSAPViewerOrAbove]

    @extend_schema(responses=serializers.DictField())
    def get(self, request):
        force = request.query_params.get("refresh", "").lower() in {
            "1",
            "true",
            "yes",
        }
        result = collect_system_status(force=force)
        return Response(
            serialize_system_status(
                result,
                include_admin_details=user_role(request.user) == "ADMIN",
            )
        )


class ProjectViewSet(viewsets.ModelViewSet):
    queryset = Project.objects.all()
    serializer_class = ProjectSerializer
    permission_classes = [IsReadOnlyViewerOrAbove]


class AuditViewSet(viewsets.ModelViewSet):
    queryset = Audit.objects.select_related("project").all()
    serializer_class = AuditSerializer
    permission_classes = [IsReadOnlyViewerOrAbove]
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
            context={
                "max_size_bytes": settings.MSAP_MAX_APK_SIZE_BYTES,
                "require_sha256": settings.MSAP_UPLOAD_REQUIRE_SHA256,
            },
        )
        serializer.is_valid(raise_exception=True)

        storage_service = MinIOStorageService()
        if storage_service.public_endpoint_hostname() == "minio":
            return Response(
                {
                    "detail": (
                        "The browser object-storage endpoint is configured as the "
                        "Docker-only host minio. Set MINIO_PUBLIC_ENDPOINT to a "
                        "browser-reachable URL such as http://127.0.0.1:9000."
                    )
                },
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
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
            sha256=serializer.validated_data.get("sha256", ""),
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
                **(
                    {"x-amz-meta-sha256": serializer.validated_data["sha256"]}
                    if serializer.validated_data.get("sha256")
                    else {}
                ),
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
    @action(detail=True, methods=["get"], url_path="coverage")
    def coverage(self, request, pk=None):
        audit = self.get_object()
        return Response(calculate_rule_coverage(audit.id))

    @extend_schema(responses=serializers.DictField())
    @action(detail=True, methods=["get"], url_path="report/json")
    def json_report(self, request, pk=None):
        audit = self.get_object()
        return Response(generate_json_report(audit.id))

    @extend_schema(
        responses={
            (200, "application/pdf"): OpenApiTypes.BINARY,
            500: inline_serializer(
                name="PdfReportError",
                fields={"detail": serializers.CharField()},
            ),
        }
    )
    @action(
        detail=True,
        methods=["get"],
        url_path="report/pdf",
        renderer_classes=[PDFRenderer],
    )
    def pdf_report(self, request, pk=None):
        audit = self.get_object()
        try:
            pdf_bytes = generate_pdf_report(audit.id)
        except Exception:
            logger.exception("PDF report generation failed for audit %s", audit.id)
            return Response(
                {"detail": "PDF report generation failed."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        filename = build_pdf_filename(audit.project.name, audit.id)
        response = HttpResponse(pdf_bytes, content_type="application/pdf")
        response["Content-Disposition"] = f'attachment; filename="{filename}"'
        return response


class APKFileViewSet(viewsets.ModelViewSet):
    queryset = APKFile.objects.select_related("audit", "storage_reference").all()
    serializer_class = APKFileSerializer
    permission_classes = [IsReadOnlyViewerOrAbove]

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

        storage_service = MinIOStorageService()
        try:
            metadata = storage_service.head_object(
                storage_reference.bucket,
                storage_reference.object_key,
            )
        except (BotoCoreError, ClientError, OSError):
            return Response(
                {
                    "detail": (
                        "The uploaded APK object could not be verified in object "
                        "storage. Complete the browser PUT and retry confirmation."
                    )
                },
                status=status.HTTP_409_CONFLICT,
            )

        actual_size = metadata.get("ContentLength")
        expected_size = storage_reference.size_bytes
        confirmed_size = serializer.validated_data.get("size_bytes")
        if (
            not isinstance(actual_size, int)
            or actual_size <= 0
            or (expected_size is not None and actual_size != expected_size)
            or (confirmed_size is not None and actual_size != confirmed_size)
        ):
            return Response(
                {"detail": "Uploaded APK object size does not match the upload contract."},
                status=status.HTTP_409_CONFLICT,
            )

        actual_content_type = str(metadata.get("ContentType") or "").split(";", 1)[0]
        if actual_content_type != storage_reference.content_type:
            return Response(
                {"detail": "Uploaded APK content type does not match the upload contract."},
                status=status.HTTP_409_CONFLICT,
            )

        expected_sha256 = storage_reference.sha256.strip().lower()
        confirmed_sha256 = serializer.validated_data.get("sha256", "")
        object_sha256 = str((metadata.get("Metadata") or {}).get("sha256") or "").lower()
        if expected_sha256 and confirmed_sha256 and confirmed_sha256 != expected_sha256:
            return Response(
                {"detail": "Confirmed APK SHA-256 does not match the upload contract."},
                status=status.HTTP_409_CONFLICT,
            )
        if expected_sha256 and object_sha256 != expected_sha256:
            return Response(
                {"detail": "Uploaded APK SHA-256 metadata does not match the upload contract."},
                status=status.HTTP_409_CONFLICT,
            )

        storage_reference.storage_status = ObjectStorageReference.StorageStatus.VERIFIED
        serializer.validated_data["size_bytes"] = actual_size
        if expected_sha256:
            serializer.validated_data["sha256"] = expected_sha256

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
    permission_classes = [IsReadOnlyViewerOrAbove]


class AuditScopedQuerysetMixin:
    def get_queryset(self):
        queryset = super().get_queryset()
        audit_id = self.request.query_params.get("audit")
        if audit_id:
            queryset = queryset.filter(audit_id=audit_id)
        return queryset


class FindingViewSet(AuditScopedQuerysetMixin, viewsets.ReadOnlyModelViewSet):
    queryset = Finding.objects.select_related("audit").prefetch_related(
        "source_references"
    ).all()
    serializer_class = FindingSerializer
    permission_classes = [IsMSAPViewerOrAbove]

    def get_permissions(self):
        permission_classes = (
            [IsMSAPAnalystOrAdmin]
            if self.action in {"generate_dynamic_validation"}
            else [IsMSAPViewerOrAbove]
        )
        return [permission() for permission in permission_classes]

    @action(detail=True, methods=["get"], url_path="source-references")
    def source_references(self, request, pk=None):
        finding = self.get_object()
        references = finding.source_references.select_related(
            "source_document"
        ).all()
        return Response(FindingSourceReferenceSerializer(references, many=True).data)

    @extend_schema(request=serializers.DictField(), responses={201: FindingValidationMissionSerializer})
    @action(detail=True, methods=["post"], url_path="dynamic-validation/generate")
    def generate_dynamic_validation(self, request, pk=None):
        if not isinstance(request.data, dict):
            return Response(
                {"detail": "Request body must be a JSON object."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        unexpected = sorted(set(request.data) - set())
        if unexpected:
            return Response(
                {key: "This field is not permitted." for key in unexpected},
                status=status.HTTP_400_BAD_REQUEST,
            )
        finding = self.get_object()
        try:
            mission = generate_finding_validation_mission(
                finding=finding,
                requested_by=request.user,
            )
        except FindingValidationMissionError as exc:
            return Response(
                {"code": exc.code, "detail": str(exc)},
                status=exc.http_status,
            )
        except Exception as exc:
            code = getattr(exc, "code", "MISSION_GENERATION_FAILED")
            http_status = getattr(exc, "http_status", status.HTTP_503_SERVICE_UNAVAILABLE)
            return Response(
                {"code": code, "detail": str(exc)},
                status=http_status,
            )
        return Response(
            FindingValidationMissionSerializer(
                mission,
                context={"request": request},
            ).data,
            status=status.HTTP_201_CREATED,
        )


class SourceDocumentViewSet(
    AuditScopedQuerysetMixin,
    viewsets.ReadOnlyModelViewSet,
):
    queryset = SourceDocument.objects.select_related(
        "audit",
        "apk_file",
        "storage_reference",
    ).all()
    serializer_class = SourceDocumentSerializer
    permission_classes = [IsMSAPViewerOrAbove]

    @action(detail=True, methods=["get"], url_path="lines")
    def lines(self, request, pk=None):
        document = self.get_object()
        try:
            start_line = int(request.query_params.get("start", "1"))
            default_end = min(
                document.line_count,
                start_line + settings.MSAP_SOURCE_LINE_RANGE_LIMIT - 1,
            )
            end_line = int(request.query_params.get("end", str(default_end)))
            lines = SourceDocumentContentService().read_lines(
                document,
                start_line,
                end_line,
            )
        except (TypeError, ValueError) as exc:
            return Response(
                {"detail": str(exc) or "Invalid source line range."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except SourceDocumentContentError as exc:
            return Response(
                {"detail": str(exc)},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        return Response(
            {
                "document": SourceDocumentSerializer(document).data,
                "start_line": start_line,
                "end_line": end_line,
                "lines": lines,
                "redaction_applied": True,
            }
        )


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
    permission_classes = [IsMSAPViewerOrAbove]


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
    permission_classes = [IsMSAPViewerOrAbove]


class SuspiciousIndicatorViewSet(
    AuditScopedQuerysetMixin,
    viewsets.ReadOnlyModelViewSet,
):
    queryset = SuspiciousIndicator.objects.select_related("audit").all()
    serializer_class = SuspiciousIndicatorSerializer
    permission_classes = [IsMSAPViewerOrAbove]


class EvidenceViewSet(AuditScopedQuerysetMixin, viewsets.ReadOnlyModelViewSet):
    queryset = Evidence.objects.select_related(
        "audit",
        "finding",
        "indicator",
        "storage_reference",
        "agent_run",
        "agent_run_step",
        "agent_run_artifact",
    ).all()
    serializer_class = EvidenceSerializer
    permission_classes = [IsMSAPViewerOrAbove]


class RiskScoreViewSet(AuditScopedQuerysetMixin, viewsets.ReadOnlyModelViewSet):
    queryset = RiskScore.objects.select_related("audit").all()
    serializer_class = RiskScoreSerializer
    permission_classes = [IsMSAPViewerOrAbove]


class ComplianceScoreViewSet(
    AuditScopedQuerysetMixin,
    viewsets.ReadOnlyModelViewSet,
):
    queryset = ComplianceScore.objects.select_related("audit").all()
    serializer_class = ComplianceScoreSerializer
    permission_classes = [IsMSAPViewerOrAbove]


class ReportViewSet(AuditScopedQuerysetMixin, viewsets.ReadOnlyModelViewSet):
    queryset = Report.objects.select_related("audit", "storage_reference").all()
    serializer_class = ReportSerializer
    permission_classes = [IsMSAPViewerOrAbove]


class RuleEvaluationViewSet(
    AuditScopedQuerysetMixin,
    viewsets.ReadOnlyModelViewSet,
):
    queryset = RuleEvaluation.objects.select_related("audit").all()
    serializer_class = RuleEvaluationSerializer
    permission_classes = [IsMSAPViewerOrAbove]
