from django.conf import settings
from django.db.models import Max
from django.utils import timezone
from drf_spectacular.utils import extend_schema
from rest_framework import mixins, status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from apps.api.permissions import (
    IsMSAPAnalystOrAdmin,
    IsMSAPViewerOrAbove,
    IsReadOnlyViewerOrAbove,
)
from apps.dynamic_analysis.models import (
    DynamicAnalysisJob,
    DynamicDevice,
    DynamicDeviceCapability,
    DynamicDeviceEvent,
    DynamicDeviceLease,
    DynamicDevicePool,
    DynamicEmulatorSnapshot,
    DynamicSession,
    DynamicSessionArtifact,
    DynamicSessionEvent,
    DynamicSessionStage,
)
from apps.dynamic_analysis.serializers import (
    DynamicAnalysisJobSerializer,
    DynamicDeviceCapabilitySerializer,
    DynamicDeviceEventSerializer,
    DynamicDeviceHealthUpdateSerializer,
    DynamicDeviceLeaseCreateSerializer,
    DynamicDeviceLeaseReleaseSerializer,
    DynamicDeviceLeaseSerializer,
    DynamicDevicePoolSerializer,
    DynamicDeviceQuarantineSerializer,
    DynamicDeviceSerializer,
    DynamicEmulatorSnapshotSerializer,
    DynamicSessionArtifactSerializer,
    DynamicSessionEventSerializer,
    DynamicSessionSerializer,
    DynamicSessionStageSerializer,
    DynamicSessionTransitionSerializer,
)
from apps.dynamic_analysis.services.health import (
    DynamicHealthPayloadError,
    update_device_health,
)
from apps.dynamic_analysis.services.leases import (
    DynamicLeaseError,
    create_lease,
    find_available_device,
    quarantine_device,
    release_lease,
)
from apps.dynamic_analysis.services.state_machine import (
    DynamicStateTransitionError,
    transition_session,
)
from apps.dynamic_analysis.tasks import run_dynamic_mvp_job_task


class DynamicFilterMixin:
    filter_fields: tuple[str, ...] = ()

    def get_queryset(self):
        queryset = super().get_queryset()
        for field in self.filter_fields:
            value = self.request.query_params.get(field)
            if value:
                queryset = queryset.filter(**{field: value})
        return queryset


class DynamicDevicePoolViewSet(DynamicFilterMixin, viewsets.ModelViewSet):
    queryset = DynamicDevicePool.objects.all()
    serializer_class = DynamicDevicePoolSerializer
    permission_classes = [IsReadOnlyViewerOrAbove]
    filter_fields = ("slug", "is_active")


class DynamicDeviceViewSet(DynamicFilterMixin, viewsets.ModelViewSet):
    queryset = DynamicDevice.objects.select_related("pool").all()
    serializer_class = DynamicDeviceSerializer
    permission_classes = [IsReadOnlyViewerOrAbove]
    filter_fields = ("pool", "status", "abi", "api_level")

    @extend_schema(
        request=DynamicDeviceQuarantineSerializer,
        responses={200: DynamicDeviceSerializer},
    )
    @action(detail=True, methods=["post"], url_path="quarantine")
    def quarantine(self, request, pk=None):
        device = self.get_object()
        serializer = DynamicDeviceQuarantineSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            device = quarantine_device(
                device,
                reason=serializer.validated_data["reason"],
                created_by=request.user,
            )
        except DynamicLeaseError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        return Response(self.get_serializer(device).data)

    @extend_schema(responses={200: DynamicDeviceSerializer})
    @action(detail=True, methods=["post"], url_path="mark-available")
    def mark_available(self, request, pk=None):
        device = self.get_object()
        if DynamicDeviceLease.objects.filter(
            device=device,
            lease_status=DynamicDeviceLease.LeaseStatus.ACTIVE,
        ).exists():
            return Response(
                {"detail": "Device has an active lease."},
                status=status.HTTP_409_CONFLICT,
            )
        previous_status = device.status
        device.status = DynamicDevice.Status.AVAILABLE
        device.quarantine_reason = ""
        device.save(update_fields=["status", "quarantine_reason", "updated_at"])
        DynamicDeviceEvent.objects.create(
            device=device,
            event_type=DynamicDeviceEvent.EventType.STATUS_CHANGE,
            severity=DynamicDeviceEvent.Severity.INFO,
            message="Device marked available by operator.",
            created_by=request.user,
            metadata={
                "previous_status": previous_status,
                "new_status": device.status,
            },
        )
        return Response(self.get_serializer(device).data)

    @extend_schema(
        request=DynamicDeviceHealthUpdateSerializer,
        responses={200: DynamicDeviceSerializer},
    )
    @action(detail=True, methods=["post"], url_path="health")
    def health(self, request, pk=None):
        device = self.get_object()
        serializer = DynamicDeviceHealthUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            device = update_device_health(device, serializer.validated_data)
        except DynamicHealthPayloadError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        return Response(self.get_serializer(device).data)


class DynamicDeviceCapabilityViewSet(
    DynamicFilterMixin,
    viewsets.ReadOnlyModelViewSet,
):
    queryset = DynamicDeviceCapability.objects.select_related("device").all()
    serializer_class = DynamicDeviceCapabilitySerializer
    permission_classes = [IsMSAPViewerOrAbove]
    filter_fields = ("device", "capability_type", "is_available")


class DynamicEmulatorSnapshotViewSet(DynamicFilterMixin, viewsets.ModelViewSet):
    queryset = DynamicEmulatorSnapshot.objects.select_related("device").all()
    serializer_class = DynamicEmulatorSnapshotSerializer
    permission_classes = [IsReadOnlyViewerOrAbove]
    filter_fields = ("device", "snapshot_type", "validation_status", "api_level", "abi")


class DynamicDeviceLeaseViewSet(
    DynamicFilterMixin,
    mixins.CreateModelMixin,
    viewsets.ReadOnlyModelViewSet,
):
    queryset = DynamicDeviceLease.objects.select_related(
        "device",
        "audit",
        "job",
        "leased_by",
    ).all()
    serializer_class = DynamicDeviceLeaseSerializer
    permission_classes = [IsReadOnlyViewerOrAbove]
    filter_fields = ("device", "audit", "job", "lease_status")

    @extend_schema(
        request=DynamicDeviceLeaseCreateSerializer,
        responses={201: DynamicDeviceLeaseSerializer},
    )
    def create(self, request, *args, **kwargs):
        serializer = DynamicDeviceLeaseCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        device = data.get("device")
        if device is None:
            device = find_available_device(
                pool=data.get("pool"),
                api_level=data.get("api_level"),
                abi=data.get("abi"),
                capabilities=data.get("capabilities"),
            )
            if device is None:
                return Response(
                    {"detail": "No available dynamic device matched the request."},
                    status=status.HTTP_409_CONFLICT,
                )

        try:
            lease = create_lease(
                device=device,
                audit=data["audit"],
                job=data.get("job"),
                leased_by=request.user,
                ttl_minutes=data.get("ttl_minutes", 60),
            )
        except DynamicLeaseError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_409_CONFLICT)
        return Response(
            self.get_serializer(lease).data,
            status=status.HTTP_201_CREATED,
        )

    @extend_schema(
        request=DynamicDeviceLeaseReleaseSerializer,
        responses={200: DynamicDeviceLeaseSerializer},
    )
    @action(detail=True, methods=["post"], url_path="release")
    def release(self, request, pk=None):
        lease = self.get_object()
        serializer = DynamicDeviceLeaseReleaseSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            lease = release_lease(
                lease,
                reason=serializer.validated_data["reason"],
                released_by=request.user,
            )
        except DynamicLeaseError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        return Response(self.get_serializer(lease).data)


class DynamicDeviceEventViewSet(DynamicFilterMixin, viewsets.ReadOnlyModelViewSet):
    queryset = DynamicDeviceEvent.objects.select_related(
        "device",
        "lease",
        "created_by",
    ).all()
    serializer_class = DynamicDeviceEventSerializer
    permission_classes = [IsMSAPViewerOrAbove]
    filter_fields = ("device", "lease", "event_type", "severity")


class DynamicAnalysisJobViewSet(DynamicFilterMixin, viewsets.ModelViewSet):
    queryset = DynamicAnalysisJob.objects.select_related(
        "audit",
        "apk",
        "requested_by",
        "requested_device_pool",
    ).all()
    serializer_class = DynamicAnalysisJobSerializer
    permission_classes = [IsReadOnlyViewerOrAbove]
    filter_fields = ("audit", "status", "requested_device_pool")

    @extend_schema(responses={200: DynamicAnalysisJobSerializer})
    @action(detail=True, methods=["post"], url_path="cancel")
    def cancel(self, request, pk=None):
        job = self.get_object()
        if job.status in {
            DynamicAnalysisJob.Status.COMPLETED,
            DynamicAnalysisJob.Status.FAILED,
            DynamicAnalysisJob.Status.CANCELLED,
        }:
            return Response(self.get_serializer(job).data)

        job.status = DynamicAnalysisJob.Status.CANCELLED
        job.failure_category = DynamicAnalysisJob.FailureCategory.OPERATOR_CANCELLED
        job.failure_message = "Dynamic analysis job cancelled by operator."
        job.finished_at = timezone.now()
        job.save(
            update_fields=[
                "status",
                "failure_category",
                "failure_message",
                "finished_at",
                "updated_at",
            ]
        )
        return Response(self.get_serializer(job).data)

    @extend_schema(responses={202: DynamicAnalysisJobSerializer})
    @action(
        detail=True,
        methods=["post"],
        url_path="run-mvp",
        permission_classes=[IsMSAPAnalystOrAdmin],
    )
    def run_mvp(self, request, pk=None):
        if not settings.MSAP_DYNAMIC_RUNNER_ENABLED:
            return Response(
                {"detail": "Dynamic MVP runner is disabled."},
                status=status.HTTP_409_CONFLICT,
            )

        job = self.get_object()
        if job.status not in {
            DynamicAnalysisJob.Status.QUEUED,
            DynamicAnalysisJob.Status.RUNNING,
        }:
            return Response(
                {"detail": f"Dynamic job cannot run from status {job.status}."},
                status=status.HTTP_409_CONFLICT,
            )

        include_platform_tls_probe = _request_bool(
            request.data,
            "include_platform_tls_probe",
        )
        if (
            include_platform_tls_probe
            and not settings.MSAP_DYNAMIC_PLATFORM_TLS_PROBE_ENABLED
        ):
            return Response(
                {"detail": "Platform TLS probe is disabled by settings."},
                status=status.HTTP_409_CONFLICT,
            )

        async_result = run_dynamic_mvp_job_task.delay(
            job.id,
            include_platform_tls_probe=include_platform_tls_probe,
        )
        return Response(
            {
                "job": self.get_serializer(job).data,
                "task_id": async_result.id,
                "include_platform_tls_probe": include_platform_tls_probe,
            },
            status=status.HTTP_202_ACCEPTED,
        )


class DynamicSessionViewSet(DynamicFilterMixin, viewsets.ReadOnlyModelViewSet):
    queryset = DynamicSession.objects.select_related(
        "job",
        "audit",
        "apk",
        "device",
        "lease",
        "snapshot",
    ).all()
    serializer_class = DynamicSessionSerializer
    permission_classes = [IsReadOnlyViewerOrAbove]
    filter_fields = ("audit", "job", "device", "state")

    @extend_schema(
        request=DynamicSessionTransitionSerializer,
        responses={200: DynamicSessionSerializer},
    )
    @action(detail=True, methods=["post"], url_path="transition")
    def transition(self, request, pk=None):
        session = self.get_object()
        serializer = DynamicSessionTransitionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            session = transition_session(
                session,
                serializer.validated_data["new_state"],
                reason=serializer.validated_data.get("reason"),
            )
        except DynamicStateTransitionError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        return Response(self.get_serializer(session).data)


class DynamicSessionStageViewSet(DynamicFilterMixin, viewsets.ReadOnlyModelViewSet):
    queryset = DynamicSessionStage.objects.select_related("session").all()
    serializer_class = DynamicSessionStageSerializer
    permission_classes = [IsMSAPViewerOrAbove]
    filter_fields = ("session", "state", "status")


class DynamicSessionEventViewSet(DynamicFilterMixin, viewsets.ReadOnlyModelViewSet):
    queryset = DynamicSessionEvent.objects.select_related("session").all()
    serializer_class = DynamicSessionEventSerializer
    permission_classes = [IsMSAPViewerOrAbove]
    filter_fields = ("session", "event_type", "severity")

    def get_queryset(self):
        queryset = super().get_queryset()
        latest_only = self.request.query_params.get("latest")
        if latest_only not in {"1", "true", "yes"}:
            return queryset

        latest_sequence = (
            DynamicSessionEvent.objects.filter(session_id=self.request.query_params.get("session"))
            .aggregate(max_sequence=Max("sequence_number"))
            .get("max_sequence")
        )
        if latest_sequence is None:
            return queryset.none()
        return queryset.filter(sequence_number=latest_sequence)


class DynamicSessionArtifactViewSet(
    DynamicFilterMixin,
    viewsets.ReadOnlyModelViewSet,
):
    queryset = DynamicSessionArtifact.objects.select_related(
        "session",
        "raw_reference",
    ).all()
    serializer_class = DynamicSessionArtifactSerializer
    permission_classes = [IsMSAPViewerOrAbove]
    filter_fields = (
        "session",
        "artifact_type",
        "category",
        "redaction_state",
        "confidence",
    )


def _request_bool(data, key: str) -> bool:
    value = data.get(key, False)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)
