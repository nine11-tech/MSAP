import logging
from hashlib import sha256

from django.conf import settings
from django.http import HttpResponse
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
from apps.apk_files.models import APKFile
from apps.audits.models import Audit
from apps.dynamic_analysis.models import (
    AgentRun,
    AgentRuntime,
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
from apps.dynamic_analysis.authentication import (
    AgentRunTokenAuthentication,
    IsAgentRunToken,
)
from apps.dynamic_analysis.serializers import (
    AgentRunArtifactSerializer,
    AgentRunCreateSerializer,
    AgentRunSerializer,
    AgentRuntimeSerializer,
    AgentRunStepSerializer,
    AgentToolCallSerializer,
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
    DynamicHostAgentInstallSerializer,
    DynamicHostAgentPackageActionSerializer,
    DynamicSessionArtifactSerializer,
    DynamicSessionEventSerializer,
    DynamicSessionSerializer,
    DynamicSessionStageSerializer,
    DynamicSessionTransitionSerializer,
)
from apps.dynamic_analysis.renderers import PNGRenderer
from apps.dynamic_analysis.services.host_agent_client import (
    DynamicHostAgentClient,
    HostAgentClientError,
)
from apps.dynamic_analysis.services.agent_controller import (
    AgentController,
    AgentControllerError,
    AgentControllerPermissionError,
)
from apps.dynamic_analysis.services.agent_gateway import (
    AgentGatewayRequestError,
    execute_run_tool_call,
)
from apps.dynamic_analysis.services.host_agent_sync import (
    fetch_and_sync_host_agent,
    record_host_agent_action,
)
from apps.dynamic_analysis.services.job_control import (
    DynamicJobControlError,
    cancel_queued_job,
    recover_stale_dynamic_jobs,
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
from apps.dynamic_analysis.services.mvp_runner import (
    DynamicMvpRunnerError,
    run_dynamic_mvp_job,
)
from apps.dynamic_analysis.services.runner_readiness import (
    get_dynamic_runner_readiness,
)
from apps.dynamic_analysis.tasks import run_dynamic_mvp_job_task
from apps.storage.services.file_provider import APKFileProvider, FileProviderError
from apps.storage.models import ObjectStorageReference


logger = logging.getLogger(__name__)


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

    def create(self, request, *args, **kwargs):
        readiness = get_dynamic_runner_readiness()
        if not readiness["ready"]:
            return Response(readiness, status=status.HTTP_503_SERVICE_UNAVAILABLE)
        return super().create(request, *args, **kwargs)

    @action(detail=False, methods=["get"], url_path="readiness")
    def readiness(self, request):
        return Response(get_dynamic_runner_readiness())

    @action(
        detail=False,
        methods=["post"],
        url_path="recover-stale",
        permission_classes=[IsMSAPAnalystOrAdmin],
    )
    def recover_stale(self, request):
        try:
            older_than_minutes = int(request.data.get("older_than_minutes", 5))
            result = recover_stale_dynamic_jobs(
                older_than_minutes=older_than_minutes,
            )
        except (TypeError, ValueError, DynamicJobControlError) as exc:
            return Response(
                {"detail": str(exc)},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return Response(result)

    @extend_schema(responses={200: DynamicAnalysisJobSerializer})
    @action(detail=True, methods=["post"], url_path="cancel")
    def cancel(self, request, pk=None):
        job = self.get_object()
        try:
            job = cancel_queued_job(job, requested_by=request.user)
        except DynamicJobControlError as exc:
            return Response(
                {"detail": str(exc)},
                status=status.HTTP_409_CONFLICT,
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

        readiness = get_dynamic_runner_readiness()
        if not readiness["ready"]:
            return Response(readiness, status=status.HTTP_503_SERVICE_UNAVAILABLE)

        job = self.get_object()
        if job.status != DynamicAnalysisJob.Status.QUEUED:
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

        if settings.MSAP_DYNAMIC_RUNNER_SYNC_DEMO_ENABLED:
            try:
                result = run_dynamic_mvp_job(
                    job.id,
                    include_platform_tls_probe=include_platform_tls_probe,
                )
            except DynamicMvpRunnerError as exc:
                return Response(
                    {"detail": str(exc), "code": "DYNAMIC_RUNNER_FAILED"},
                    status=status.HTTP_409_CONFLICT,
                )
            job.refresh_from_db()
            return Response(
                {
                    "job": self.get_serializer(job).data,
                    "task_id": None,
                    "execution_mode": "synchronous",
                    "include_platform_tls_probe": include_platform_tls_probe,
                    "result": result,
                }
            )

        try:
            async_result = run_dynamic_mvp_job_task.delay(
                job.id,
                include_platform_tls_probe=include_platform_tls_probe,
            )
        except Exception as exc:
            logger.warning(
                "Dynamic job enqueue failed job_id=%s error_type=%s",
                job.id,
                type(exc).__name__,
            )
            return Response(
                {
                    "detail": (
                        "The Celery worker readiness check passed, but the task "
                        "could not be queued. Check Redis and the worker, then retry."
                    ),
                    "code": "DYNAMIC_JOB_ENQUEUE_FAILED",
                },
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        return Response(
            {
                "job": self.get_serializer(job).data,
                "task_id": async_result.id,
                "execution_mode": "celery",
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


class AgentRuntimeViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = AgentRuntime.objects.all()
    serializer_class = AgentRuntimeSerializer
    permission_classes = [IsMSAPViewerOrAbove]


class AgentRunViewSet(
    DynamicFilterMixin,
    mixins.CreateModelMixin,
    viewsets.ReadOnlyModelViewSet,
):
    queryset = AgentRun.objects.select_related(
        "audit",
        "device",
        "runtime",
        "requested_by",
    ).all()
    serializer_class = AgentRunSerializer
    permission_classes = [IsMSAPViewerOrAbove]
    filter_fields = ("audit", "status", "objective", "requested_by")

    def get_permissions(self):
        if self.action == "tool_call":
            permission_classes = [IsAgentRunToken]
        elif self.action == "create":
            permission_classes = [IsMSAPAnalystOrAdmin]
        else:
            permission_classes = [IsMSAPViewerOrAbove]
        return [permission() for permission in permission_classes]

    @extend_schema(
        request=AgentRunCreateSerializer,
        responses={201: AgentRunSerializer},
    )
    def create(self, request, *args, **kwargs):
        serializer = AgentRunCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            run = AgentController().run(
                objective=serializer.validated_data["objective"],
                audit=serializer.validated_data.get("audit"),
                requested_by=request.user,
                runtime_type=serializer.validated_data["runtime_type"],
            )
        except AgentControllerPermissionError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_403_FORBIDDEN)
        except AgentControllerError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        return Response(
            AgentRunSerializer(run, context={"request": request}).data,
            status=status.HTTP_201_CREATED,
        )

    @extend_schema(
        request=AgentToolCallSerializer,
        responses={200: dict},
    )
    @action(
        detail=True,
        methods=["post"],
        url_path="tool-call",
        authentication_classes=[AgentRunTokenAuthentication],
    )
    def tool_call(self, request, pk=None):
        serializer = AgentToolCallSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            result = execute_run_tool_call(
                run_id=int(pk),
                tool_name=serializer.validated_data["tool_name"],
                arguments=serializer.validated_data["arguments"],
            )
        except AgentGatewayRequestError as exc:
            return Response(
                {"code": exc.code, "detail": str(exc)},
                status=exc.http_status,
            )
        except Exception as exc:  # pragma: no cover - defensive API boundary
            logger.error(
                "agent_gateway_request_failed run_id=%s error_type=%s",
                pk,
                type(exc).__name__,
            )
            return Response(
                {
                    "code": "AGENT_GATEWAY_ERROR",
                    "detail": "The restricted tool gateway failed unexpectedly.",
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        return Response(result)

    @extend_schema(responses={200: AgentRunStepSerializer(many=True)})
    @action(detail=True, methods=["get"], url_path="steps")
    def steps(self, request, pk=None):
        run = self.get_object()
        serializer = AgentRunStepSerializer(run.steps.all(), many=True)
        return Response(serializer.data)

    @extend_schema(responses={200: AgentRunArtifactSerializer(many=True)})
    @action(detail=True, methods=["get"], url_path="artifacts")
    def artifacts(self, request, pk=None):
        run = self.get_object()
        serializer = AgentRunArtifactSerializer(
            run.artifacts.select_related("step", "object_reference").all(),
            many=True,
        )
        return Response(serializer.data)


class DynamicHostAgentViewSet(viewsets.ViewSet):
    """Permission-aware backend facade for the local allowlisted host agent."""

    permission_classes = [IsMSAPViewerOrAbove]
    viewer_actions = {"status", "packages", "screenshot"}

    def get_permissions(self):
        permission_classes = (
            [IsMSAPViewerOrAbove]
            if self.action in self.viewer_actions
            else [IsMSAPAnalystOrAdmin]
        )
        return [permission() for permission in permission_classes]

    @action(detail=False, methods=["get"], url_path="status")
    def status(self, request):
        payload = DynamicHostAgentClient().get_status()
        device_payload = payload.get("device") or {}
        serial = device_payload.get("serial")
        if serial:
            tracked_device = DynamicDevice.objects.filter(serial=serial).first()
            if tracked_device is not None:
                payload["synced_device_id"] = tracked_device.id
                payload["last_sync_at"] = tracked_device.last_health_check_at
        return Response(payload)

    @action(detail=False, methods=["post"], url_path="sync")
    def sync_device(self, request):
        payload = fetch_and_sync_host_agent(requested_by=request.user)
        if not payload.get("connected"):
            return _host_agent_payload_response(payload)
        return Response(payload)

    @action(
        detail=False,
        methods=["post"],
        url_path="screenshot",
        renderer_classes=[PNGRenderer],
    )
    def screenshot(self, request):
        try:
            screenshot = DynamicHostAgentClient().request_screenshot()
        except HostAgentClientError as exc:
            return _host_agent_error_response(exc)
        if not DynamicDevice.objects.filter(
            serial=settings.MSAP_DYNAMIC_ADB_SERIAL
        ).exists():
            fetch_and_sync_host_agent(requested_by=request.user)
        record_host_agent_action(
            "screenshot",
            {"success": True, "status": "PASS"},
            requested_by=request.user,
        )
        response = HttpResponse(screenshot, content_type="image/png")
        response["Cache-Control"] = "no-store"
        response["Content-Disposition"] = 'inline; filename="emulator-screen.png"'
        return response

    @action(detail=False, methods=["get"], url_path="packages")
    def packages(self, request):
        try:
            result = DynamicHostAgentClient().request_json(
                "/actions/list-packages",
                method="POST",
                body={},
            )
        except HostAgentClientError as exc:
            return _host_agent_error_response(exc)
        return Response(result)

    @action(detail=False, methods=["post"], url_path="force-stop")
    def force_stop(self, request):
        return self._run_package_action(request, "force-stop")

    @action(detail=False, methods=["post"], url_path="launch-package")
    def launch_package(self, request):
        return self._run_package_action(request, "launch-package")

    @action(detail=False, methods=["post"], url_path="clear-data")
    def clear_data(self, request):
        return self._run_package_action(request, "clear-data")

    @action(detail=False, methods=["post"], url_path="uninstall")
    def uninstall(self, request):
        return self._run_package_action(request, "uninstall")

    @action(detail=False, methods=["post"], url_path="install-audit-apk")
    def install_audit_apk(self, request):
        serializer = DynamicHostAgentInstallSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        audit_id = serializer.validated_data["audit"]
        try:
            # Audit access follows the same authenticated project-wide scope as
            # AuditViewSet in the current MVP RBAC model.
            audit = Audit.objects.get(pk=audit_id)
        except Audit.DoesNotExist:
            return Response(
                {"detail": "Audit does not exist or is not accessible."},
                status=status.HTTP_404_NOT_FOUND,
            )

        apk_file_id = serializer.validated_data.get("apk_file")
        apk_files = APKFile.objects.select_related("storage_reference").filter(
            audit=audit
        )
        if apk_file_id is not None:
            apk_file = apk_files.filter(pk=apk_file_id).first()
        else:
            apk_file = apk_files.order_by("-created_at", "-id").first()
        if apk_file is None:
            return Response(
                {"detail": "No uploaded APK was found for this audit."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if apk_file.storage_reference is None:
            return Response(
                {"detail": "Selected APK has no uploaded storage object."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if (
            apk_file.storage_reference.storage_status
            != ObjectStorageReference.StorageStatus.VERIFIED
        ):
            return Response(
                {"detail": "Selected APK object must be confirmed as VERIFIED before installation."},
                status=status.HTTP_409_CONFLICT,
            )

        try:
            with APKFileProvider().open_apk_local_copy(apk_file) as apk_path:
                calculated_sha256 = _validate_apk_for_agent_install(apk_file, apk_path)
                result = DynamicHostAgentClient().install_apk(
                    apk_path,
                    expected_sha256=calculated_sha256,
                )
        except FileProviderError as exc:
            return Response(
                {"detail": str(exc)},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except HostAgentClientError as exc:
            return _host_agent_error_response(exc)

        package_metadata = result.get("package_metadata") or {}
        package_name = str(result.get("package_name") or apk_file.package_name or "")
        result.update(
            {
                "audit": audit.id,
                "apk_file": apk_file.id,
                "package_name": package_name,
            }
        )
        if result.get("success") and package_name:
            update_fields = []
            if apk_file.package_name != package_name:
                apk_file.package_name = package_name
                update_fields.append("package_name")
            version_name = str(package_metadata.get("version_name") or "")
            if version_name and apk_file.version_name != version_name:
                apk_file.version_name = version_name
                update_fields.append("version_name")
            if update_fields:
                apk_file.save(update_fields=update_fields)
        if not DynamicDevice.objects.filter(
            serial=settings.MSAP_DYNAMIC_ADB_SERIAL
        ).exists():
            fetch_and_sync_host_agent(requested_by=request.user)
        record_host_agent_action(
            "install-apk",
            result,
            requested_by=request.user,
            audit_id=audit.id,
            apk_file_id=apk_file.id,
            package_name=package_name,
        )
        return Response(result)

    def _run_package_action(self, request, action_name: str):
        serializer = DynamicHostAgentPackageActionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        package_name = serializer.validated_data["package_name"]
        try:
            result = DynamicHostAgentClient().request_json(
                f"/actions/{action_name}",
                method="POST",
                body={"package_name": package_name},
            )
        except HostAgentClientError as exc:
            return _host_agent_error_response(exc)
        if not DynamicDevice.objects.filter(
            serial=settings.MSAP_DYNAMIC_ADB_SERIAL
        ).exists():
            fetch_and_sync_host_agent(requested_by=request.user)
        record_host_agent_action(
            action_name,
            result,
            requested_by=request.user,
            package_name=package_name,
        )
        return Response(result)


def _request_bool(data, key: str) -> bool:
    value = data.get(key, False)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _validate_apk_for_agent_install(apk_file: APKFile, apk_path) -> str:
    try:
        size_bytes = apk_path.stat().st_size
        with apk_path.open("rb") as apk_stream:
            prefix = apk_stream.read(4)
            digest = sha256()
            digest.update(prefix)
            while True:
                chunk = apk_stream.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
    except OSError as exc:
        raise FileProviderError("Verified APK bytes could not be read safely.") from exc

    max_size = min(
        int(settings.MSAP_MAX_APK_SIZE_BYTES),
        int(settings.MSAP_DYNAMIC_HOST_AGENT_MAX_APK_SIZE_BYTES),
    )
    if size_bytes <= 0 or size_bytes > max_size:
        raise FileProviderError(
            f"Verified APK size must be between 1 and {max_size} bytes."
        )
    expected_sizes = {
        value
        for value in (
            apk_file.size_bytes,
            apk_file.storage_reference.size_bytes,
        )
        if value is not None
    }
    if any(value != size_bytes for value in expected_sizes):
        raise FileProviderError("Verified APK size does not match stored metadata.")
    if prefix not in {b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"}:
        raise FileProviderError("Verified object does not have an APK/ZIP signature.")

    calculated_sha256 = digest.hexdigest()
    expected_hashes = {
        value.strip().lower()
        for value in (apk_file.sha256, apk_file.storage_reference.sha256)
        if value and value.strip()
    }
    if any(value != calculated_sha256 for value in expected_hashes):
        raise FileProviderError("Verified APK SHA-256 does not match stored metadata.")
    if not expected_hashes:
        apk_file.sha256 = calculated_sha256
        apk_file.storage_reference.sha256 = calculated_sha256
        apk_file.save(update_fields=["sha256"])
        apk_file.storage_reference.save(update_fields=["sha256", "updated_at"])
    return calculated_sha256


def _host_agent_error_response(exc: HostAgentClientError) -> Response:
    return Response(
        {"detail": str(exc), "code": exc.code},
        status=exc.status_code,
    )


def _host_agent_payload_response(payload: dict) -> Response:
    response_status = (
        status.HTTP_409_CONFLICT
        if payload.get("code") in {"HOST_AGENT_DISABLED", "HOST_AGENT_NOT_CONFIGURED"}
        else status.HTTP_503_SERVICE_UNAVAILABLE
    )
    return Response(payload, status=response_status)
