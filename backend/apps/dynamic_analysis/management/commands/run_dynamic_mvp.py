from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from apps.audits.models import Audit
from apps.dynamic_analysis.models import DynamicAnalysisJob
from apps.dynamic_analysis.services.local_scripts import DynamicScriptExecutionError
from apps.dynamic_analysis.services.mvp_runner import (
    DynamicMvpRunnerError,
    create_dynamic_mvp_job,
    dynamic_mvp_stage_plan,
    run_dynamic_mvp_job,
)


class Command(BaseCommand):
    help = "Run the local dynamic MVP lab script sequence for an audit."

    def add_arguments(self, parser):
        parser.add_argument("--audit-id", type=int, required=True)
        parser.add_argument("--include-platform-tls-probe", action="store_true")
        parser.add_argument("--requested-by", default="")
        parser.add_argument("--dry-run", action="store_true")

    def handle(self, *args, **options):
        include_platform_tls_probe = bool(options["include_platform_tls_probe"])
        if (
            include_platform_tls_probe
            and not settings.MSAP_DYNAMIC_PLATFORM_TLS_PROBE_ENABLED
        ):
            raise CommandError(
                "Platform TLS probe was requested but "
                "MSAP_DYNAMIC_PLATFORM_TLS_PROBE_ENABLED is false."
            )
        dry_run = bool(options["dry_run"])
        if not dry_run and not settings.MSAP_DYNAMIC_RUNNER_ENABLED:
            raise CommandError(
                "Dynamic MVP runner is disabled. Set MSAP_DYNAMIC_RUNNER_ENABLED=true "
                "for local demo execution."
            )

        try:
            audit = Audit.objects.get(pk=options["audit_id"])
        except Audit.DoesNotExist as exc:
            raise CommandError(
                f"Audit {options['audit_id']} does not exist. "
                "List audits with: python manage.py shell -c "
                "\"from apps.audits.models import Audit; "
                "print(list(Audit.objects.values('id', 'name')))\""
            ) from exc

        if dry_run:
            self._print_dry_run_plan(
                audit_id=audit.id,
                include_platform_tls_probe=include_platform_tls_probe,
            )
            return

        requested_by = self._requested_by(options["requested_by"])
        job = create_dynamic_mvp_job(
            audit,
            requested_by=requested_by,
            include_platform_tls_probe=include_platform_tls_probe,
        )
        self._write(f"Job ID: {job.id}")
        self._write(f"Audit ID: {audit.id}")
        self._write(
            "Dynamic MVP runner starting "
            f"include_platform_tls_probe={include_platform_tls_probe}"
        )

        try:
            result = run_dynamic_mvp_job(
                job.id,
                include_platform_tls_probe=include_platform_tls_probe,
                progress_callback=self._progress,
            )
        except (DynamicMvpRunnerError, DynamicScriptExecutionError) as exc:
            raise CommandError(str(exc)) from exc

        self._write(f"Final job status: {result['job_status']}")
        self._write(f"Final session state: {result['session_state']}")
        self._write(f"Final cleanup status: {result['cleanup_status']}")
        self._write(f"Artifacts: {result['artifacts_count']}")
        self._write(f"Stages: {result['stages_count']}")
        if result["job_status"] != DynamicAnalysisJob.Status.COMPLETED:
            self._write("DYNAMIC_MVP_RUNNER_RESULT=FAIL")
            raise CommandError(
                f"Dynamic MVP runner failed: {result['failure_category']} "
                f"{result['failure_message']}"
            )
        self._write("DYNAMIC_MVP_RUNNER_RESULT=PASS")

    def _requested_by(self, username: str):
        if not username:
            return None
        User = get_user_model()
        try:
            return User.objects.get(username=username)
        except User.DoesNotExist as exc:
            raise CommandError(f"User {username!r} does not exist.") from exc

    def _print_dry_run_plan(
        self,
        *,
        audit_id: int,
        include_platform_tls_probe: bool,
    ) -> None:
        self._write(f"Dynamic MVP runner dry-run audit_id={audit_id}")
        self._write(
            "Planned stages "
            f"include_platform_tls_probe={include_platform_tls_probe}"
        )
        try:
            plan = dynamic_mvp_stage_plan(
                include_platform_tls_probe=include_platform_tls_probe,
            )
        except DynamicScriptExecutionError as exc:
            raise CommandError(str(exc)) from exc
        for item in plan:
            marker = "SKIP" if item["skipped"] else "PLAN"
            suffix = f" reason={item['skip_reason']}" if item.get("skip_reason") else ""
            self._write(
                f"{marker} {item['stage']} script={item['script_name']} "
                f"timeout={item['timeout_seconds']}s state={item['state']}{suffix}"
            )
        self._write("DYNAMIC_MVP_RUNNER_DRY_RUN=PASS")

    def _progress(self, event: str, payload: dict) -> None:
        if event == "job_started":
            self._write(
                f"Job started: job_id={payload['job_id']} "
                f"audit_id={payload['audit_id']}"
            )
        elif event == "session_created":
            self._write(
                f"Session ID: {payload['session_id']} "
                f"lease_id={payload['lease_id']} "
                f"device={payload['device_serial']}"
            )
        elif event == "stage_started":
            self._write(
                f"STAGE START {payload['stage']} "
                f"script={payload['script_name']} "
                f"timeout={payload['timeout_seconds']}s"
            )
        elif event == "stage_succeeded":
            markers = ", ".join(payload.get("pass_markers") or ["PASS"])
            self._write(
                f"PASS {payload['stage']} script={payload['script_name']} "
                f"duration={payload['duration_seconds']:.1f}s markers={markers}"
            )
        elif event == "stage_failed":
            self._write(
                f"FAIL {payload['stage']} script={payload['script_name']} "
                f"return_code={payload['return_code']} "
                f"duration={payload['duration_seconds']:.1f}s "
                f"timed_out={payload['timed_out']}"
            )
            fail_markers = payload.get("fail_markers") or []
            if fail_markers:
                self._write(f"FAIL markers: {', '.join(fail_markers)}")
            self._write(f"Failure: {payload['message']}")
            self._write_preview("stdout", payload.get("stdout_preview", ""))
            self._write_preview("stderr", payload.get("stderr_preview", ""))
        elif event == "stage_skipped":
            self._write(
                f"SKIP {payload['stage']} script={payload['script_name']} "
                f"timeout={payload['timeout_seconds']}s {payload['message']}"
            )

    def _write_preview(self, label: str, preview: str) -> None:
        if not preview:
            return
        self._write(f"{label} preview:")
        self._write(self._short_preview(preview))

    def _short_preview(self, value: str, limit: int = 1200) -> str:
        if len(value) <= limit:
            return value
        return f"[truncated]\n{value[-limit:]}"

    def _write(self, message: str) -> None:
        self.stdout.write(message)
        self.stdout.flush()
