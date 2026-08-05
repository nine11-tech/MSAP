from celery import shared_task
from django.conf import settings
from django.utils import timezone

from apps.dynamic_analysis.models import DynamicAnalysisJob
from apps.dynamic_analysis.services.mvp_runner import (
    DynamicMvpRunnerError,
    run_dynamic_mvp_job,
)


@shared_task(bind=True)
def run_dynamic_mvp_job_task(
    self,
    job_id: int,
    include_platform_tls_probe: bool = False,
) -> dict:
    if not settings.MSAP_DYNAMIC_RUNNER_ENABLED:
        _mark_job_failed(
            job_id,
            DynamicAnalysisJob.FailureCategory.UNKNOWN,
            "Dynamic MVP runner is disabled.",
        )
        return {"job_id": job_id, "job_status": DynamicAnalysisJob.Status.FAILED}

    try:
        return run_dynamic_mvp_job(
            job_id,
            include_platform_tls_probe=include_platform_tls_probe,
        )
    except DynamicMvpRunnerError as exc:
        _mark_job_failed(
            job_id,
            DynamicAnalysisJob.FailureCategory.UNKNOWN,
            str(exc),
        )
        return {"job_id": job_id, "job_status": DynamicAnalysisJob.Status.FAILED}
    except Exception as exc:
        _mark_job_failed(
            job_id,
            DynamicAnalysisJob.FailureCategory.UNKNOWN,
            "Dynamic MVP runner task failed unexpectedly.",
        )
        raise exc


def _mark_job_failed(job_id: int, category: str, message: str) -> None:
    DynamicAnalysisJob.objects.filter(
        pk=job_id,
        status__in=[
            DynamicAnalysisJob.Status.QUEUED,
            DynamicAnalysisJob.Status.RUNNING,
        ],
    ).update(
        status=DynamicAnalysisJob.Status.FAILED,
        failure_category=category,
        failure_message=message,
        finished_at=timezone.now(),
        updated_at=timezone.now(),
    )
