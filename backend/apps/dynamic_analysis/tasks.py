from celery import shared_task
import logging
from django.conf import settings
from django.utils import timezone

from apps.dynamic_analysis.models import AgentRun, DynamicAnalysisJob
from apps.dynamic_analysis.services.mvp_runner import (
    DynamicMvpRunnerError,
    run_dynamic_mvp_job,
)
from apps.dynamic_analysis.services.assessment_executor import (
    AssessmentExecutionError,
    AssessmentExecutor,
)
from apps.dynamic_analysis.services.assessment_agent import (
    AssessmentAgent,
    AssessmentAgentError,
)


logger = logging.getLogger(__name__)


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


@shared_task(bind=True)
def execute_assessment_plan_run_task(self, run_id: int) -> dict:
    """Execute only the immutable approved-plan snapshot already linked to a run."""

    try:
        run = AssessmentExecutor().execute(run_id)
    except AssessmentExecutionError as exc:
        logger.warning(
            "assessment_execution_task_failed run_id=%s code=%s",
            run_id,
            exc.code,
        )
        run = AssessmentExecutor.mark_execution_failed(
            run_id,
            message=str(exc),
        )
    except Exception as exc:
        logger.error(
            "assessment_execution_task_failed run_id=%s error_type=%s",
            run_id,
            type(exc).__name__,
        )
        run = AssessmentExecutor.mark_execution_failed(
            run_id,
            message="The bounded assessment execution worker failed unexpectedly.",
        )
    return {"run_id": run.id, "run_status": run.status}


@shared_task(bind=True)
def execute_adaptive_assessment_run_task(self, run_id: int) -> dict:
    """Run only persisted adaptive decisions through the existing gateway."""

    try:
        run = AssessmentAgent().execute(run_id)
    except (AssessmentAgentError, AssessmentExecutionError) as exc:
        logger.warning(
            "adaptive_assessment_task_failed run_id=%s code=%s",
            run_id,
            exc.code,
        )
        run = AgentRun.objects.get(pk=run_id)
        run = AssessmentAgent._finish(
            run,
            status=AgentRun.Status.FAILED,
            termination_reason="AGENT_RUNTIME_FAILURE",
            message=str(exc),
        )
    except Exception as exc:
        logger.error(
            "adaptive_assessment_task_failed run_id=%s error_type=%s",
            run_id,
            type(exc).__name__,
        )
        run = AgentRun.objects.get(pk=run_id)
        run = AssessmentAgent._finish(
            run,
            status=AgentRun.Status.FAILED,
            termination_reason="AGENT_RUNTIME_FAILURE",
            message="The bounded adaptive assessment worker failed unexpectedly.",
        )
    return {"run_id": run.id, "run_status": run.status}


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
