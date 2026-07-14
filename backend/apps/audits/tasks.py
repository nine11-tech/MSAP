from celery import shared_task
from django.db import transaction
from django.utils import timezone

from apps.audits.models import AnalysisJob, Audit


@shared_task(bind=True)
def analyze_audit_placeholder(self, audit_id):
    job = None
    try:
        with transaction.atomic():
            audit = Audit.objects.select_for_update().get(id=audit_id)
            job = (
                AnalysisJob.objects.select_for_update()
                .filter(
                    audit=audit,
                    status__in=[
                        AnalysisJob.Status.QUEUED,
                        AnalysisJob.Status.RUNNING,
                    ],
                )
                .order_by("-created_at")
                .first()
            )
            if job is None:
                job = AnalysisJob.objects.create(
                    audit=audit,
                    task_id=self.request.id or "",
                    status=AnalysisJob.Status.QUEUED,
                )
            elif self.request.id and not job.task_id:
                job.task_id = self.request.id

            now = timezone.now()
            job.status = AnalysisJob.Status.RUNNING
            job.started_at = job.started_at or now
            job.error_message = ""
            job.save(
                update_fields=[
                    "task_id",
                    "status",
                    "started_at",
                    "error_message",
                    "updated_at",
                ]
            )

            audit.status = Audit.Status.ANALYSIS_RUNNING
            audit.save(update_fields=["status", "updated_at"])

        with transaction.atomic():
            audit = Audit.objects.select_for_update().get(id=audit_id)
            job = AnalysisJob.objects.select_for_update().get(id=job.id)
            now = timezone.now()
            job.status = AnalysisJob.Status.COMPLETED
            job.finished_at = now
            job.error_message = ""
            job.save(update_fields=["status", "finished_at", "error_message", "updated_at"])

            audit.status = Audit.Status.ANALYSIS_COMPLETED
            audit.save(update_fields=["status", "updated_at"])

        return {"audit_id": audit_id, "status": AnalysisJob.Status.COMPLETED}
    except Exception as exc:
        error_message = str(exc)
        with transaction.atomic():
            try:
                audit = Audit.objects.select_for_update().get(id=audit_id)
            except Audit.DoesNotExist:
                raise

            if job is not None:
                job = AnalysisJob.objects.select_for_update().get(id=job.id)
            else:
                job = (
                    AnalysisJob.objects.select_for_update()
                    .filter(audit=audit)
                    .order_by("-created_at")
                    .first()
                )

            if job is not None:
                job.status = AnalysisJob.Status.FAILED
                job.finished_at = timezone.now()
                job.error_message = error_message
                job.save(
                    update_fields=[
                        "status",
                        "finished_at",
                        "error_message",
                        "updated_at",
                    ]
                )

            audit.status = Audit.Status.ANALYSIS_FAILED
            audit.save(update_fields=["status", "updated_at"])
        raise
