from django.db import models


class Audit(models.Model):
    class Status(models.TextChoices):
        CREATED = "created", "Created"
        DRAFT = "DRAFT", "Draft"
        APK_UPLOADED = "apk_uploaded", "APK uploaded"
        QUEUED = "queued", "Queued"
        ANALYZING = "analyzing", "Analyzing"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"
        ANALYSIS_QUEUED = "ANALYSIS_QUEUED", "Analysis queued"
        ANALYSIS_RUNNING = "ANALYSIS_RUNNING", "Analysis running"
        ANALYSIS_COMPLETED = "ANALYSIS_COMPLETED", "Analysis completed"
        ANALYSIS_FAILED = "ANALYSIS_FAILED", "Analysis failed"
        EXPORT_READY = "export_ready", "Export ready"

    project = models.ForeignKey(
        "projects.Project",
        on_delete=models.CASCADE,
        related_name="audits",
    )
    name = models.CharField(max_length=255)
    status = models.CharField(
        max_length=32,
        choices=Status.choices,
        default=Status.CREATED,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return self.name


class AnalysisJob(models.Model):
    class Status(models.TextChoices):
        QUEUED = "QUEUED", "Queued"
        RUNNING = "RUNNING", "Running"
        COMPLETED = "COMPLETED", "Completed"
        FAILED = "FAILED", "Failed"

    audit = models.ForeignKey(
        Audit,
        on_delete=models.CASCADE,
        related_name="analysis_jobs",
    )
    task_id = models.CharField(max_length=255, blank=True)
    status = models.CharField(
        max_length=32,
        choices=Status.choices,
        default=Status.QUEUED,
    )
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    error_message = models.TextField(blank=True)
    result_summary = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"Analysis job {self.id} for audit {self.audit_id}"
