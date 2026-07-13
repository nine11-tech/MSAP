from django.db import models


class Audit(models.Model):
    class Status(models.TextChoices):
        CREATED = "created", "Created"
        APK_UPLOADED = "apk_uploaded", "APK uploaded"
        QUEUED = "queued", "Queued"
        ANALYZING = "analyzing", "Analyzing"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"
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

