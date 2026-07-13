from django.db import models


class APKFile(models.Model):
    audit = models.ForeignKey(
        "audits.Audit",
        on_delete=models.CASCADE,
        related_name="apk_files",
    )
    package_name = models.CharField(max_length=255, blank=True)
    version_name = models.CharField(max_length=128, blank=True)
    sha256 = models.CharField(max_length=64, blank=True)
    size_bytes = models.BigIntegerField(null=True, blank=True)
    storage_reference = models.ForeignKey(
        "storage.ObjectStorageReference",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="apk_files",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return self.package_name or f"APK for audit {self.audit_id}"

