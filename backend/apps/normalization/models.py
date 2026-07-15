from django.db import models


class NormalizedArtifact(models.Model):
    class ArtifactType(models.TextChoices):
        APK_METADATA = "APK_METADATA", "APK metadata"
        MANIFEST = "MANIFEST", "Manifest"
        PERMISSIONS = "PERMISSIONS", "Permissions"
        COMPONENTS = "COMPONENTS", "Components"
        CERTIFICATE = "CERTIFICATE", "Certificate"
        STRINGS = "STRINGS", "Strings"
        RESOURCES = "RESOURCES", "Resources"
        CODE_REFERENCES = "CODE_REFERENCES", "Code references"

    audit = models.ForeignKey(
        "audits.Audit",
        on_delete=models.CASCADE,
        related_name="normalized_artifacts",
    )
    apk_file = models.ForeignKey(
        "apk_files.APKFile",
        on_delete=models.CASCADE,
        related_name="normalized_artifacts",
    )
    artifact_type = models.CharField(max_length=64, choices=ArtifactType.choices)
    source = models.CharField(max_length=128)
    normalized_data = models.JSONField(default=dict, blank=True)
    storage_reference = models.ForeignKey(
        "storage.ObjectStorageReference",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="normalized_artifacts",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["audit", "apk_file"]),
            models.Index(fields=["artifact_type", "source"]),
        ]

    def __str__(self) -> str:
        return f"{self.artifact_type} artifact for audit {self.audit_id}"

