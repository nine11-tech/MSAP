from django.db import models


class NormalizedArtifact(models.Model):
    class ArtifactType(models.TextChoices):
        APK_METADATA = "APK_METADATA", "APK metadata"
        MANIFEST = "MANIFEST", "Manifest"
        PERMISSIONS = "PERMISSIONS", "Permissions"
        COMPONENTS = "COMPONENTS", "Components"
        NETWORK_SECURITY_CONFIG = "NETWORK_SECURITY_CONFIG", "Network security config"
        CERTIFICATE = "CERTIFICATE", "Certificate"
        SIGNING = "SIGNING", "Signing"
        DEX_METADATA = "DEX_METADATA", "DEX metadata"
        STRINGS = "STRINGS", "Strings"
        RESOURCES = "RESOURCES", "Resources"
        CODE_REFERENCES = "CODE_REFERENCES", "Code references"
        SECRETS = "SECRETS", "Secrets"
        CRYPTO_USAGE = "CRYPTO_USAGE", "Cryptographic usage"
        WEBVIEW_USAGE = "WEBVIEW_USAGE", "WebView usage"
        NATIVE_LIBRARIES = "NATIVE_LIBRARIES", "Native libraries"
        THIRD_PARTY_SDKS = "THIRD_PARTY_SDKS", "Third-party SDKs"
        URLS_AND_ENDPOINTS = "URLS_AND_ENDPOINTS", "URLs and endpoints"
        PACKAGE_CONTENT = "PACKAGE_CONTENT", "Package content"
        RESILIENCE_SIGNALS = "RESILIENCE_SIGNALS", "Resilience signals"

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
        constraints = [
            models.UniqueConstraint(
                fields=["audit", "apk_file", "artifact_type", "source"],
                name="unique_normalized_artifact_per_analyzer",
            )
        ]

    def __str__(self) -> str:
        return f"{self.artifact_type} artifact for audit {self.audit_id}"
