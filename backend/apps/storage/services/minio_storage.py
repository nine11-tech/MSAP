from pathlib import PurePosixPath
from uuid import uuid4

import boto3
from django.conf import settings


class MinIOStorageService:
    def __init__(self):
        self.client = boto3.client(
            "s3",
            endpoint_url=self._endpoint_url(),
            aws_access_key_id=settings.MINIO_ACCESS_KEY,
            aws_secret_access_key=settings.MINIO_SECRET_KEY,
        )

    def build_object_key(self, project_id, audit_id, object_type, filename):
        clean_filename = PurePosixPath(filename).name
        return str(
            PurePosixPath(
                "projects",
                str(project_id),
                "audits",
                str(audit_id),
                object_type.lower(),
                f"{uuid4().hex}-{clean_filename}",
            )
        )

    def generate_presigned_upload_url(
        self,
        bucket,
        object_key,
        content_type,
        expires_in=900,
    ):
        return self.client.generate_presigned_url(
            "put_object",
            Params={
                "Bucket": bucket,
                "Key": object_key,
                "ContentType": content_type,
            },
            ExpiresIn=expires_in,
        )

    def generate_presigned_download_url(self, bucket, object_key, expires_in=900):
        return self.client.generate_presigned_url(
            "get_object",
            Params={"Bucket": bucket, "Key": object_key},
            ExpiresIn=expires_in,
        )

    def head_object(self, bucket, object_key):
        return self.client.head_object(Bucket=bucket, Key=object_key)

    def get_apk_upload_bucket(self):
        return settings.MINIO_BUCKET_APK_UPLOADS

    def _endpoint_url(self):
        endpoint = settings.MINIO_ENDPOINT
        if endpoint.startswith(("http://", "https://")):
            return endpoint
        scheme = "https" if settings.MINIO_SECURE else "http"
        return f"{scheme}://{endpoint}"
