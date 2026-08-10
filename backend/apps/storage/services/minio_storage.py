from pathlib import PurePosixPath
from urllib.parse import urlsplit
from uuid import uuid4

import boto3
from django.conf import settings


class MinIOStorageService:
    def __init__(self):
        internal_endpoint = self._endpoint_url(settings.MINIO_ENDPOINT)
        public_endpoint = self._endpoint_url(settings.MINIO_PUBLIC_ENDPOINT)
        client_options = {
            "aws_access_key_id": settings.MINIO_ACCESS_KEY,
            "aws_secret_access_key": settings.MINIO_SECRET_KEY,
        }
        self.client = boto3.client(
            "s3",
            endpoint_url=internal_endpoint,
            **client_options,
        )
        self.presign_client = boto3.client(
            "s3",
            endpoint_url=public_endpoint,
            **client_options,
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
        sha256="",
        expires_in=900,
    ):
        params = {
            "Bucket": bucket,
            "Key": object_key,
            "ContentType": content_type,
        }
        if sha256:
            params["Metadata"] = {"sha256": sha256}
        return self.presign_client.generate_presigned_url(
            "put_object",
            Params=params,
            ExpiresIn=expires_in,
        )

    def public_endpoint_hostname(self):
        return urlsplit(self._endpoint_url(settings.MINIO_PUBLIC_ENDPOINT)).hostname

    def generate_presigned_download_url(self, bucket, object_key, expires_in=900):
        return self.presign_client.generate_presigned_url(
            "get_object",
            Params={"Bucket": bucket, "Key": object_key},
            ExpiresIn=expires_in,
        )

    def head_object(self, bucket, object_key):
        return self.client.head_object(Bucket=bucket, Key=object_key)

    def download_file(self, bucket, object_key, destination):
        return self.client.download_file(
            Bucket=bucket,
            Key=object_key,
            Filename=str(destination),
        )

    def upload_file(self, bucket, object_key, source, content_type="text/plain"):
        return self.client.upload_file(
            Filename=str(source),
            Bucket=bucket,
            Key=object_key,
            ExtraArgs={"ContentType": content_type},
        )

    def get_apk_upload_bucket(self):
        return settings.MINIO_BUCKET_APK_UPLOADS

    def _endpoint_url(self, endpoint):
        if endpoint.startswith(("http://", "https://")):
            return endpoint
        scheme = "https" if settings.MINIO_SECURE else "http"
        return f"{scheme}://{endpoint}"
