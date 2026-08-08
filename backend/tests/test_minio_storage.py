from unittest.mock import MagicMock, call, patch

from django.test import SimpleTestCase, override_settings

from apps.storage.services.minio_storage import MinIOStorageService


@override_settings(
    MINIO_ENDPOINT="http://minio:9000",
    MINIO_PUBLIC_ENDPOINT="http://localhost:9000",
    MINIO_ACCESS_KEY="test-access",
    MINIO_SECRET_KEY="test-secret",
    MINIO_SECURE=False,
)
class MinIOStorageServiceEndpointTests(SimpleTestCase):
    @patch("apps.storage.services.minio_storage.boto3.client")
    def test_presigned_url_uses_public_endpoint(self, mock_boto_client):
        internal_client = MagicMock()
        public_client = MagicMock()
        public_client.generate_presigned_url.return_value = (
            "http://localhost:9000/msap-apk-uploads/example.apk"
        )
        mock_boto_client.side_effect = [internal_client, public_client]

        service = MinIOStorageService()
        result = service.generate_presigned_upload_url(
            "msap-apk-uploads",
            "example.apk",
            "application/vnd.android.package-archive",
            sha256="a" * 64,
        )

        self.assertEqual(
            result,
            "http://localhost:9000/msap-apk-uploads/example.apk",
        )
        self.assertEqual(
            mock_boto_client.call_args_list,
            [
                call(
                    "s3",
                    endpoint_url="http://minio:9000",
                    aws_access_key_id="test-access",
                    aws_secret_access_key="test-secret",
                ),
                call(
                    "s3",
                    endpoint_url="http://localhost:9000",
                    aws_access_key_id="test-access",
                    aws_secret_access_key="test-secret",
                ),
            ],
        )
        public_client.generate_presigned_url.assert_called_once()
        public_client.generate_presigned_url.assert_called_once_with(
            "put_object",
            Params={
                "Bucket": "msap-apk-uploads",
                "Key": "example.apk",
                "ContentType": "application/vnd.android.package-archive",
                "Metadata": {"sha256": "a" * 64},
            },
            ExpiresIn=900,
        )
        internal_client.generate_presigned_url.assert_not_called()

    @patch("apps.storage.services.minio_storage.boto3.client")
    def test_server_side_operations_use_internal_endpoint(self, mock_boto_client):
        internal_client = MagicMock()
        public_client = MagicMock()
        mock_boto_client.side_effect = [internal_client, public_client]

        service = MinIOStorageService()
        service.head_object("msap-apk-uploads", "example.apk")
        service.download_file(
            "msap-apk-uploads",
            "example.apk",
            "/tmp/example.apk",
        )

        internal_client.head_object.assert_called_once_with(
            Bucket="msap-apk-uploads",
            Key="example.apk",
        )
        internal_client.download_file.assert_called_once_with(
            Bucket="msap-apk-uploads",
            Key="example.apk",
            Filename="/tmp/example.apk",
        )
        public_client.head_object.assert_not_called()
        public_client.download_file.assert_not_called()
