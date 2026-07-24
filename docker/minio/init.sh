#!/bin/sh
set -eu

alias_name=msap
max_attempts=30
attempt=1

until mc alias set \
    "$alias_name" \
    http://minio:9000 \
    "$MINIO_ROOT_USER" \
    "$MINIO_ROOT_PASSWORD" >/dev/null 2>&1 \
    && mc ready "$alias_name" >/dev/null 2>&1
do
    if [ "$attempt" -ge "$max_attempts" ]; then
        echo "MinIO was not ready after ${max_attempts} attempts." >&2
        exit 1
    fi
    echo "Waiting for MinIO (${attempt}/${max_attempts})..."
    attempt=$((attempt + 1))
    sleep 2
done

for bucket in \
    "$MINIO_BUCKET_APK_UPLOADS" \
    "$MINIO_BUCKET_ARTIFACTS" \
    "$MINIO_BUCKET_EVIDENCE" \
    "$MINIO_BUCKET_REPORTS" \
    "$MINIO_BUCKET_EXPORTS"
do
    mc mb --ignore-existing "$alias_name/$bucket"
done

test -s /opt/msap/cors.xml
echo "MinIO buckets are ready. Browser origins are configured by the MinIO service."
