#!/bin/sh
set -eu

max_attempts=30
attempt=1

until pg_isready \
    -h "${POSTGRES_HOST:-postgres}" \
    -p "${POSTGRES_PORT:-5432}" \
    -U "${POSTGRES_USER:-msap_app}" \
    -d "${POSTGRES_DB:-msap}" >/dev/null 2>&1
do
    if [ "$attempt" -ge "$max_attempts" ]; then
        echo "PostgreSQL was not ready after ${max_attempts} attempts." >&2
        exit 1
    fi
    echo "Waiting for PostgreSQL (${attempt}/${max_attempts})..."
    attempt=$((attempt + 1))
    sleep 2
done

python manage.py migrate --noinput

case "${MSAP_VALIDATE_RULES_ON_STARTUP:-true}" in
    1|true|TRUE|yes|YES|on|ON)
        python manage.py validate_rules
        ;;
esac

exec python manage.py runserver 0.0.0.0:8000
