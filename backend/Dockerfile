FROM python:3.12.13-slim-bookworm AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}"

COPY backend/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

FROM python:3.12.13-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:${PATH}" \
    DJANGO_SETTINGS_MODULE=msap.settings.production \
    ANALYZER_RULES_PATH=/app/rules

RUN groupadd --gid 10001 msap \
    && useradd --uid 10001 --gid msap --no-create-home --shell /usr/sbin/nologin msap

COPY --from=builder /opt/venv /opt/venv
COPY --chown=msap:msap backend/ /app/backend/
COPY --chown=msap:msap rules/ /app/rules/

WORKDIR /app/backend
USER 10001:10001

EXPOSE 8000

CMD ["gunicorn", "msap.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "3", "--timeout", "120", "--access-logfile", "-", "--error-logfile", "-"]
