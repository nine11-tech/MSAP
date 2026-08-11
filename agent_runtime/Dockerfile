FROM python:3.12.13-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --gid 10001 msap-agent \
    && useradd --uid 10001 --gid msap-agent --no-create-home --shell /usr/sbin/nologin msap-agent

COPY --chown=10001:10001 runner.py /app/runner.py

WORKDIR /app
USER 10001:10001

ENTRYPOINT ["python", "/app/runner.py"]
