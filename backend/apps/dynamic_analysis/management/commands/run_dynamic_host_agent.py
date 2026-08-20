from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from apps.dynamic_analysis.services.host_agent import serve_dynamic_host_agent


class Command(BaseCommand):
    help = "Run the token-authenticated local MSAP dynamic host agent."

    def add_arguments(self, parser):
        parser.add_argument(
            "--host",
            default=settings.MSAP_DYNAMIC_HOST_AGENT_BIND,
        )
        parser.add_argument(
            "--port",
            type=int,
            default=settings.MSAP_DYNAMIC_HOST_AGENT_PORT,
        )

    def handle(self, *args, **options):
        token = settings.MSAP_DYNAMIC_HOST_AGENT_TOKEN
        if not token:
            raise CommandError(
                "MSAP_DYNAMIC_HOST_AGENT_TOKEN must be set in the local environment."
            )
        host = options["host"]
        port = options["port"]
        if not 1 <= port <= 65535:
            raise CommandError("Host-agent port must be between 1 and 65535.")

        self.stdout.write(
            f"MSAP dynamic host agent {settings.MSAP_APPLICATION_VERSION} "
            f"starting on http://{host}:{port}"
        )
        if host not in {"127.0.0.1", "::1", "localhost"}:
            self.stdout.write(
                self.style.WARNING(
                    "Host-agent is not bound to loopback; restrict this local listener."
                )
            )
        try:
            serve_dynamic_host_agent(host=host, port=port, token=token)
        except OSError as exc:
            raise CommandError(
                f"Dynamic host-agent listener could not start on {host}:{port}: {exc}"
            ) from exc
