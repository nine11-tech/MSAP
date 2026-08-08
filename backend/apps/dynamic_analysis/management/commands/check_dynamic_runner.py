from django.core.management.base import BaseCommand, CommandError

from apps.dynamic_analysis.services.runner_readiness import (
    get_dynamic_runner_readiness,
)


class Command(BaseCommand):
    help = "Verify that the configured dynamic runner execution mode is ready."

    def handle(self, *args, **options):
        result = get_dynamic_runner_readiness()
        self.stdout.write(f"Execution mode: {result['execution_mode']}")
        self.stdout.write(f"Worker status: {result['worker_status']}")
        if not result["ready"]:
            raise CommandError(result["detail"])
        self.stdout.write("CHECK_DYNAMIC_RUNNER_RESULT=PASS")
