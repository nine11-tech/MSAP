from django.core.management.base import BaseCommand, CommandError

from apps.dynamic_analysis.services.job_control import (
    DynamicJobControlError,
    recover_stale_dynamic_jobs,
)


class Command(BaseCommand):
    help = "Cancel stale queued jobs and quarantine/recover abandoned running jobs."

    def add_arguments(self, parser):
        parser.add_argument("--older-than-minutes", type=int, default=5)
        parser.add_argument("--limit", type=int, default=100)

    def handle(self, *args, **options):
        try:
            result = recover_stale_dynamic_jobs(
                older_than_minutes=options["older_than_minutes"],
                limit=options["limit"],
            )
        except DynamicJobControlError as exc:
            raise CommandError(str(exc)) from exc
        self.stdout.write(f"Recovered jobs: {result['recovered_count']}")
        self.stdout.write(
            "Recovered job IDs: "
            + ",".join(str(value) for value in result["recovered_job_ids"])
        )
        self.stdout.write("RECOVER_DYNAMIC_JOBS_RESULT=PASS")
