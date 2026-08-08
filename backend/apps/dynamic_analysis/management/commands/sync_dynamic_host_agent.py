from django.core.management.base import BaseCommand, CommandError

from apps.dynamic_analysis.services.host_agent_sync import fetch_and_sync_host_agent


class Command(BaseCommand):
    help = "Fetch local host-agent device metadata and update the dynamic inventory."

    def handle(self, *args, **options):
        result = fetch_and_sync_host_agent()
        if not result.get("connected"):
            raise CommandError(result.get("detail") or "Dynamic host-agent sync failed.")
        device = result.get("device") or {}
        self.stdout.write(f"Agent version: {(result.get('agent') or {}).get('version', '')}")
        self.stdout.write(f"Device: {device.get('serial', '')}")
        self.stdout.write(f"ADB state: {device.get('state', 'unknown')}")
        self.stdout.write(f"Database device ID: {result.get('synced_device_id')}")
        self.stdout.write("SYNC_DYNAMIC_HOST_AGENT_RESULT=PASS")
