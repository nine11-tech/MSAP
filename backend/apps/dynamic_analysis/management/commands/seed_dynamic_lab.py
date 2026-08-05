from django.core.management.base import BaseCommand

from apps.dynamic_analysis.models import (
    DynamicDeviceCapability,
    DynamicEmulatorSnapshot,
)
from apps.dynamic_analysis.services.mvp_runner import ensure_local_mvp_device


class Command(BaseCommand):
    help = "Create or update the local Android dynamic MVP lab metadata."

    def handle(self, *args, **options):
        device = ensure_local_mvp_device()
        capability_count = DynamicDeviceCapability.objects.filter(device=device).count()
        snapshot_count = DynamicEmulatorSnapshot.objects.filter(device=device).count()

        self.stdout.write(f"Pool: {device.pool.slug}")
        self.stdout.write(f"Device: {device.name} ({device.serial})")
        self.stdout.write(f"Status: {device.status}")
        self.stdout.write(f"Capabilities: {capability_count}")
        self.stdout.write(f"Snapshots: {snapshot_count}")
        self.stdout.write("SEED_DYNAMIC_LAB_RESULT=PASS")
