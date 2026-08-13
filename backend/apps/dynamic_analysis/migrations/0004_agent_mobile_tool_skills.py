# Generated for Sprint C2 Agent Mobile Tool Skills Foundation.

from django.db import migrations, models


TOOLS = [
    "get_device_status",
    "list_packages",
    "install_verified_apk",
    "launch_package",
    "force_stop_package",
    "clear_package_data",
    "take_screenshot",
    "start_logcat",
    "stop_logcat",
    "get_logcat_excerpt",
    "dump_ui",
    "tap_coordinates",
    "type_text",
]


def update_agent_runtime_capabilities(apps, schema_editor):
    AgentRuntime = apps.get_model("dynamic_analysis", "AgentRuntime")
    AgentRuntime.objects.filter(
        name__in=["Sprint B Internal Controller", "Sprint C Container Sandbox"]
    ).update(
        capabilities={
            "objectives": [
                "DEVICE_READINESS_CHECK",
                "BASIC_APP_INTERACTION_CHECK",
            ],
            "tools": TOOLS,
        }
    )


class Migration(migrations.Migration):
    dependencies = [
        ("dynamic_analysis", "0003_agentrun_run_token_expires_at_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="agentrun",
            name="objective_input",
            field=models.JSONField(blank=True, default=dict),
        ),
        migrations.AlterField(
            model_name="agentrun",
            name="objective",
            field=models.CharField(
                choices=[
                    ("DEVICE_READINESS_CHECK", "Device readiness check"),
                    (
                        "BASIC_APP_INTERACTION_CHECK",
                        "Basic app interaction check",
                    ),
                ],
                max_length=64,
            ),
        ),
        migrations.RunPython(
            update_agent_runtime_capabilities,
            reverse_code=migrations.RunPython.noop,
        ),
    ]
