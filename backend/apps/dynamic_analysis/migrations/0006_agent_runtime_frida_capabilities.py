from django.db import migrations


OBJECTIVES = [
    "DEVICE_READINESS_CHECK",
    "BASIC_APP_INTERACTION_CHECK",
    "FRIDA_RUNTIME_ACTION",
    "FRIDA_RUNTIME_UI_MODIFICATION_PROOF",
    "FRIDA_CUSTOM_SCRIPT",
]

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
    "frida_status",
    "frida_ps",
    "frida_setup",
    "frida_attach",
    "frida_run_js",
]


def update_agent_runtime_capabilities(apps, schema_editor):
    AgentRuntime = apps.get_model("dynamic_analysis", "AgentRuntime")
    AgentRuntime.objects.filter(
        name__in=["Sprint B Internal Controller", "Sprint C Container Sandbox"]
    ).update(capabilities={"objectives": OBJECTIVES, "tools": TOOLS})


class Migration(migrations.Migration):
    dependencies = [
        ("dynamic_analysis", "0005_alter_agentrun_objective"),
    ]

    operations = [
        migrations.RunPython(
            update_agent_runtime_capabilities,
            reverse_code=migrations.RunPython.noop,
        ),
    ]
