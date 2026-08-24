from django.db import migrations


RUNTIME_OBJECTIVES = [
    "DEVICE_READINESS_CHECK",
    "BASIC_APP_INTERACTION_CHECK",
    "FRIDA_RUNTIME_ACTION",
    "FRIDA_RUNTIME_UI_MODIFICATION_PROOF",
    "FRIDA_CUSTOM_SCRIPT",
    "ASSESSMENT_PLAN_EXECUTION",
]

RUNTIME_TOOLS = [
    "get_device_status",
    "list_packages",
    "install_verified_apk",
    "launch_package",
    "reset_root_detection_demo",
    "prepare_root_detection_demo",
    "force_stop_package",
    "clear_package_data",
    "take_screenshot",
    "start_logcat",
    "stop_logcat",
    "get_logcat_excerpt",
    "start_proxy_capture",
    "stop_proxy_capture",
    "get_proxy_flows",
    "dump_ui",
    "tap_coordinates",
    "type_text",
    "frida_status",
    "frida_ps",
    "frida_setup",
    "frida_attach",
    "frida_run_js",
]


def forwards(apps, schema_editor):
    AgentRuntime = apps.get_model("dynamic_analysis", "AgentRuntime")
    for runtime in AgentRuntime.objects.all():
        capabilities = runtime.capabilities if isinstance(runtime.capabilities, dict) else {}
        objectives = list(capabilities.get("objectives", []))
        tools = list(capabilities.get("tools", []))
        merged_objectives = list(dict.fromkeys(objectives + RUNTIME_OBJECTIVES))
        merged_tools = list(dict.fromkeys(tools + RUNTIME_TOOLS))
        runtime.capabilities = {
            **capabilities,
            "objectives": merged_objectives,
            "tools": merged_tools,
        }
        runtime.save(update_fields=["capabilities", "updated_at"])


def backwards(apps, schema_editor):
    AgentRuntime = apps.get_model("dynamic_analysis", "AgentRuntime")
    added_objectives = set(RUNTIME_OBJECTIVES)
    added_tools = set(
        {
            "prepare_root_detection_demo",
            "start_proxy_capture",
            "stop_proxy_capture",
            "get_proxy_flows",
            "ASSESSMENT_PLAN_EXECUTION",
        }
    )
    for runtime in AgentRuntime.objects.all():
        capabilities = runtime.capabilities if isinstance(runtime.capabilities, dict) else {}
        objectives = [
            item for item in capabilities.get("objectives", [])
            if item not in {"ASSESSMENT_PLAN_EXECUTION"}
        ]
        tools = [
            item for item in capabilities.get("tools", [])
            if item not in {
                "prepare_root_detection_demo",
                "start_proxy_capture",
                "stop_proxy_capture",
                "get_proxy_flows",
            }
        ]
        runtime.capabilities = {
            **capabilities,
            "objectives": objectives,
            "tools": tools,
        }
        runtime.save(update_fields=["capabilities", "updated_at"])


class Migration(migrations.Migration):

    dependencies = [
        ("dynamic_analysis", "0026_budget_adaptive_30"),
    ]

    operations = [
        migrations.RunPython(forwards, backwards),
    ]
