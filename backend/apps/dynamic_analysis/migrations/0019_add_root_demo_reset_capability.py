from django.db import migrations


def add_root_demo_reset_capability(apps, schema_editor):
    AgentRuntime = apps.get_model("dynamic_analysis", "AgentRuntime")
    for runtime in AgentRuntime.objects.filter(enabled=True):
        capabilities = dict(runtime.capabilities or {})
        tools = list(capabilities.get("tools") or [])
        if "reset_root_detection_demo" not in tools:
            capabilities["tools"] = sorted({*tools, "reset_root_detection_demo"})
            runtime.capabilities = capabilities
            runtime.save(update_fields=["capabilities", "updated_at"])


class Migration(migrations.Migration):
    dependencies = [("dynamic_analysis", "0018_alter_dynamicvalidationresult_validation_status")]

    operations = [migrations.RunPython(add_root_demo_reset_capability, migrations.RunPython.noop)]
