from django.db import migrations


PLAYBOOK_TOOLS = {
    "launch_exported_activity",
    "send_explicit_broadcast",
    "query_exported_provider",
}


def add_playbook_tools(apps, schema_editor):
    AgentRuntime = apps.get_model("dynamic_analysis", "AgentRuntime")
    for runtime in AgentRuntime.objects.filter(runtime_type="INTERNAL_CONTROLLER"):
        capabilities = runtime.capabilities if isinstance(runtime.capabilities, dict) else {}
        tools = set(capabilities.get("tools", [])) | PLAYBOOK_TOOLS
        capabilities["tools"] = sorted(tools)
        runtime.capabilities = capabilities
        runtime.save(update_fields=["capabilities", "updated_at"])


class Migration(migrations.Migration):
    dependencies = [("dynamic_analysis", "0014_dynamicvalidationresult")]

    operations = [
        migrations.RunPython(add_playbook_tools, reverse_code=migrations.RunPython.noop),
    ]
