"""Descriptive dynamic capability registry (msap.dynamic-capability-manifest/v1).

This registry is the AI-facing description of the real Tool Gateway. It maps
every implemented capability to a stable ID, a human description, its input
schema, the evidence it produces, applicable contexts, and its risk/approval
class. The registry never invents capabilities: only tools that exist in the
real ``agent_tools.TOOL_MANIFEST`` appear here.
"""
from __future__ import annotations

from hashlib import sha256
import json
from typing import Any

from apps.dynamic_analysis.models import AgentRuntime
from apps.dynamic_analysis.services.agent_capability_envelope import (
    ADDITIONAL_APPROVAL_CAPABILITIES,
    AGENTIC_SAFE_CAPABILITIES,
    ALL_AGENTIC_SAFE_CAPABILITIES,
    DESTRUCTIVE_CAPABILITIES,
)
from apps.dynamic_analysis.services.agent_tools import ALL_TOOL_NAMES, TOOL_MANIFEST


CAPABILITY_MANIFEST_VERSION = "msap.dynamic-capability-manifest/v1"

CAPABILITY_DESCRIPTIONS: dict[str, str] = {
    "get_device_status": "Inspect the managed Android device readiness, version, and foreground state.",
    "list_packages": "List the bounded set of installed third-party applications.",
    "install_verified_apk": "Install the audit-verified APK on the managed device.",
    "launch_package": "Launch the authorized target application.",
    "force_stop_package": "Force-stop the authorized target application.",
    "clear_package_data": "Clear the authorized target application data (destructive).",
    "take_screenshot": "Capture a bounded screenshot of the current screen.",
    "start_logcat": "Start a bounded target-correlated logcat capture window.",
    "stop_logcat": "Stop the active bounded logcat capture window.",
    "get_logcat_excerpt": "Read a bounded excerpt of the target-correlated logcat capture.",
    "dump_ui": "Dump the current UI hierarchy (resource ids and text values).",
    "tap_coordinates": "Execute a bounded approved UI tap interaction.",
    "type_text": "Enter bounded approved text into the focused UI control.",
    "frida_status": "Check Frida client/server agreement and attach capability.",
    "frida_ps": "List the bounded set of running processes visible to Frida.",
    "frida_setup": "Prepare the Frida instrumentation runtime on the device.",
    "frida_attach": "Attach the approved Frida instrumentation to the target process.",
    "frida_run_js": "Run a backend-owned controlled Frida proof template.",
    "launch_exported_activity": "Launch an exported activity from the audit manifest inventory.",
    "send_explicit_broadcast": "Send an explicit broadcast to an exported receiver from the manifest inventory.",
    "query_exported_provider": "Query an exported content provider authority from the manifest inventory.",
    "reset_root_detection_demo": "Reset the AndroGoat root-detection lab demo marker (fixture only).",
}

EVIDENCE_BY_CAPABILITY: dict[str, list[str]] = {
    "get_device_status": ["tool_output"],
    "list_packages": ["tool_output"],
    "install_verified_apk": ["tool_output"],
    "launch_package": ["tool_output", "screenshot"],
    "force_stop_package": ["tool_output"],
    "clear_package_data": ["tool_output"],
    "take_screenshot": ["screenshot"],
    "start_logcat": ["logcat"],
    "stop_logcat": ["logcat"],
    "get_logcat_excerpt": ["logcat"],
    "dump_ui": ["ui_hierarchy"],
    "tap_coordinates": ["tool_output", "ui_hierarchy"],
    "type_text": ["tool_output", "ui_hierarchy"],
    "frida_status": ["tool_output"],
    "frida_ps": ["tool_output"],
    "frida_setup": ["tool_output"],
    "frida_attach": ["frida_events", "tool_output"],
    "frida_run_js": ["frida_events", "logcat", "screenshot", "before_after_comparison"],
    "launch_exported_activity": ["tool_output", "screenshot", "ui_hierarchy"],
    "send_explicit_broadcast": ["tool_output"],
    "query_exported_provider": ["tool_output"],
    "reset_root_detection_demo": ["tool_output"],
}

CONTEXT_BY_CAPABILITY: dict[str, list[str]] = {
    "get_device_status": ["device", "baseline"],
    "list_packages": ["device", "baseline"],
    "install_verified_apk": ["device", "deployment"],
    "launch_package": ["app", "workflow"],
    "force_stop_package": ["app", "cleanup"],
    "clear_package_data": ["app", "cleanup"],
    "take_screenshot": ["ui", "evidence"],
    "start_logcat": ["logging", "observation"],
    "stop_logcat": ["logging", "cleanup"],
    "get_logcat_excerpt": ["logging", "evidence"],
    "dump_ui": ["ui", "observation"],
    "tap_coordinates": ["ui", "interaction"],
    "type_text": ["ui", "interaction"],
    "frida_status": ["runtime", "instrumentation"],
    "frida_ps": ["runtime", "instrumentation"],
    "frida_setup": ["runtime", "instrumentation"],
    "frida_attach": ["runtime", "instrumentation"],
    "frida_run_js": ["runtime", "instrumentation"],
    "launch_exported_activity": ["components", "activities"],
    "send_explicit_broadcast": ["components", "receivers"],
    "query_exported_provider": ["components", "providers"],
    "reset_root_detection_demo": ["lab", "fixture"],
}


def _risk_class(tool_name: str) -> dict[str, Any]:
    if tool_name in DESTRUCTIVE_CAPABILITIES:
        approval = "additional_approval"
        risk = "destructive"
    elif tool_name in ADDITIONAL_APPROVAL_CAPABILITIES:
        approval = "additional_approval"
        risk = "elevated"
    elif tool_name in ALL_AGENTIC_SAFE_CAPABILITIES:
        approval = "auditor_approved"
        risk = "low"
    else:
        approval = "auditor_approved"
        risk = "low"
    return {"risk_class": risk, "approval_class": approval}


def describe_capability(tool_name: str) -> str:
    return CAPABILITY_DESCRIPTIONS.get(
        str(tool_name),
        f"Execute the approved {tool_name} capability through the Tool Gateway.",
    )


def evidence_produced_by_capability(tool_name: str) -> list[str]:
    return list(EVIDENCE_BY_CAPABILITY.get(str(tool_name), ["tool_output"]))


def build_capability_manifest(
    *,
    host_agent_connected: bool,
    runtime_tools: set[str] | None = None,
) -> dict[str, Any]:
    """Build the current descriptive capability manifest.

    ``runtime_tools`` is the live AgentRuntime tool allowlist when available.
    A capability is ``available`` only when it is implemented in the Tool
    Gateway and the current runtime exposes it.
    """
    runtime_tools = set(runtime_tools or set(ALL_TOOL_NAMES))
    capabilities: list[dict[str, Any]] = []
    available_ids: list[str] = []
    unavailable_ids: list[str] = []
    for name in sorted(ALL_TOOL_NAMES):
        spec = TOOL_MANIFEST[name]
        risk = _risk_class(name)
        is_available = name in runtime_tools and host_agent_connected
        entry = {
            "capability_id": name,
            "description": describe_capability(name),
            "input_schema": dict(spec.input_schema),
            "evidence_produced": evidence_produced_by_capability(name),
            "applicable_contexts": list(CONTEXT_BY_CAPABILITY.get(name, [])),
            "risk_class": risk["risk_class"],
            "approval_class": risk["approval_class"],
            "available": is_available,
        }
        capabilities.append(entry)
        if is_available:
            available_ids.append(name)
        else:
            unavailable_ids.append(name)
    manifest = {
        "contract_version": CAPABILITY_MANIFEST_VERSION,
        "host_agent_connected": bool(host_agent_connected),
        "capabilities": capabilities,
        "available_capabilities": available_ids,
        "unavailable_capabilities": unavailable_ids,
    }
    return manifest


def capability_manifest_hash(manifest: dict[str, Any]) -> str:
    canonical = json.dumps(
        manifest,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return sha256(canonical.encode("utf-8")).hexdigest()


def live_capability_manifest(
    *,
    host_agent_connected: bool | None = None,
    runtime: AgentRuntime | None = None,
) -> dict[str, Any]:
    """Build the manifest from live lab state (cheap, no device actions)."""
    if runtime is None:
        runtime = (
            AgentRuntime.objects.filter(
                status=AgentRuntime.Status.AVAILABLE,
                enabled=True,
            )
            .order_by("id")
            .first()
        )
    runtime_tools = None
    if runtime is not None and isinstance(runtime.capabilities, dict):
        tools = runtime.capabilities.get("tools")
        if isinstance(tools, list):
            runtime_tools = {str(item) for item in tools}
    return build_capability_manifest(
        host_agent_connected=bool(host_agent_connected),
        runtime_tools=runtime_tools,
    )


def summarize_manifest(manifest: dict[str, Any]) -> str:
    """Compact human sentence describing the manifest for auditor messages."""
    available = manifest.get("available_capabilities", [])
    if not isinstance(available, list):
        available = []
    return f"{len(available)} dynamic capabilities available."