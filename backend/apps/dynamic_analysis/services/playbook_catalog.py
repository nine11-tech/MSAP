"""Backend-owned finding-driven dynamic playbook catalog.

Playbooks are data, not model instructions.  Keep this module deterministic and
small: provider output may select an entry, but cannot create one.
"""
from __future__ import annotations

from copy import deepcopy
from typing import Any


CATALOG_VERSION = "msap.dynamic-playbook/v1"


def _playbook(
    playbook_id: str,
    title: str,
    description: str,
    rules: tuple[str, ...],
    tools: tuple[str, ...],
    evidence: tuple[str, ...],
    oracle_id: str,
    status: str,
    priority: int,
    limitations: str,
    *,
    objective_keywords: tuple[str, ...] = (),
    requires_additional_approval: bool = False,
) -> dict[str, Any]:
    return {
        "playbook_id": playbook_id,
        "title": title,
        "description": description,
        "applicable_static_rule_ids": list(rules),
        "masvs_mapping": ["MASVS-RESILIENCE-1", "MASVS-ARCH-1"],
        "required_evidence_inputs": list(evidence),
        "supported_tools": list(tools),
        "required_capabilities": list(tools),
        "safe_argument_policy": "backend-owned manifest component and target-package constraints",
        "oracle_id": oracle_id,
        "result_states": ["CONFIRMED", "REFUTED", "INCONCLUSIVE"],
        "limitations": limitations,
        "destructive": False,
        "requires_additional_approval": requires_additional_approval,
        "objective_keywords": list(objective_keywords),
        "default_priority": priority,
        "current_capability_status": status,
    }


PLAYBOOK_CATALOG: tuple[dict[str, Any], ...] = (
    _playbook("DEBUGGABLE_APP_VERIFICATION", "Debuggable app verification", "Correlate the static debuggable finding with bounded runtime process visibility and approved instrumentation evidence.", ("MSAP-AND-001",), ("frida_status", "frida_ps", "frida_attach"), ("tool_output",), "runtime_instrumentation_oracle", "AVAILABLE", 100, "Confirms runtime instrumentation feasibility, not exploitability."),
    _playbook("EXPORTED_ACTIVITY_LAUNCH_VERIFICATION", "Exported activity launch verification", "Attempt one explicit launch of an exported activity from the authorized target manifest.", ("MSAP-AND-004",), ("launch_exported_activity", "dump_ui", "take_screenshot"), ("tool_output", "ui_hierarchy", "screenshot"), "exported_activity_oracle", "AVAILABLE", 95, "Only manifest-inventory activities are eligible; no arbitrary intents or extras."),
    _playbook("EXPORTED_RECEIVER_BROADCAST_VERIFICATION", "Exported receiver broadcast verification", "Send one bounded explicit broadcast to an exported receiver using a manifest-declared action.", ("MSAP-AND-006",), ("send_explicit_broadcast", "get_logcat_excerpt"), ("tool_output", "logcat"), "exported_receiver_oracle", "AVAILABLE", 90, "No arbitrary actions or extras; lack of observable behavior is inconclusive."),
    _playbook("EXPORTED_PROVIDER_ACCESS_VERIFICATION", "Exported provider access verification", "Perform a read-only metadata/query check against an exported provider authority.", ("MSAP-AND-007",), ("query_exported_provider",), ("tool_output",), "exported_provider_oracle", "AVAILABLE", 90, "URI is built as content://authority/; no writes and no full sensitive rows."),
    _playbook("TLS_USER_CA_DYNAMIC_VALIDATION", "TLS user-CA runtime validation", "Look for target-correlated TLS/network observations after a bounded app workflow.", ("MSAP-AND-016", "MSAP-AND-029"), ("get_logcat_excerpt",), ("logcat",), "tls_runtime_oracle", "PARTIAL", 80, "Without an exercised target network flow the result is inconclusive."),
    _playbook("BACKUP_ENABLED_DYNAMIC_NOTE", "Backup enabled dynamic note", "Record that safe backup/restore validation is unavailable in the current capability envelope.", ("MSAP-AND-002",), (), (), "not_assessable_oracle", "NOT_ASSESSABLE_WITH_CURRENT_CAPABILITIES", 40, "No arbitrary adb shell, backup archive, or broad filesystem access is permitted."),
    _playbook("DEBUG_SIGNING_CERT_DYNAMIC_NOTE", "Debug signing certificate dynamic note", "Keep the conclusive signing property as static evidence without spending runtime actions.", ("MSAP-AND-023",), (), (), "not_assessable_oracle", "STATIC_CONFIRMED_RUNTIME_NOT_REQUIRED", 35, "Signing certificate status is primarily a static property."),
    _playbook("ROOT_SIGNAL_OBSERVATION", "Root-signal observation", "Observe bounded root-detection API signals in the authorized app without bypassing them.", (), ("frida_status", "frida_attach", "frida_run_js"), ("tool_output", "logcat"), "runtime_instrumentation_oracle", "AVAILABLE", 60, "Observation only. No root checks are bypassed; a separate lab-only bypass requires explicit additional approval."),
    _playbook("EMULATOR_SIGNAL_OBSERVATION", "Emulator-signal observation", "Record bounded emulator-detection signals used by the authorized app without changing them.", (), ("frida_status", "frida_attach", "frida_run_js"), ("tool_output",), "runtime_instrumentation_oracle", "AVAILABLE", 55, "Observation only. The template reports signals and never spoofs device properties."),
    _playbook("ROOT_DETECTION_LAB_BYPASS", "Root detection lab resilience", "On an explicitly authorized lab target, compare the root-detection screen before and after a backend-owned bounded resilience template.", (), ("launch_package", "take_screenshot", "frida_run_js"), ("screenshot", "frida_events", "tool_output"), "lab_resilience_oracle", "AVAILABLE", 70, "Lab-only and auditor-approved. This tests resilience; it is not an exploit and cannot run arbitrary scripts.", objective_keywords=("root", "root detection", "rooted"), requires_additional_approval=True),
    _playbook("ROOT_DETECTION_SCREEN_VALIDATION", "Root detection Frida UI proof", "Reset the fixed AndroGoat lab signal, click Check Root to capture Device is not rooted, apply the backend-owned Frida native hook template, and capture Device is rooted.", (), ("reset_root_detection_demo", "launch_package", "tap_coordinates", "take_screenshot", "frida_run_js", "dump_ui"), ("screenshot", "ui_hierarchy", "frida_events", "tool_output"), "root_detection_frida_oracle", "AVAILABLE", 80, "Lab-only and auditor-approved. Reset is restricted to one fixed AndroGoat marker; the Frida template cannot run arbitrary scripts or access host resources.", objective_keywords=("root", "root detection", "rooted")),
    _playbook("EMULATOR_DETECTION_LAB_BYPASS", "Emulator detection lab resilience", "On an explicitly authorized lab target, compare the emulator-detection screen before and after a backend-owned bounded resilience template.", (), ("launch_package", "take_screenshot", "frida_run_js"), ("screenshot", "frida_events", "tool_output"), "lab_resilience_oracle", "AVAILABLE", 65, "Lab-only and auditor-approved. This tests resilience; it is not an exploit and cannot run arbitrary scripts.", objective_keywords=("emulator", "emulator detection", "virtual device"), requires_additional_approval=True),
)

_BY_ID = {item["playbook_id"]: item for item in PLAYBOOK_CATALOG}
_BY_RULE = {rule: [item["playbook_id"] for item in PLAYBOOK_CATALOG if rule in item["applicable_static_rule_ids"]] for rule in {rule for item in PLAYBOOK_CATALOG for rule in item["applicable_static_rule_ids"]}}


def playbooks_for_finding(finding: Any) -> list[dict[str, Any]]:
    """Map one bounded static finding to executable catalog playbooks.

    Rule IDs are authoritative when present.  Root/emulator detections are
    often emitted by SDK/triage analyzers with project-specific rule IDs, so
    their bounded title/category text is also used.  No source code or report
    blob is inspected here.
    """
    row = finding if isinstance(finding, dict) else {
        "rule_id": getattr(finding, "rule_id", ""),
        "title": getattr(finding, "title", ""),
        "category": getattr(finding, "category", ""),
        "description": getattr(finding, "description", ""),
    }
    rule_id = str(row.get("rule_id") or "")
    text = " ".join(str(row.get(key) or "") for key in ("title", "category", "description")).lower()
    # Text classification wins when an analyzer uses a generic rule id for a
    # more specific root/emulator control.
    if any(term in text for term in ("root detection", "rootbeer", "rooted device", "root check")):
        return [get_playbook("ROOT_DETECTION_SCREEN_VALIDATION")]  # type: ignore[list-item]
    if any(term in text for term in ("emulator detection", "emulator check", "virtual device", "emulator posture")):
        return [get_playbook("EMULATOR_DETECTION_LAB_BYPASS")]  # type: ignore[list-item]
    explicit = playbooks_for_rule(rule_id)
    if explicit:
        return explicit
    if "debuggable" in text or "instrumentation" in text:
        return [get_playbook("DEBUGGABLE_APP_VERIFICATION")]  # type: ignore[list-item]
    return []


def executable_playbooks_for_finding(finding: Any) -> list[dict[str, Any]]:
    """Return only catalog entries that can produce useful runtime evidence."""
    return [
        item for item in playbooks_for_finding(finding)
        if item.get("current_capability_status") == "AVAILABLE"
        and item.get("supported_tools")
    ]


def get_playbook(playbook_id: str) -> dict[str, Any] | None:
    item = _BY_ID.get(playbook_id)
    return deepcopy(item) if item else None


def list_playbooks() -> list[dict[str, Any]]:
    return [deepcopy(item) for item in PLAYBOOK_CATALOG]


def playbooks_for_rule(rule_id: str) -> list[dict[str, Any]]:
    return [deepcopy(_BY_ID[item]) for item in _BY_RULE.get(rule_id, [])]


def playbooks_for_objective(objective: str) -> list[dict[str, Any]]:
    normalized = str(objective or "").lower()
    return [
        deepcopy(item) for item in PLAYBOOK_CATALOG
        if item.get("objective_keywords") and any(keyword in normalized for keyword in item["objective_keywords"])
    ]


def validate_playbook_selection(playbook_id: str, *, available_tools: set[str] | None = None) -> dict[str, Any]:
    item = _BY_ID.get(playbook_id)
    if item is None:
        raise ValueError("The selected playbook is not in the backend catalog.")
    if available_tools is not None and not set(item["required_capabilities"]) <= available_tools:
        raise ValueError("The selected playbook requires unavailable capabilities.")
    return deepcopy(item)


def summarize_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return compact, deterministic finding/playbook context for an agent."""
    result = []
    for row in findings[:25]:
        rule_id = str(row.get("rule_id") or "")
        result.append({
            "finding_id": row.get("id"),
            "rule_id": rule_id,
            "title": str(row.get("title") or "")[:255],
            "severity": row.get("severity"),
            "confidence": row.get("confidence"),
            "category": str(row.get("category") or "")[:128],
            "status": row.get("status", "OPEN"),
            "source_type": "STATIC_ANALYZER",
            "evidence_summary": str(row.get("description") or "")[:600],
            "recommended_playbook_ids": [p["playbook_id"] for p in playbooks_for_finding(row)],
        })
    return result
