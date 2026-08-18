"""Conservative deterministic playbook oracles."""
from __future__ import annotations
from typing import Any

CONFIRMED = "CONFIRMED"
REFUTED = "REFUTED"
INCONCLUSIVE = "INCONCLUSIVE"


def _status(evidence: dict[str, Any], *, success_keys: tuple[str, ...]) -> str:
    if not isinstance(evidence, dict):
        return INCONCLUSIVE
    if any(evidence.get(key) is True for key in success_keys):
        return CONFIRMED
    if evidence.get("permission_denied") is True or evidence.get("denied") is True:
        return REFUTED
    return INCONCLUSIVE


def exported_activity_oracle(evidence: dict[str, Any]) -> dict[str, Any]:
    result = _status(evidence, success_keys=("launched", "target_package_running"))
    return {"status": result, "oracle_id": "exported_activity_oracle", "summary": "External launch evidence was observed." if result == CONFIRMED else "Activity launch did not produce decisive evidence."}


def exported_receiver_oracle(evidence: dict[str, Any]) -> dict[str, Any]:
    result = _status(evidence, success_keys=("delivered", "receiver_observed", "target_correlated"))
    return {"status": result, "oracle_id": "exported_receiver_oracle", "summary": "Receiver delivery or target-correlated behavior was observed." if result == CONFIRMED else "Receiver behavior was not decisive."}


def exported_provider_oracle(evidence: dict[str, Any]) -> dict[str, Any]:
    result = _status(evidence, success_keys=("rows_returned", "metadata_returned", "query_succeeded"))
    return {"status": result, "oracle_id": "exported_provider_oracle", "summary": "Read-only provider access returned bounded evidence." if result == CONFIRMED else "Provider access was not decisive."}


def runtime_instrumentation_oracle(evidence: dict[str, Any]) -> dict[str, Any]:
    result = _status(evidence, success_keys=("attach_event_received", "script_loaded", "target_visible"))
    return {"status": result, "oracle_id": "runtime_instrumentation_oracle", "summary": "Runtime instrumentation evidence is correlated with the target." if result == CONFIRMED else "Runtime instrumentation evidence is insufficient."}


def lab_resilience_oracle(evidence: dict[str, Any]) -> dict[str, Any]:
    events = evidence.get("frida_events", []) if isinstance(evidence, dict) else []
    if not events and isinstance(evidence, dict):
        events = evidence.get("events", [])
    names = {item.get("event") or item.get("type") for item in events if isinstance(item, dict)}
    modified = {"lab_root_bypass_applied", "lab_emulator_bypass_applied"} & names
    before = evidence.get("before_screenshot") or evidence.get("before_screenshot_sha256")
    after = evidence.get("after_screenshot") or evidence.get("after_screenshot_sha256")
    if modified and before and after:
        return {"status": CONFIRMED, "oracle_id": "lab_resilience_oracle", "summary": "The approved lab template produced a target-correlated modification event with before/after screenshot evidence."}
    return {"status": INCONCLUSIVE, "oracle_id": "lab_resilience_oracle", "summary": "The lab template or complete before/after evidence was not observed."}


def root_detection_screen_oracle(evidence: dict[str, Any]) -> dict[str, Any]:
    """Confirm the real AndroGoat root-control screen was observed.

    This is intentionally an observation oracle.  It does not infer a bypass,
    and it does not need ADB root or a Frida server.  A screenshot plus a
    target-correlated UI hierarchy containing the control's result is enough
    for the auditor to see what the app actually reported.
    """
    if not isinstance(evidence, dict):
        return {"status": INCONCLUSIVE, "oracle_id": "root_detection_screen_oracle", "summary": "The root-detection screen evidence was not available."}
    values = " ".join(str(value) for value in evidence.get("text_values", [])).lower()
    preview = str(evidence.get("raw_preview") or "").lower()
    screen_text = f"{values} {preview}"
    target = evidence.get("focused_package") == "owasp.sat.agoat" or evidence.get("target_package_running") is True
    screenshot = bool(evidence.get("object_reference_id") or evidence.get("screenshot_sha256"))
    control_visible = any(term in screen_text for term in ("root", "rooted", "su binary", "rootbeer"))
    if target and screenshot and control_visible:
        return {"status": CONFIRMED, "oracle_id": "root_detection_screen_oracle", "summary": "AndroGoat's root-detection control was observed on the authorized emulator with real screenshot and UI evidence."}
    return {"status": INCONCLUSIVE, "oracle_id": "root_detection_screen_oracle", "summary": "The authorized app ran, but a target-correlated root-detection result and screenshot were not both observed."}


def root_detection_frida_oracle(evidence: dict[str, Any]) -> dict[str, Any]:
    events = evidence.get("events", []) if isinstance(evidence, dict) else []
    names = {item.get("type") for item in events if isinstance(item, dict)}
    changed = "root_detection_native_hooks_installed" in names
    before = str(evidence.get("before_screenshot_sha256") or "")
    after = str(evidence.get("after_screenshot_sha256") or "")
    values = " ".join(str(value) for value in evidence.get("text_values", [])).lower() if isinstance(evidence, dict) else ""
    rooted_visible = "device is rooted" in values
    if changed and before and after and before != after and rooted_visible:
        return {"status": CONFIRMED, "oracle_id": "root_detection_frida_oracle", "summary": "Approved Frida instrumentation ran against AndroGoat and produced a real Device is rooted after-state, with distinct before/after screenshots and UI evidence."}
    return {"status": INCONCLUSIVE, "oracle_id": "root_detection_frida_oracle", "summary": "The approved Frida event, distinct before/after screenshots, and rooted after-state UI were not all observed."}


def tls_runtime_oracle(evidence: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(evidence, dict) or not evidence.get("target_network_flow_exercised"):
        return {"status": INCONCLUSIVE, "oracle_id": "tls_runtime_oracle", "summary": "Static risk requires a runtime workflow exercising network calls."}
    return {"status": _status(evidence, success_keys=("tls_success", "user_ca_accepted")), "oracle_id": "tls_runtime_oracle", "summary": "Target-correlated TLS evidence was evaluated."}


def not_assessable_oracle(evidence: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"status": "NOT_ASSESSABLE", "oracle_id": "not_assessable_oracle", "summary": "Not assessable with current capabilities."}


ORACLES = {name: value for name, value in {
    "exported_activity_oracle": exported_activity_oracle,
    "exported_receiver_oracle": exported_receiver_oracle,
    "exported_provider_oracle": exported_provider_oracle,
    "runtime_instrumentation_oracle": runtime_instrumentation_oracle,
    "lab_resilience_oracle": lab_resilience_oracle,
    "root_detection_screen_oracle": root_detection_screen_oracle,
    "root_detection_frida_oracle": root_detection_frida_oracle,
    "tls_runtime_oracle": tls_runtime_oracle,
    "not_assessable_oracle": not_assessable_oracle,
}.items()}
