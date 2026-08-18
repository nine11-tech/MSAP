"""Authorization helpers for manifest-derived playbook arguments."""
from __future__ import annotations


def authorize_manifest_component(*, package_name: str, component_name: str, components: list[dict], component_type: str, require_unprotected: bool = False) -> dict:
    if not component_name.startswith(package_name + "."):
        raise ValueError("Component is outside the authorized package.")
    matches = [item for item in components if item.get("type") == component_type and item.get("name") == component_name]
    if len(matches) != 1 or matches[0].get("exported") is not True:
        raise ValueError("Component must be an exported component from static analyzer inventory.")
    if require_unprotected and any(matches[0].get(key) for key in ("permission", "read_permission", "write_permission")):
        raise ValueError("Component is protected and is not eligible for this playbook.")
    return matches[0]


def authorize_provider_authority(*, package_name: str, authority: str, components: list[dict]) -> dict:
    if "/" in authority or ".." in authority or not authority:
        raise ValueError("Provider authority must be a manifest authority, not a path.")
    for item in components:
        if item.get("type") == "provider" and item.get("exported") is True and item.get("name", "").startswith(package_name + "."):
            authorities = {part.strip() for part in str(item.get("authorities") or "").split(";") if part.strip()}
            if authority in authorities:
                if item.get("read_permission") or item.get("permission"):
                    raise ValueError("Provider requires a permission and is not eligible for this playbook.")
                return item
    raise ValueError("Provider authority is not in the exported manifest inventory.")
