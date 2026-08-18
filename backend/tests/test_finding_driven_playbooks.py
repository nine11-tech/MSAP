import pytest

from apps.dynamic_analysis.services.playbook_authorization import (
    authorize_manifest_component,
    authorize_provider_authority,
)
from apps.dynamic_analysis.services.playbook_catalog import (
    CATALOG_VERSION,
    list_playbooks,
    playbooks_for_rule,
    validate_playbook_selection,
    playbooks_for_finding,
)
from apps.dynamic_analysis.services.playbook_oracles import (
    CONFIRMED,
    INCONCLUSIVE,
    REFUTED,
    exported_activity_oracle,
    exported_provider_oracle,
    tls_runtime_oracle,
)


def test_catalog_is_closed_and_maps_high_value_rules():
    items = list_playbooks()
    assert CATALOG_VERSION == "msap.dynamic-playbook/v1"
    assert len({item["playbook_id"] for item in items}) == len(items)
    assert playbooks_for_rule("MSAP-AND-004")[0]["playbook_id"] == "EXPORTED_ACTIVITY_LAUNCH_VERIFICATION"
    with pytest.raises(ValueError):
        validate_playbook_selection("MODEL_INVENTED_PLAYBOOK")


def test_root_and_unrelated_findings_are_separated_for_auditor_ux():
    root = {"rule_id": "SDK-ROOT-001", "title": "Root detection via RootBeer", "category": "MASVS-RESILIENCE"}
    unrelated = {"rule_id": "CUSTOM-001", "title": "Unused resource", "category": "QUALITY"}
    assert playbooks_for_finding(root)[0]["playbook_id"] == "ROOT_DETECTION_SCREEN_VALIDATION"
    assert playbooks_for_finding(unrelated) == []


def test_oracles_are_conservative():
    assert exported_activity_oracle({"launched": True})["status"] == CONFIRMED
    assert exported_activity_oracle({"permission_denied": True})["status"] == REFUTED
    assert exported_activity_oracle({})["status"] == INCONCLUSIVE
    assert exported_provider_oracle({"rows_returned": True})["status"] == CONFIRMED
    assert tls_runtime_oracle({})["status"] == INCONCLUSIVE


def test_manifest_authorization_rejects_arbitrary_targets():
    components = [{"type": "activity", "name": "com.example.Export", "exported": True}]
    assert authorize_manifest_component(package_name="com.example", component_name="com.example.Export", components=components, component_type="activity")["name"] == "com.example.Export"
    with pytest.raises(ValueError):
        authorize_manifest_component(package_name="com.example", component_name="com.other.Export", components=components, component_type="activity")
    with pytest.raises(ValueError):
        authorize_provider_authority(package_name="com.example", authority="com.example.provider/../secret", components=[])
