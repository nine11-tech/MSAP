from __future__ import annotations

from hashlib import sha256
import re
from typing import Any

from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
from django.utils import timezone

from apps.api.roles import user_role
from apps.dynamic_analysis.models import (
    AgentHypothesis,
    AgentRun,
    FridaScriptProposal,
)
from apps.dynamic_analysis.services.openai_budget import (
    KIND_DECISION,
    OpenAIBudgetExhausted,
    record_response_id,
    release_call,
    reserve_call,
)


GENERATED_FRIDA_SOURCE_PREFIX = "__MSAP_APPROVED_GENERATED_FRIDA_SCRIPT__"
GENERATED_FRIDA_SOURCE_RE = re.compile(
    rf"^{re.escape(GENERATED_FRIDA_SOURCE_PREFIX)}:(?P<id>[1-9][0-9]*):(?P<sha>[a-f0-9]{{16}})$"
)
MAX_GENERATED_FRIDA_SCRIPT_BYTES = 32 * 1024
FRIDA_SCRIPT_SCHEMA_NAME = "msap_generated_frida_script"
FRIDA_SCRIPT_SYSTEM_INSTRUCTIONS = """
You generate one Frida JavaScript proposal for an authorized Android dynamic security assessment.
Return only the strict JSON schema. The script must be observation-first, bounded, and likely to run.
Do not include shell, adb, filesystem, Docker, Python, secrets, tokens, network exfiltration, or host paths.
The script may use Frida Java APIs and must emit at least one send({...}) event for evidence.
Prefer Java.perform and safe try/catch blocks. Keep the script short and explain the expected evidence.
The backend and auditor must approve before execution; you are proposing, not executing.
""".strip()
FRIDA_SCRIPT_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "title": {"type": "string", "minLength": 1, "maxLength": 200},
        "rationale": {"type": "string", "minLength": 1, "maxLength": 1000},
        "expected_evidence": {
            "type": "array",
            "maxItems": 6,
            "items": {"type": "string", "minLength": 1, "maxLength": 120},
        },
        "source_code": {
            "type": "string",
            "minLength": 1,
            "maxLength": MAX_GENERATED_FRIDA_SCRIPT_BYTES,
        },
    },
    "required": ["title", "rationale", "expected_evidence", "source_code"],
    "additionalProperties": False,
}
FORBIDDEN_SCRIPT_RE = re.compile(
    r"(\bRuntime\.getRuntime\s*\(|\bProcessBuilder\b|\bjava\.net\.|"
    r"\bSocket\b|\bWebSocket\b|\bXMLHttpRequest\b|\bfetch\s*\(|"
    r"\bOkHttpClient\b|\.env\b|/home/|/mnt/|Authorization|api[_-]?key|"
    r"password|credential|token|secret)",
    re.IGNORECASE,
)


class FridaScriptProposalError(RuntimeError):
    def __init__(self, message: str, *, code: str, http_status: int = 409):
        super().__init__(message)
        self.code = code
        self.http_status = http_status


def is_generated_frida_source_identifier(value: Any) -> bool:
    return isinstance(value, str) and GENERATED_FRIDA_SOURCE_RE.fullmatch(value) is not None


def generate_frida_script_proposal(
    *,
    run: AgentRun,
    requested_by,
    hypothesis_id: int | None = None,
) -> FridaScriptProposal:
    _authorize_generation(run, requested_by)
    hypothesis = _select_hypothesis(run, hypothesis_id)
    generated, provider, model, metadata = _generate_script_payload(run, hypothesis)
    return create_frida_script_proposal(
        run=run,
        requested_by=requested_by,
        hypothesis=hypothesis,
        title=generated["title"],
        rationale=generated["rationale"],
        expected_evidence=generated["expected_evidence"],
        source_code=generated["source_code"],
        generator_provider=provider,
        generator_model=model,
        provider_metadata=metadata,
    )


def create_frida_script_proposal(
    *,
    run: AgentRun,
    requested_by,
    title: str,
    rationale: str,
    expected_evidence: list[str],
    source_code: str,
    hypothesis: AgentHypothesis | None = None,
    generator_provider: str = "DETERMINISTIC",
    generator_model: str = "",
    provider_metadata: dict[str, Any] | None = None,
) -> FridaScriptProposal:
    _authorize_generation(run, requested_by)
    warnings = validate_generated_frida_script_source(source_code)
    digest = sha256(source_code.encode("utf-8")).hexdigest()
    try:
        mission = run.finding_validation_mission
    except ObjectDoesNotExist:
        mission = None
    proposal = FridaScriptProposal.objects.create(
        run=run,
        audit=run.audit,
        finding=mission.finding if mission else None,
        mission=mission,
        hypothesis=hypothesis,
        title=_bounded_text(title, 200, required=True),
        rationale=_bounded_text(rationale, 1000, required=True),
        expected_evidence=[
            _bounded_text(item, 120, required=True)
            for item in (expected_evidence or [])[:6]
            if isinstance(item, str) and item.strip()
        ],
        source_sha256=digest,
        source_code=source_code,
        source_size_bytes=len(source_code.encode("utf-8")),
        generator_provider=generator_provider[:32],
        generator_model=generator_model[:128],
        provider_metadata=_safe_metadata(provider_metadata or {}),
        validation_warnings=warnings,
        created_by=requested_by,
    )
    proposal.source_identifier = _source_identifier(proposal.id, digest)
    proposal.save(update_fields=["source_identifier", "updated_at"])
    return proposal


def approve_frida_script_proposal(
    *,
    proposal: FridaScriptProposal,
    approved_by,
) -> FridaScriptProposal:
    if user_role(approved_by) not in {"ADMIN", "ANALYST"}:
        raise FridaScriptProposalError(
            "Only an Analyst or Admin can approve Frida scripts.",
            code="FRIDA_SCRIPT_APPROVAL_DENIED",
            http_status=403,
        )
    if proposal.status != FridaScriptProposal.Status.GENERATED:
        raise FridaScriptProposalError(
            "Only generated Frida script proposals can be approved.",
            code="FRIDA_SCRIPT_NOT_APPROVABLE",
        )
    validate_generated_frida_script_source(proposal.source_code)
    proposal.status = FridaScriptProposal.Status.APPROVED
    proposal.approved_by = approved_by
    proposal.approved_at = timezone.now()
    proposal.last_error = ""
    proposal.suggested_fix = ""
    proposal.save(
        update_fields=[
            "status",
            "approved_by",
            "approved_at",
            "last_error",
            "suggested_fix",
            "updated_at",
        ]
    )
    return proposal


def reject_frida_script_proposal(
    *,
    proposal: FridaScriptProposal,
    rejected_by,
    reason: str = "",
) -> FridaScriptProposal:
    if user_role(rejected_by) not in {"ADMIN", "ANALYST"}:
        raise FridaScriptProposalError(
            "Only an Analyst or Admin can reject Frida scripts.",
            code="FRIDA_SCRIPT_REJECTION_DENIED",
            http_status=403,
        )
    if proposal.status not in {
        FridaScriptProposal.Status.GENERATED,
        FridaScriptProposal.Status.APPROVED,
        FridaScriptProposal.Status.FAILED,
    }:
        raise FridaScriptProposalError(
            "This Frida script proposal cannot be rejected.",
            code="FRIDA_SCRIPT_NOT_REJECTABLE",
        )
    proposal.status = FridaScriptProposal.Status.REJECTED
    proposal.last_error = _bounded_text(reason, 1000)
    proposal.suggested_fix = ""
    proposal.save(update_fields=["status", "last_error", "suggested_fix", "updated_at"])
    return proposal


def resolve_approved_generated_frida_source(
    source_identifier: str,
    *,
    run: AgentRun | None = None,
    requested_by=None,
    target_package: str = "",
) -> str:
    match = GENERATED_FRIDA_SOURCE_RE.fullmatch(source_identifier or "")
    if match is None:
        raise FridaScriptProposalError(
            "Frida source identifier is not a generated-script approval reference.",
            code="FRIDA_SCRIPT_IDENTIFIER_INVALID",
        )
    proposal = FridaScriptProposal.objects.select_related("run").filter(
        pk=int(match.group("id")),
    ).first()
    if proposal is None or proposal.source_sha256[:16] != match.group("sha"):
        raise FridaScriptProposalError(
            "Approved Frida script reference was not found.",
            code="FRIDA_SCRIPT_REFERENCE_UNKNOWN",
        )
    if proposal.status not in {
        FridaScriptProposal.Status.APPROVED,
        FridaScriptProposal.Status.EXECUTED,
    }:
        raise FridaScriptProposalError(
            "Generated Frida script has not been auditor-approved.",
            code="FRIDA_SCRIPT_NOT_APPROVED",
            http_status=403,
        )
    if run is not None and proposal.run_id != run.id:
        raise FridaScriptProposalError(
            "Generated Frida script approval belongs to a different AgentRun.",
            code="FRIDA_SCRIPT_RUN_MISMATCH",
            http_status=403,
        )
    if target_package and proposal.run.target_package != target_package:
        raise FridaScriptProposalError(
            "Generated Frida script target package does not match the tool call.",
            code="FRIDA_SCRIPT_TARGET_MISMATCH",
            http_status=403,
        )
    if requested_by is not None and user_role(requested_by) not in {"ADMIN", "ANALYST"}:
        raise FridaScriptProposalError(
            "Only an Analyst or Admin can execute approved Frida scripts.",
            code="FRIDA_SCRIPT_EXECUTION_DENIED",
            http_status=403,
        )
    if sha256(proposal.source_code.encode("utf-8")).hexdigest() != proposal.source_sha256:
        raise FridaScriptProposalError(
            "Generated Frida script failed its integrity check.",
            code="FRIDA_SCRIPT_HASH_MISMATCH",
            http_status=409,
        )
    return proposal.source_code


def mark_frida_script_execution(
    source_identifier: str,
    *,
    succeeded: bool,
    error: str = "",
) -> None:
    match = GENERATED_FRIDA_SOURCE_RE.fullmatch(source_identifier or "")
    if match is None:
        return
    update = {
        "executed_at": timezone.now(),
        "updated_at": timezone.now(),
    }
    if succeeded:
        update.update(
            {
                "status": FridaScriptProposal.Status.EXECUTED,
                "last_error": "",
                "suggested_fix": "",
            }
        )
    else:
        update.update(
            {
                "status": FridaScriptProposal.Status.FAILED,
                "last_error": _bounded_text(error, 1000),
                "suggested_fix": _suggest_fix(error),
            }
        )
    FridaScriptProposal.objects.filter(pk=int(match.group("id"))).update(**update)


def validate_generated_frida_script_source(source: Any) -> list[str]:
    if not isinstance(source, str) or not source.strip():
        raise FridaScriptProposalError(
            "Frida JavaScript source cannot be empty.",
            code="FRIDA_SCRIPT_SOURCE_EMPTY",
            http_status=400,
        )
    encoded = source.encode("utf-8")
    if len(encoded) > MAX_GENERATED_FRIDA_SCRIPT_BYTES:
        raise FridaScriptProposalError(
            f"Frida JavaScript exceeds {MAX_GENERATED_FRIDA_SCRIPT_BYTES} bytes.",
            code="FRIDA_SCRIPT_SOURCE_TOO_LARGE",
            http_status=400,
        )
    if "\x00" in source:
        raise FridaScriptProposalError(
            "Frida JavaScript cannot contain NUL characters.",
            code="FRIDA_SCRIPT_SOURCE_NUL",
            http_status=400,
        )
    if "send(" not in source:
        raise FridaScriptProposalError(
            "Generated Frida scripts must emit at least one bounded send(...) event.",
            code="FRIDA_SCRIPT_NO_EVIDENCE_EVENT",
            http_status=400,
        )
    if FORBIDDEN_SCRIPT_RE.search(source):
        raise FridaScriptProposalError(
            "Generated Frida script contains a prohibited operation.",
            code="FRIDA_SCRIPT_PROHIBITED_OPERATION",
            http_status=400,
        )
    warnings: list[str] = []
    if "Java.perform" not in source:
        warnings.append("Script does not use Java.perform; Java API hooks may be unreliable.")
    if "try" not in source or "catch" not in source:
        warnings.append("Script has limited try/catch handling; runtime errors may stop evidence collection.")
    return warnings[:4]


def _authorize_generation(run: AgentRun, requested_by) -> None:
    if user_role(requested_by) not in {"ADMIN", "ANALYST"}:
        raise FridaScriptProposalError(
            "Only an Analyst or Admin can request Frida script proposals.",
            code="FRIDA_SCRIPT_GENERATION_DENIED",
            http_status=403,
        )
    if run.audit_id is None or not run.target_package:
        raise FridaScriptProposalError(
            "The AgentRun is missing audit or target package context.",
            code="FRIDA_SCRIPT_RUN_CONTEXT_INVALID",
        )
    envelope = run.capability_envelope if isinstance(run.capability_envelope, dict) else {}
    if "frida_run_js" not in set(envelope.get("allowed_capabilities") or []):
        raise FridaScriptProposalError(
            "This assessment does not authorize Frida JavaScript execution.",
            code="FRIDA_SCRIPT_CAPABILITY_NOT_ALLOWED",
            http_status=403,
        )


def _select_hypothesis(run: AgentRun, hypothesis_id: int | None) -> AgentHypothesis | None:
    query = run.hypotheses.all()
    if hypothesis_id is not None:
        hypothesis = query.filter(pk=hypothesis_id).first()
        if hypothesis is None:
            raise FridaScriptProposalError(
                "The requested hypothesis does not belong to this AgentRun.",
                code="FRIDA_SCRIPT_HYPOTHESIS_UNKNOWN",
                http_status=404,
            )
        return hypothesis
    return query.filter(status__in=["UNTESTED", "ACTIVE", "INCONCLUSIVE"]).first() or query.first()


def _generate_script_payload(
    run: AgentRun,
    hypothesis: AgentHypothesis | None,
) -> tuple[dict[str, Any], str, str, dict[str, Any]]:
    if settings.MSAP_FRIDA_SCRIPT_GENERATION_PROVIDER == "DETERMINISTIC":
        return _deterministic_script_payload(run, hypothesis), "DETERMINISTIC", "msap-safe-frida-proposer-v1", {}
    from apps.dynamic_analysis.services.assessment_planner import (
        OpenAIPlannerProvider,
        PlannerProviderError,
    )

    provider = OpenAIPlannerProvider(max_output_tokens=2000)
    provider_call_was_reserved = False
    try:
        reserve_call(KIND_DECISION)
        provider_call_was_reserved = True
        payload = provider.generate_structured(
            _script_generation_context(run, hypothesis),
            system_instructions=FRIDA_SCRIPT_SYSTEM_INSTRUCTIONS,
            output_schema=FRIDA_SCRIPT_OUTPUT_SCHEMA,
            schema_name=FRIDA_SCRIPT_SCHEMA_NAME,
            max_context_bytes=24 * 1024,
            max_output_bytes=MAX_GENERATED_FRIDA_SCRIPT_BYTES + 2048,
            request_kind="frida_script_proposal",
        )
        record_response_id(provider.last_metadata.get("response_id"))
        validate_generated_frida_script_source(payload.get("source_code"))
        return payload, "OPENAI", provider.model, provider.last_metadata
    except OpenAIBudgetExhausted as exc:
        raise FridaScriptProposalError(
            str(exc),
            code=exc.reason,
            http_status=429,
        ) from None
    except PlannerProviderError as exc:
        if provider_call_was_reserved and provider.last_metadata.get("provider_request_sent") is False:
            release_call(KIND_DECISION)
        raise FridaScriptProposalError(
            str(exc),
            code=exc.code,
            http_status=exc.http_status,
        ) from None
    except FridaScriptProposalError:
        if provider_call_was_reserved and provider.last_metadata.get("provider_request_sent") is False:
            release_call(KIND_DECISION)
        raise


def _script_generation_context(run: AgentRun, hypothesis: AgentHypothesis | None) -> dict[str, Any]:
    observations = []
    for step in run.steps.order_by("-sequence_number")[:8]:
        observations.append(
            {
                "tool": step.tool_name,
                "status": step.status,
                "summary": _safe_metadata(step.output_summary if isinstance(step.output_summary, dict) else {}),
            }
        )
    observations.reverse()
    return {
        "trusted": {
            "agent_run_id": run.id,
            "audit_id": run.audit_id,
            "target_package": run.target_package,
            "objective": run.objective,
            "scope": run.capability_envelope.get("scope", "") if isinstance(run.capability_envelope, dict) else "",
            "hypothesis": {
                "id": hypothesis.hypothesis_id if hypothesis else "",
                "family": hypothesis.family if hypothesis else "",
                "title": hypothesis.title if hypothesis else "",
            },
            "required_output": "One or more send({...}) events usable as bounded evidence.",
        },
        "untrusted_recent_observations": observations,
    }


def _deterministic_script_payload(
    run: AgentRun,
    hypothesis: AgentHypothesis | None,
) -> dict[str, Any]:
    family = hypothesis.family if hypothesis else ""
    event_type = "generated_frida_probe"
    if "ROOT" in family:
        event_type = "generated_root_signal_probe"
    elif "EMULATOR" in family:
        event_type = "generated_emulator_signal_probe"
    source = f"""
Java.perform(function () {{
  try {{
    send({{
      type: "{event_type}",
      package_name: "{run.target_package}",
      hypothesis: "{(hypothesis.hypothesis_id if hypothesis else 'runtime_probe')}",
      observation_only: true,
      java_available: true
    }});
  }} catch (error) {{
    send({{
      type: "{event_type}_error",
      package_name: "{run.target_package}",
      observation_only: true,
      error: String(error).slice(0, 200)
    }});
  }}
}});
""".strip()
    return {
        "title": "Generated Frida observation probe",
        "rationale": "Collect a minimal Java runtime event from the authorized target before attempting deeper instrumentation.",
        "expected_evidence": ["Frida event emitted by the target process", "Script hash and bounded execution metadata"],
        "source_code": source,
    }


def _source_identifier(proposal_id: int, digest: str) -> str:
    return f"{GENERATED_FRIDA_SOURCE_PREFIX}:{proposal_id}:{digest[:16]}"


def _bounded_text(value: Any, limit: int, *, required: bool = False) -> str:
    if not isinstance(value, str):
        value = ""
    value = value.strip()
    if required and not value:
        raise FridaScriptProposalError(
            "Generated Frida script metadata is incomplete.",
            code="FRIDA_SCRIPT_METADATA_INVALID",
            http_status=400,
        )
    return value[:limit]


def _safe_metadata(value: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    return {
        str(key)[:80]: _safe_metadata_value(child)
        for key, child in list(value.items())[:40]
    }


def _safe_metadata_value(value: Any) -> Any:
    if isinstance(value, dict):
        return _safe_metadata(value)
    if isinstance(value, list):
        return [_safe_metadata_value(child) for child in value[:40]]
    if isinstance(value, str):
        cleaned = re.sub(r"\bBearer\s+[A-Za-z0-9._~+/=-]+", "[REDACTED]", value)
        cleaned = re.sub(r"\bsk-[A-Za-z0-9_-]{8,}\b", "[REDACTED]", cleaned)
        return cleaned[:600]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)[:200]


def _suggest_fix(error: str) -> str:
    lowered = (error or "").lower()
    if "not running" in lowered or "attach" in lowered:
        return "Launch the target app, verify Frida status, then approve a revised attach-mode script."
    if "java" in lowered or "class" in lowered:
        return "Regenerate the script using observed classes only, or approve a simpler Java.perform probe first."
    if "timeout" in lowered:
        return "Regenerate with fewer hooks and a shorter observation path, then retry within the bounded timeout."
    return "Review the script error, regenerate a narrower proposal, and approve only the revised script."
