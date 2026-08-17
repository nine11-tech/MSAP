from __future__ import annotations

from typing import Any


LOCAL_SCHEMA_REJECTION_MESSAGE = (
    "AI schema is not compatible with the provider. No request was sent."
)

_ALLOWED_SCHEMA_KEYWORDS = frozenset(
    {
        "additionalProperties",
        "anyOf",
        "const",
        "description",
        "enum",
        "items",
        "maxItems",
        "maxLength",
        "maximum",
        "minItems",
        "minLength",
        "minimum",
        "pattern",
        "properties",
        "required",
        "type",
    }
)
_SUPPORTED_TYPES = frozenset(
    {"array", "boolean", "integer", "null", "number", "object", "string"}
)


class OpenAISchemaCompatibilityError(ValueError):
    """An MSAP provider schema is outside the supported strict-output subset."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def validate_openai_structured_output_schema(
    schema: Any,
    *,
    schema_name: str,
) -> None:
    """Conservatively validate the strict JSON-schema shapes MSAP sends to OpenAI.

    This deliberately is not a general JSON Schema or provider validator. It is
    a small compatibility gate for the two closed schemas MSAP owns.
    """

    if not isinstance(schema, dict):
        _reject("The root schema must be an object schema.")
    if any(keyword in schema for keyword in ("anyOf", "oneOf", "allOf")):
        _reject("Root unions are not supported.")
    if schema.get("type") != "object":
        _reject("The root schema must declare type object.")
    if schema.get("additionalProperties") is not False:
        _reject("The root object must be closed.")

    _validate_node(schema, path="$", is_root=True, depth=0)
    if schema_name == "msap_agent_action_decision":
        _validate_action_decision_coupling(schema)
    elif schema_name == "msap_assessment_plan":
        _validate_planner_tool_coupling(schema)


def _validate_node(value: Any, *, path: str, is_root: bool, depth: int) -> None:
    if depth > 40:
        _reject(f"The schema is too deeply nested at {path}.")
    if not isinstance(value, dict):
        _reject(f"A schema node is invalid at {path}.")

    unsupported = sorted(set(value) - _ALLOWED_SCHEMA_KEYWORDS)
    if unsupported:
        _reject(f"Unsupported schema keyword {unsupported[0]!r} at {path}.")
    if "uniqueItems" in value:
        _reject(f"uniqueItems is not supported at {path}.")

    schema_type = value.get("type")
    if schema_type is None and "anyOf" not in value:
        _reject(f"Schema nodes must declare a type at {path}.")
    if isinstance(schema_type, list):
        if (
            len(schema_type) != 2
            or "null" not in schema_type
            or any(item not in _SUPPORTED_TYPES for item in schema_type)
            or len(set(schema_type)) != len(schema_type)
        ):
            _reject(f"Only one nullable primitive type is supported at {path}.")
    elif schema_type is not None and schema_type not in _SUPPORTED_TYPES:
        _reject(f"Unsupported schema type at {path}.")

    properties = value.get("properties")
    if properties is not None or schema_type == "object":
        if schema_type != "object" or not isinstance(properties, dict):
            _reject(f"Object properties are invalid at {path}.")
        if value.get("additionalProperties") is not False:
            _reject(f"Object schemas must be closed at {path}.")
        required = value.get("required")
        if (
            not isinstance(required, list)
            or any(not isinstance(item, str) for item in required)
            or len(required) != len(set(required))
            or set(required) != set(properties)
        ):
            _reject(f"Every object property must be required at {path}.")
        for name, child in properties.items():
            if not isinstance(name, str) or not name:
                _reject(f"Object property names are invalid at {path}.")
            _validate_node(
                child,
                path=f"{path}.properties.{name}",
                is_root=False,
                depth=depth + 1,
            )

    if schema_type == "array":
        if "items" not in value:
            _reject(f"Array items are required at {path}.")
        _validate_node(
            value["items"],
            path=f"{path}.items",
            is_root=False,
            depth=depth + 1,
        )
    elif "items" in value:
        _reject(f"items is only supported for arrays at {path}.")

    variants = value.get("anyOf")
    if variants is not None:
        if is_root or not isinstance(variants, list) or len(variants) < 2:
            _reject(f"The union is not supported at {path}.")
        for index, child in enumerate(variants):
            _validate_node(
                child,
                path=f"{path}.anyOf[{index}]",
                is_root=False,
                depth=depth + 1,
            )

    enum = value.get("enum")
    if enum is not None and (not isinstance(enum, list) or not enum):
        _reject(f"Enums must be non-empty at {path}.")


def _validate_action_decision_coupling(schema: dict[str, Any]) -> None:
    decision = schema.get("properties", {}).get("decision", {})
    variants = decision.get("anyOf") if isinstance(decision, dict) else None
    if not isinstance(variants, list):
        _reject("The adaptive decision union is missing.")

    tool_names: set[str] = set()
    terminal_types: set[str] = set()
    for variant in variants:
        properties = variant.get("properties", {})
        decision_type = properties.get("decision_type", {}).get("const")
        tool_name_schema = properties.get("tool_name", {})
        arguments = properties.get("arguments", {})
        if decision_type == "TOOL_ACTION":
            tool_name = tool_name_schema.get("const")
            if not isinstance(tool_name, str) or not tool_name or tool_name in tool_names:
                _reject("Each adaptive tool must have one unique, coupled branch.")
            if "enum" in tool_name_schema or "anyOf" in arguments:
                _reject("Adaptive tool names and arguments must be coupled.")
            tool_names.add(tool_name)
        elif decision_type in {"COMPLETE", "NEEDS_AUDITOR"}:
            terminal_types.add(decision_type)
            if tool_name_schema.get("const") != "":
                _reject("Non-tool decisions cannot carry a tool name.")
            if arguments.get("properties") != {}:
                _reject("Non-tool decisions cannot carry tool arguments.")
        else:
            _reject("The adaptive decision type is unsupported.")
    if not tool_names or terminal_types != {"COMPLETE", "NEEDS_AUDITOR"}:
        _reject("The adaptive decision union is incomplete.")


def _validate_planner_tool_coupling(schema: dict[str, Any]) -> None:
    try:
        variants = schema["properties"]["steps"]["items"]["properties"]["tools"][
            "items"
        ]["anyOf"]
    except (KeyError, TypeError):
        _reject("The planner tool union is missing.")
    if not isinstance(variants, list) or not variants:
        _reject("The planner tool union is empty.")
    names: set[str] = set()
    for variant in variants:
        properties = variant.get("properties", {})
        name = properties.get("name", {}).get("const")
        arguments = properties.get("arguments", {})
        if (
            not isinstance(name, str)
            or not name
            or name in names
            or arguments.get("type") != "object"
        ):
            _reject("Planner tool names and arguments must be uniquely coupled.")
        names.add(name)


def _reject(reason: str) -> None:
    raise OpenAISchemaCompatibilityError(reason)
