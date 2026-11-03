"""Small JSON Schema Draft 2020-12 subset validator using only the stdlib.

The project contracts intentionally use a bounded keyword set. Unsupported
keywords fail closed so adding schema features cannot silently weaken checks.
"""
import json
from pathlib import Path
from urllib.parse import urlparse
from datetime import datetime

SCHEMA_DIR = Path(__file__).resolve().parent.parent / "schemas"
SUPPORTED = {"$schema", "$id", "title", "description", "type", "additionalProperties",
             "required", "properties", "items", "enum", "const", "minimum", "maximum", "maxItems",
             "minLength", "minItems", "pattern", "$ref", "$defs", "format", "default"}


class SchemaValidationError(ValueError):
    pass


def validate(instance, schema, path="$", root=None):
    root = root or schema
    unknown = set(schema) - SUPPORTED
    if unknown:
        raise SchemaValidationError(f"unsupported schema keywords: {sorted(unknown)}")
    if "$ref" in schema:
        ref = schema["$ref"]
        if ref.startswith("#/"):
            target = root
            for part in ref[2:].split("/"):
                target = target[part.replace("~1", "/").replace("~0", "~")]
        else:
            target_file, _, fragment = ref.partition("#")
            target = json.loads((SCHEMA_DIR / target_file).read_text(encoding="utf-8"))
            for part in fragment.lstrip("/").split("/") if fragment else []:
                target = target[part]
            root = target if not fragment else root
        return validate(instance, target, path, root)
    typ = schema.get("type")
    types = [typ] if isinstance(typ, str) else (typ or [])
    def matches(t):
        return {"object": isinstance(instance, dict), "array": isinstance(instance, list),
                "string": isinstance(instance, str), "integer": isinstance(instance, int) and not isinstance(instance, bool),
                "number": isinstance(instance, (int, float)) and not isinstance(instance, bool),
                "boolean": isinstance(instance, bool), "null": instance is None}[t]
    if types and not any(matches(t) for t in types):
        raise SchemaValidationError(f"{path}: expected {types}")
    if "const" in schema and instance != schema["const"]:
        raise SchemaValidationError(f"{path}: expected constant {schema['const']!r}")
    if "enum" in schema and instance not in schema["enum"]:
        raise SchemaValidationError(f"{path}: value not in enum")
    if isinstance(instance, dict):
        missing = set(schema.get("required", [])) - set(instance)
        if missing:
            raise SchemaValidationError(f"{path}: missing required {sorted(missing)}")
        props = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            extra = set(instance) - set(props)
            if extra:
                raise SchemaValidationError(f"{path}: unexpected properties {sorted(extra)}")
        for key, value in instance.items():
            if key in props:
                validate(value, props[key], f"{path}.{key}", root)
    if isinstance(instance, list) and "items" in schema:
        if len(instance) < schema.get("minItems", 0):
            raise SchemaValidationError(f"{path}: too few items")
        if "maxItems" in schema and len(instance) > schema["maxItems"]:
            raise SchemaValidationError(f"{path}: too many items")
        for i, value in enumerate(instance):
            validate(value, schema["items"], f"{path}[{i}]", root)
    if isinstance(instance, str):
        if len(instance) < schema.get("minLength", 0):
            raise SchemaValidationError(f"{path}: string too short")
        if "pattern" in schema:
            import re
            if not re.search(schema["pattern"], instance):
                raise SchemaValidationError(f"{path}: string pattern mismatch")
        if schema.get("format") == "uri" and not urlparse(instance).scheme:
            raise SchemaValidationError(f"{path}: invalid URI")
        if schema.get("format") == "date-time":
            try:
                parsed = datetime.fromisoformat(instance.replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    raise ValueError("timezone required")
            except ValueError as exc:
                raise SchemaValidationError(f"{path}: invalid date-time") from exc
    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            raise SchemaValidationError(f"{path}: value below minimum")
        if "maximum" in schema and instance > schema["maximum"]:
            raise SchemaValidationError(f"{path}: value above maximum")
