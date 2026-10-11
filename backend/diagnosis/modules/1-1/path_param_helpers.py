"""path param helpers helpers split out of zap_runner.py (code moved verbatim)."""

import importlib.util
import os
import re
import sys


def _sibling(name):
    key = f"diag_g11_split_{name}"
    module = sys.modules.get(key)
    if module is None:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), f"{name}.py")
        spec = importlib.util.spec_from_file_location(key, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[key] = module
        spec.loader.exec_module(module)
    return module

extract_id_from_location = _sibling("request_helpers").extract_id_from_location
extract_id_from_url = _sibling("request_helpers").extract_id_from_url
is_resource_identifier_value = _sibling("request_helpers").is_resource_identifier_value
normalized_field_name = _sibling("schema_payloads").normalized_field_name


def extract_id_candidates_from_json(data, param_name: str, depth: int = 0) -> list:
    if depth > 5:
        return []

    candidates = []
    preferred_keys = [
        param_name,
        param_name.replace("Id", "ID"),
        param_name.replace("_id", "Id"),
        "id",
        "uuid",
        "key",
        "no",
        "seq",
    ]
    if isinstance(data, dict):
        for key in preferred_keys:
            if key in data and data[key] is not None:
                candidates.append(data[key])
        for value in data.values():
            candidates.extend(extract_id_candidates_from_json(value, param_name, depth + 1))
    elif isinstance(data, list):
        for item in data[:10]:
            candidates.extend(extract_id_candidates_from_json(item, param_name, depth + 1))

    deduped = []
    for value in candidates:
        value = str(value)
        if value and value not in deduped:
            deduped.append(value)
    return deduped


def resource_hint_for_param(param_name: str) -> str:
    return re.sub(r"(_?id|Id|ID)$", "", param_name).lower()


def plural_resource_hints(hint: str) -> list:
    if not hint:
        return []
    hints = [hint]
    if hint.endswith("y"):
        hints.append(f"{hint[:-1]}ies")
    elif not hint.endswith("s"):
        hints.append(f"{hint}s")
    return list(dict.fromkeys(hints))


def resolve_path_with_known_values(path: str, known_values: dict) -> str | None:
    resolved = path
    for param in re.findall(r"\{([^}]+)\}", resolved):
        if param not in known_values:
            return None
        resolved = resolved.replace(f"{{{param}}}", str(known_values[param]))
    return resolved


def path_param_matches_identifier(param_name: str, value) -> bool:
    if value is None or isinstance(value, bool):
        return False
    return is_resource_identifier_value(value)


def extract_id_from_response_or_location(response, param_name: str):
    found = extract_id_from_url(getattr(response, "url", ""))
    if path_param_matches_identifier(param_name, found):
        return found
    found = extract_id_from_location(response)
    if path_param_matches_identifier(param_name, found):
        return found
    try:
        for candidate in extract_id_candidates_from_json(response.json(), param_name):
            if path_param_matches_identifier(param_name, candidate):
                return candidate
    except Exception:
        pass
    return None


def extract_identity_value(data, param_name: str):
    wanted = normalized_field_name(param_name)
    if isinstance(data, dict):
        for key, value in data.items():
            normalized_key = normalized_field_name(key)
            if value is not None and normalized_key == wanted:
                return value
        for value in data.values():
            found = extract_identity_value(value, param_name)
            if found is not None:
                return found
    elif isinstance(data, list):
        for item in data[:5]:
            found = extract_identity_value(item, param_name)
            if found is not None:
                return found
    return None
