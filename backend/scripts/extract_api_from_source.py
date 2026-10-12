"""Extract API inventory from source code: OpenAPI(swagger) + api-list + url-list.

Reads Spring MVC controllers (and optionally a React Router frontend) without
touching the target project, so apps that ship no OpenAPI spec can still be fed
to ARGUS.

    python extract_api_from_source.py --name mate \
        --backend path/to/spring/src/main/java \
        --frontend path/to/react/src \
        --out examples/targets/mate
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

HTTP_ANNOTATIONS = {
    "GetMapping": "GET",
    "PostMapping": "POST",
    "PutMapping": "PUT",
    "PatchMapping": "PATCH",
    "DeleteMapping": "DELETE",
}
SKIP_PARAM_TYPES = {
    "HttpServletRequest", "HttpServletResponse", "Principal", "Authentication", "Model",
    "BindingResult", "UserDetails", "CustomUserDetails", "Locale", "HttpSession", "MultipartHttpServletRequest",
}
SIMPLE_TYPES = {
    "String": {"type": "string"},
    "char": {"type": "string"}, "Character": {"type": "string"},
    "int": {"type": "integer", "format": "int32"}, "Integer": {"type": "integer", "format": "int32"},
    "long": {"type": "integer", "format": "int64"}, "Long": {"type": "integer", "format": "int64"},
    "short": {"type": "integer"}, "Short": {"type": "integer"},
    "double": {"type": "number", "format": "double"}, "Double": {"type": "number", "format": "double"},
    "float": {"type": "number", "format": "float"}, "Float": {"type": "number", "format": "float"},
    "BigDecimal": {"type": "number"},
    "boolean": {"type": "boolean"}, "Boolean": {"type": "boolean"},
    "LocalDate": {"type": "string", "format": "date"},
    "LocalDateTime": {"type": "string", "format": "date-time"},
    "OffsetDateTime": {"type": "string", "format": "date-time"},
    "Instant": {"type": "string", "format": "date-time"},
    "LocalTime": {"type": "string", "format": "time"},
    "UUID": {"type": "string", "format": "uuid"},
    "MultipartFile": {"type": "string", "format": "binary"},
    "Object": {},
}


# ---------------------------------------------------------------- java scanning
def _strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def _balanced(text: str, open_idx: int, open_ch: str = "(", close_ch: str = ")") -> int:
    """Index of the bracket matching text[open_idx]; -1 if unbalanced."""
    depth = 0
    in_str = None
    i = open_idx
    while i < len(text):
        ch = text[i]
        if in_str:
            if ch == "\\":
                i += 1
            elif ch == in_str:
                in_str = None
        elif ch in "\"'":
            in_str = ch
        elif ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def _split_top_level(text: str) -> list[str]:
    parts, depth, cur, in_str = [], 0, [], None
    for ch in text:
        if in_str:
            cur.append(ch)
            if ch == in_str:
                in_str = None
            continue
        if ch in "\"'":
            in_str = ch
        elif ch in "(<[{":
            depth += 1
        elif ch in ")>]}":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
            continue
        cur.append(ch)
    tail = "".join(cur).strip()
    if tail:
        parts.append(tail)
    return parts


def _string_literals(text: str) -> list[str]:
    return re.findall(r'"((?:[^"\\]|\\.)*)"', text)


def _mapping_paths(args: str) -> list[str]:
    """Paths declared in a mapping annotation's argument string."""
    if not args.strip():
        return [""]
    value_match = re.search(r"\b(?:value|path)\s*=\s*(\{[^}]*\}|\"[^\"]*\")", args)
    if value_match:
        paths = _string_literals(value_match.group(1))
        return paths or [""]
    first = _split_top_level(args)[0]
    if "=" in first and not first.lstrip().startswith(("\"", "{")):
        return [""]
    paths = _string_literals(first)
    return paths or [""]


def _join_path(*parts: str) -> str:
    joined = "/".join(p.strip("/") for p in parts if p and p.strip("/"))
    return "/" + joined if joined else "/"


@dataclass
class Param:
    name: str
    location: str  # path | query | header | body | part
    schema: dict
    required: bool = True


@dataclass
class Endpoint:
    method: str
    path: str
    params: list[Param] = field(default_factory=list)
    body_type: str | None = None
    body_is_list: bool = False
    multipart: bool = False
    controller: str = ""
    handler: str = ""
    tag: str = ""
    index: object = None

    def add_param(self, param: "Param") -> None:
        if not any(p.name == param.name and p.location == param.location for p in self.params):
            self.params.append(param)


class JavaIndex:
    """Class/enum/record lookup so DTO and enum fields can be resolved by simple name."""

    def __init__(self, roots: list[Path]):
        self.files: list[tuple[Path, str]] = []
        self.classes: dict[str, tuple[str, str]] = {}  # name -> (kind, body)
        for root in roots:
            for path in sorted(Path(root).rglob("*.java")):
                text = _strip_comments(path.read_text(encoding="utf-8", errors="replace"))
                self.files.append((path, text))
                for match in re.finditer(r"\b(class|record|enum|interface)\s+(\w+)", text):
                    kind, name = match.groups()
                    brace = text.find("{", match.end())
                    paren_record = text.find("(", match.end()) if kind == "record" else -1
                    if kind == "record" and paren_record != -1 and (brace == -1 or paren_record < brace):
                        end = _balanced(text, paren_record)
                        self.classes.setdefault(name, (kind, text[paren_record + 1:end] if end != -1 else ""))
                        continue
                    if brace == -1:
                        continue
                    end = _balanced(text, brace, "{", "}")
                    self.classes.setdefault(name, (kind, text[brace + 1:end if end != -1 else len(text)]))

    def enum_values(self, name: str) -> list[str] | None:
        entry = self.classes.get(name)
        if not entry or entry[0] != "enum":
            return None
        head = entry[1].split(";", 1)[0]
        values = []
        for part in _split_top_level(head):
            token = re.match(r"\s*([A-Za-z_]\w*)", part)
            if token:
                values.append(token.group(1))
        return values or None


_VALIDATION = re.compile(r"@(\w+)(?:\(([^)]*)\))?")


def _apply_validation(schema: dict, annotations: str) -> tuple[dict, bool]:
    required = False
    for name, args in _VALIDATION.findall(annotations):
        args = args or ""
        if name in {"NotNull", "NotBlank", "NotEmpty"}:
            required = True
        if name == "Email":
            schema["format"] = "email"
        if name == "Size":
            lo = re.search(r"min\s*=\s*(\d+)", args)
            hi = re.search(r"max\s*=\s*(\d+)", args)
            key_lo, key_hi = ("minLength", "maxLength") if schema.get("type") == "string" else ("minItems", "maxItems")
            if lo:
                schema[key_lo] = int(lo.group(1))
            if hi:
                schema[key_hi] = int(hi.group(1))
        if name in {"Min", "DecimalMin"}:
            num = re.search(r"-?\d+(?:\.\d+)?", args)
            if num:
                schema["minimum"] = float(num.group(0)) if "." in num.group(0) else int(num.group(0))
        if name in {"Max", "DecimalMax"}:
            num = re.search(r"-?\d+(?:\.\d+)?", args)
            if num:
                schema["maximum"] = float(num.group(0)) if "." in num.group(0) else int(num.group(0))
        if name == "Pattern":
            pattern = re.search(r'regexp\s*=\s*"((?:[^"\\]|\\.)*)"', args)
            if pattern:
                schema["pattern"] = pattern.group(1)
    _add_example(schema)
    return schema, required


def _add_example(schema: dict) -> None:
    """Give generators a value that already satisfies the declared constraints."""
    if "example" in schema or schema.get("enum"):
        return
    if schema.get("type") == "integer" and "minimum" in schema:
        schema["example"] = int(schema["minimum"])
        return
    if schema.get("type") != "string":
        return
    digits = re.fullmatch(r"\^?\\d\{(\d+)\}\$?", schema.get("pattern", ""))
    if digits:
        schema["example"] = ("1234567890" * 4)[: int(digits.group(1))]
    elif schema.get("minLength", 0) > 1:
        schema["example"] = "a" * int(schema["minLength"])


def type_schema(java_type: str, index: JavaIndex, schemas: dict, depth: int = 0) -> dict:
    java_type = java_type.strip().replace("final ", "")
    java_type = re.sub(r"\s+", "", java_type)
    java_type = re.sub(r"(?:[a-z_]\w*\.)+(?=[A-Z])", "", java_type)
    if java_type.endswith("[]"):
        return {"type": "array", "items": type_schema(java_type[:-2], index, schemas, depth + 1)}
    generic = re.match(r"(\w+)<(.+)>$", java_type)
    if generic:
        outer, inner = generic.groups()
        if outer in {"List", "Set", "Collection", "Iterable", "ArrayList"}:
            return {"type": "array", "items": type_schema(inner, index, schemas, depth + 1)}
        if outer == "Map":
            return {"type": "object", "additionalProperties": True}
        if outer in {"Optional"}:
            return type_schema(inner, index, schemas, depth + 1)
        java_type = outer
    if java_type in SIMPLE_TYPES:
        return dict(SIMPLE_TYPES[java_type])
    enum_values = index.enum_values(java_type)
    if enum_values:
        return {"type": "string", "enum": enum_values}
    if java_type in index.classes and depth < 4:
        return {"$ref": f"#/components/schemas/{_register_schema(java_type, index, schemas, depth + 1)}"}
    return {"type": "object"}


def _register_schema(name: str, index: JavaIndex, schemas: dict, depth: int) -> str:
    if name in schemas:
        return name
    schemas[name] = {"type": "object"}  # guards recursion
    kind, body = index.classes[name]
    properties: dict[str, dict] = {}
    required: list[str] = []
    if kind == "record":
        for component in _split_top_level(body):
            match = re.match(r"((?:@\w+(?:\([^)]*\))?\s*)*)([\w<>\[\],.? ]+?)\s+(\w+)\s*$", component.strip(), flags=re.S)
            if not match:
                continue
            annotations, java_type, field_name = match.groups()
            schema = type_schema(java_type, index, schemas, depth)
            schema, is_required = _apply_validation(schema, annotations)
            properties[field_name] = schema
            if is_required:
                required.append(field_name)
    else:
        pattern = re.compile(
            r"((?:@\w+(?:\([^)]*\))?\s*)*)(?:private|protected|public)\s+(?!static)(?:final\s+)?([\w<>\[\],.? ]+?)\s+(\w+)\s*(?:=[^;]*)?;",
            flags=re.S,
        )
        for match in pattern.finditer(body):
            annotations, java_type, field_name = match.groups()
            if "transient" in java_type or "(" in java_type:
                continue
            schema = type_schema(java_type, index, schemas, depth)
            schema, is_required = _apply_validation(schema, annotations)
            properties[field_name] = schema
            if is_required:
                required.append(field_name)
    schemas[name] = {"type": "object", "properties": properties}
    if required:
        schemas[name]["required"] = required
    return name


# -------------------------------------------------------------- controller parse
def _clean_type(raw: str) -> str:
    return re.sub(r"\s+", "", raw)


def _parse_parameter(raw: str, index: JavaIndex, schemas: dict, method: str, endpoint: Endpoint) -> None:
    annotations = re.findall(r"@\w+(?:\((?:[^()]|\([^()]*\))*\))?", raw)
    remainder = raw
    for annotation in annotations:
        remainder = remainder.replace(annotation, "", 1)
    remainder = remainder.replace("final ", "").strip()
    match = re.match(r"(.+?)\s+(\w+)$", remainder, flags=re.S)
    if not match:
        return
    java_type, var_name = _clean_type(match.group(1)), match.group(2)
    base_type = re.sub(r"<.*>$", "", java_type)
    names = {re.match(r"@(\w+)", a).group(1): a for a in annotations}

    def declared_name(annotation: str) -> str:
        explicit = re.search(r"\b(?:name|value)\s*=\s*\"([^\"]*)\"", annotation) or re.match(r"@\w+\(\s*\"([^\"]*)\"", annotation)
        return explicit.group(1) if explicit else var_name

    if "AuthenticationPrincipal" in names or base_type in SKIP_PARAM_TYPES:
        return
    if "PathVariable" in names:
        endpoint.add_param(Param(declared_name(names["PathVariable"]), "path", type_schema(java_type, index, schemas)))
        return
    if "RequestHeader" in names:
        header = declared_name(names["RequestHeader"])
        if header.lower() != "authorization":
            endpoint.add_param(Param(header, "header", type_schema(java_type, index, schemas), False))
        return
    if "RequestBody" in names:
        generic = re.match(r"(?:List|Set|Collection)<(.+)>$", java_type)
        endpoint.body_type = generic.group(1) if generic else java_type
        endpoint.body_is_list = bool(generic)
        return
    if "RequestPart" in names or base_type == "MultipartFile" or java_type in {"MultipartFile[]", "List<MultipartFile>"}:
        endpoint.multipart = True
        endpoint.add_param(Param(declared_name(names.get("RequestPart", names.get("RequestParam", "")) or ""), "part",
                                     type_schema(java_type, index, schemas), "RequestPart" in names))
        return
    if "RequestParam" in names:
        annotation = names["RequestParam"]
        required = not re.search(r"required\s*=\s*false", annotation) and "defaultValue" not in annotation
        schema = type_schema(java_type, index, schemas)
        default = re.search(r"defaultValue\s*=\s*\"([^\"]*)\"", annotation)
        if default:
            schema["default"] = default.group(1)
        endpoint.add_param(Param(declared_name(annotation), "query", schema, required))
        return
    if base_type == "Pageable":
        for name, schema in (("page", {"type": "integer", "example": 0}), ("size", {"type": "integer", "example": 10})):
            endpoint.add_param(Param(name, "query", schema, False))
        return
    if "ModelAttribute" in names or (base_type in index.classes and index.classes[base_type][0] in {"class", "record"}):
        if method == "GET":
            resolved = type_schema(java_type, index, schemas)
            ref = resolved.get("$ref", "").rsplit("/", 1)[-1]
            for field_name, schema in schemas.get(ref, {}).get("properties", {}).items():
                endpoint.add_param(Param(field_name, "query", schema, False))
        else:
            endpoint.body_type = java_type
            endpoint.multipart = endpoint.multipart or "ModelAttribute" in names
        return
    if base_type in SIMPLE_TYPES:
        endpoint.add_param(Param(var_name, "query", type_schema(java_type, index, schemas), False))


def parse_controllers(index: JavaIndex, schemas: dict) -> list[Endpoint]:
    endpoints: list[Endpoint] = []
    for _, text in index.files:
        for class_match in re.finditer(r"@(RestController|Controller)\b", text):
            header_start = max(text.rfind("\n\n", 0, class_match.start()), 0)
            class_decl = re.search(r"\bclass\s+(\w+)", text[class_match.end():])
            if not class_decl:
                continue
            class_name = class_decl.group(1)
            prefix_zone = text[header_start:class_match.end() + class_decl.start()]
            base_paths = [""]
            request_mapping = re.search(r"@RequestMapping\s*(?:\(([^)]*)\))?", prefix_zone)
            if request_mapping:
                base_paths = _mapping_paths(request_mapping.group(1) or "")
            body_open = text.find("{", class_match.end() + class_decl.end())
            body_close = _balanced(text, body_open, "{", "}")
            body = text[body_open + 1: body_close if body_close != -1 else len(text)]
            for mapping in re.finditer(r"@(Get|Post|Put|Patch|Delete|Request)Mapping\b", body):
                kind = mapping.group(1) + "Mapping"
                cursor = mapping.end()
                args = ""
                after = body[cursor:].lstrip()
                if after.startswith("("):
                    open_idx = body.index("(", cursor)
                    close_idx = _balanced(body, open_idx)
                    args = body[open_idx + 1:close_idx]
                    cursor = close_idx + 1
                if kind == "RequestMapping":
                    methods = re.findall(r"RequestMethod\.(\w+)", args) or ["GET"]
                else:
                    methods = [HTTP_ANNOTATIONS[kind]]
                paths = _mapping_paths(args)
                signature = re.search(r"(\w+)\s*\(", body[cursor:])
                if not signature:
                    continue
                handler = signature.group(1)
                open_idx = cursor + signature.end() - 1
                close_idx = _balanced(body, open_idx)
                raw_params = body[open_idx + 1:close_idx] if close_idx != -1 else ""
                multipart = "MULTIPART_FORM_DATA" in args or "multipart/form-data" in args
                for method in methods:
                    for base in base_paths:
                        for sub in paths:
                            endpoint = Endpoint(method=method, path=_join_path(base, sub), multipart=multipart,
                                                controller=class_name, handler=handler, tag=class_name, index=index)
                            for raw in _split_top_level(raw_params):
                                _parse_parameter(raw, index, schemas, method, endpoint)
                            endpoints.append(endpoint)
    return endpoints


# ------------------------------------------------------------- security rules
@dataclass
class SecurityRule:
    methods: set[str]
    patterns: list[str]
    rule: str


def parse_security_rules(index: JavaIndex) -> list[SecurityRule]:
    rules: list[SecurityRule] = []
    for _, text in index.files:
        for match in re.finditer(r"requestMatchers\s*\(", text):
            open_idx = match.end() - 1
            close_idx = _balanced(text, open_idx)
            if close_idx == -1:
                continue
            args = text[open_idx + 1:close_idx]
            tail = text[close_idx + 1: close_idx + 160]
            rule_match = re.match(r"\s*\.\s*(permitAll|authenticated|denyAll|hasRole|hasAnyRole|hasAuthority|hasAnyAuthority)\s*\(([^)]*)\)", tail)
            if not rule_match:
                continue
            name, rule_args = rule_match.groups()
            methods = {m.upper() for m in re.findall(r"HttpMethod\.(\w+)", args)}
            patterns = _string_literals(args)
            if not patterns:
                continue
            rule = name
            roles = _string_literals(rule_args)
            if roles:
                rule = f"{name}:{','.join(roles)}"
            rules.append(SecurityRule(methods, patterns, rule))
    return rules


def _ant_to_regex(pattern: str) -> re.Pattern:
    out, i = "", 0
    while i < len(pattern):
        if pattern.startswith("**", i):
            out += ".*"
            i += 2
        elif pattern[i] == "*":
            out += "[^/]*"
            i += 1
        elif pattern[i] == "{":
            end = pattern.index("}", i)
            out += "[^/]+"
            i = end + 1
        else:
            out += re.escape(pattern[i])
            i += 1
    return re.compile("^" + out + "/?$")


def security_for(endpoint: Endpoint, rules: list[SecurityRule]) -> str:
    concrete = re.sub(r"\{[^}]+\}", "x", endpoint.path)
    for rule in rules:
        if rule.methods and endpoint.method not in rule.methods:
            continue
        if any(_ant_to_regex(p).match(concrete) for p in rule.patterns):
            return rule.rule
    return "authenticated"


# ------------------------------------------------------------------ outputs
def build_openapi(name: str, endpoints: list[Endpoint], index: JavaIndex, schemas: dict, rules: list[SecurityRule],
                  server_url: str) -> dict:
    paths: dict[str, dict] = {}
    for endpoint in endpoints:
        operation: dict = {
            "tags": [endpoint.tag],
            "operationId": f"{endpoint.controller}_{endpoint.handler}_{endpoint.method.lower()}",
            "parameters": [],
            "responses": {"200": {"description": "OK"}},
        }
        for param in endpoint.params:
            if param.location in {"path", "query", "header"}:
                operation["parameters"].append(
                    {"name": param.name, "in": param.location, "required": param.required or param.location == "path",
                     "schema": param.schema}
                )
        if endpoint.multipart:
            props = {p.name: p.schema for p in endpoint.params if p.location == "part"}
            if endpoint.body_type:
                ref = type_schema(endpoint.body_type, endpoint.index or index, schemas)
                props.update(schemas.get(ref.get("$ref", "").rsplit("/", 1)[-1], {}).get("properties", {}))
            operation["requestBody"] = {"content": {"multipart/form-data": {"schema": {"type": "object", "properties": props}}}}
        elif endpoint.body_type:
            schema = type_schema(endpoint.body_type, endpoint.index or index, schemas)
            if endpoint.body_is_list:
                schema = {"type": "array", "items": schema}
            operation["requestBody"] = {"required": True, "content": {"application/json": {"schema": schema}}}
        rule = security_for(endpoint, rules)
        if rule != "permitAll":
            operation["security"] = [{"bearerAuth": []}]
        if ":" in rule:
            operation["x-required-role"] = rule.split(":", 1)[1]
        if not operation["parameters"]:
            del operation["parameters"]
        paths.setdefault(endpoint.path, {})[endpoint.method.lower()] = operation
    return {
        "openapi": "3.0.3",
        "info": {"title": f"{name} (extracted from source)", "version": "1.0.0"},
        "servers": [{"url": server_url}] if server_url else [],
        "paths": dict(sorted(paths.items())),
        "components": {
            "schemas": schemas,
            "securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}},
        },
    }


def build_api_list(name: str, endpoints: list[Endpoint]) -> str:
    lines = [
        f"# {name} API List (extracted from source by extract_api_from_source.py)",
        "# Format: METHOD /path | queryParam, queryParam",
        "# Path params like {id} stay in the path.",
        "",
    ]
    seen = set()
    for endpoint in sorted(endpoints, key=lambda e: (e.path, e.method)):
        key = (endpoint.method, endpoint.path)
        if key in seen:
            continue
        seen.add(key)
        query = [p.name for p in endpoint.params if p.location == "query"]
        suffix = f" | {', '.join(query)}" if query else ""
        lines.append(f"{endpoint.method} {endpoint.path}{suffix}")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------- frontend routes
_ROUTE_TAG = re.compile(r"<(/?)Route\b([^>]*?)(/?)>", re.S)
_OBJECT_ROUTE = re.compile(r"\bpath\s*:\s*['\"`]([^'\"`]+)['\"`]")


def extract_routes(frontend_root: Path) -> list[str]:
    routes: list[str] = []

    def add(path: str) -> None:
        if "*" in path:
            return
        path = re.sub(r":(\w+)\??", r"{\1}", path)
        if path not in routes:
            routes.append(path)

    for source in sorted(Path(frontend_root).rglob("*")):
        if source.suffix not in {".jsx", ".tsx", ".js", ".ts"} or "node_modules" in source.parts:
            continue
        text = source.read_text(encoding="utf-8", errors="replace")
        if "<Route" in text:
            stack: list[str] = []
            for match in _ROUTE_TAG.finditer(text):
                closing, attrs, self_closing = match.groups()
                if closing:
                    if stack:
                        stack.pop()
                    continue
                path_match = re.search(r"\bpath\s*=\s*['\"{`]+([^'\"`}]+)['\"`}]", attrs)
                own = path_match.group(1) if path_match else ""
                if own.startswith("/"):
                    full = own
                else:
                    full = _join_path(stack[-1] if stack else "", own) if own else (stack[-1] if stack else "")
                if path_match or attrs.strip().startswith("index"):
                    add(full or "/")
                if not self_closing:
                    stack.append(full)
        elif "createBrowserRouter" in text or "createRoutesFromElements" in text or "routes" in text.lower():
            for match in _OBJECT_ROUTE.finditer(text):
                if match.group(1).startswith("/"):
                    add(match.group(1))
    return routes


def build_url_list(name: str, routes: list[str]) -> str:
    lines = [
        f"# {name} URL List (frontend routes extracted from React Router by extract_api_from_source.py)",
        "# One path per line. Dynamic segments are written as {param}.",
        "",
    ]
    lines.extend(routes or ["/"])
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------- main
def run(name: str, backend_roots: list[Path], frontend_roots: list[Path] | None, out_dir: Path, server_url: str,
        exclude_prefixes: list[str] | None = None) -> dict:
    schemas: dict = {}
    endpoints: list[Endpoint] = []
    rules: list[SecurityRule] = []
    index = None
    for root in backend_roots:
        index = JavaIndex([root])
        endpoints.extend(parse_controllers(index, schemas))
        rules.extend(parse_security_rules(index))
    if exclude_prefixes:
        endpoints = [e for e in endpoints if not any(e.path.startswith(prefix) for prefix in exclude_prefixes)]
    openapi = build_openapi(name, endpoints, index, schemas, rules, server_url)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{name}-swagger.json").write_text(json.dumps(openapi, ensure_ascii=False, indent=2), encoding="utf-8")
    (out_dir / f"{name}-api-list.txt").write_text(build_api_list(name, endpoints), encoding="utf-8")
    routes: list[str] = []
    for frontend_root in frontend_roots or []:
        routes.extend(r for r in extract_routes(frontend_root) if r not in routes)
    (out_dir / f"{name}-url-list.txt").write_text(build_url_list(name, routes), encoding="utf-8")
    return {"endpoints": len(endpoints), "paths": len(openapi["paths"]), "routes": len(routes), "schemas": len(schemas),
            "security_rules": len(rules)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--name", required=True)
    parser.add_argument("--backend", required=True, nargs="+", type=Path, help="Spring source root(s), e.g. src/main/java")
    parser.add_argument("--frontend", nargs="+", type=Path, help="React source root(s) (for the url list)")
    parser.add_argument("--exclude-prefix", nargs="+", default=[], help="drop endpoints under these path prefixes (e.g. /internal)")
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--server-url", default="", help="base URL written into the OpenAPI servers block")
    args = parser.parse_args(argv)
    summary = run(args.name, args.backend, args.frontend, args.out, args.server_url, args.exclude_prefix)
    print(json.dumps(summary, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
