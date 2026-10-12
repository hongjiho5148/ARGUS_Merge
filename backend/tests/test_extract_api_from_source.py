"""extract_api_from_source: OpenAPI / api-list / url-list extraction from Spring + React sources."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "extract_api_from_source.py"


@pytest.fixture(scope="module")
def ex():
    spec = importlib.util.spec_from_file_location("extract_api_from_source_test", _SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    import sys

    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


CONTROLLER = '''
package demo;

@RestController
@RequestMapping("/api/items")
public class ItemController {

    @PostMapping
    public Resp create(@Valid @RequestBody ItemRequest body, @AuthenticationPrincipal User user) { return null; }

    @GetMapping("/{itemId}")
    public Resp one(@PathVariable Long itemId) { return null; }

    @GetMapping
    public Resp list(@RequestParam(required = false) String keyword,
                     @RequestParam(defaultValue = "0") int page,
                     Pageable pageable) { return null; }

    @RequestMapping(value = "/legacy", method = RequestMethod.PUT)
    public Resp legacy() { return null; }

    @PatchMapping(value = "/image", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public Resp image(@RequestPart("file") MultipartFile file) { return null; }

    @GetMapping({"/a", "/b"})
    public Resp both() { return null; }
}
'''

DTO = '''
public class ItemRequest {
    @NotBlank
    @Size(min = 2, max = 20)
    private String name;

    @NotNull
    @Min(1)
    private Integer count;

    private Kind kind;

    @Email
    private String contact;

    private java.util.Set<String> tags;
}
'''

ENUM = "public enum Kind { SMALL, LARGE; }"

RECORD = "public record Login(@NotBlank String email, String password) {}"

SECURITY = '''
class SecurityConfig {
    void chain(HttpSecurity http) {
        http.authorizeHttpRequests(a -> a
            .requestMatchers("/api/auth/**").permitAll()
            .requestMatchers(HttpMethod.GET, "/api/items", "/api/items/{id}").permitAll()
            .requestMatchers("/admin/**").hasRole("ADMIN")
            .anyRequest().authenticated());
    }
}
'''


@pytest.fixture
def source(tmp_path):
    root = tmp_path / "java"
    root.mkdir()
    for name, text in {
        "ItemController.java": CONTROLLER,
        "ItemRequest.java": DTO,
        "Kind.java": ENUM,
        "Login.java": RECORD,
        "SecurityConfig.java": SECURITY,
    }.items():
        (root / name).write_text(text, encoding="utf-8")
    return root


@pytest.fixture
def spec(ex, source):
    index = ex.JavaIndex([source])
    schemas: dict = {}
    endpoints = ex.parse_controllers(index, schemas)
    rules = ex.parse_security_rules(index)
    return ex.build_openapi("demo", endpoints, index, schemas, rules, "http://x"), endpoints


def _ops(spec):
    return {(m.upper(), p): op for p, item in spec[0]["paths"].items() for m, op in item.items()}


def test_class_prefix_and_method_paths_are_combined(spec):
    ops = _ops(spec)
    assert ("POST", "/api/items") in ops
    assert ("GET", "/api/items/{itemId}") in ops
    assert ("PUT", "/api/items/legacy") in ops


def test_multiple_paths_in_one_annotation(spec):
    ops = _ops(spec)
    assert ("GET", "/api/items/a") in ops and ("GET", "/api/items/b") in ops


def test_path_and_query_parameters(spec):
    ops = _ops(spec)
    path_param = ops[("GET", "/api/items/{itemId}")]["parameters"][0]
    assert (path_param["name"], path_param["in"], path_param["required"]) == ("itemId", "path", True)
    listing = {p["name"]: p for p in ops[("GET", "/api/items")]["parameters"]}
    assert listing["keyword"]["required"] is False
    assert listing["page"]["required"] is False
    assert "size" in listing
    assert "sort" not in listing
    assert listing["size"]["schema"]["example"] == 10


def test_authentication_principal_is_not_a_parameter(spec):
    assert "parameters" not in _ops(spec)[("POST", "/api/items")]


def test_request_body_schema_carries_validation_and_enum(spec):
    schema = spec[0]["components"]["schemas"]["ItemRequest"]
    props = schema["properties"]
    assert set(schema["required"]) == {"name", "count"}
    assert (props["name"]["minLength"], props["name"]["maxLength"]) == (2, 20)
    assert props["count"]["minimum"] == 1
    assert props["contact"]["format"] == "email"
    assert props["kind"] == {"type": "string", "enum": ["SMALL", "LARGE"]}


def test_fully_qualified_collection_type_is_resolved(spec):
    assert spec[0]["components"]["schemas"]["ItemRequest"]["properties"]["tags"] == {
        "type": "array", "items": {"type": "string"},
    }


def test_multipart_endpoint(spec):
    body = _ops(spec)[("PATCH", "/api/items/image")]["requestBody"]["content"]
    assert "multipart/form-data" in body
    assert body["multipart/form-data"]["schema"]["properties"]["file"]["format"] == "binary"


def test_record_dto(ex, source):
    index = ex.JavaIndex([source])
    schemas: dict = {}
    ex.type_schema("Login", index, schemas)
    assert schemas["Login"]["required"] == ["email"]
    assert set(schemas["Login"]["properties"]) == {"email", "password"}


def test_security_rules_mark_public_and_role_restricted(ex, source):
    index = ex.JavaIndex([source])
    rules = ex.parse_security_rules(index)
    probe = lambda method, path: ex.security_for(ex.Endpoint(method, path), rules)
    assert probe("POST", "/api/auth/login") == "permitAll"
    assert probe("GET", "/api/items/5") == "permitAll"
    assert probe("POST", "/api/items") == "authenticated"
    assert probe("GET", "/admin/users") == "hasRole:ADMIN"


def test_public_endpoints_have_no_security_requirement(spec):
    ops = _ops(spec)
    assert "security" not in ops[("GET", "/api/items/{itemId}")]
    assert ops[("POST", "/api/items")]["security"] == [{"bearerAuth": []}]


def test_api_list_format(ex, spec):
    text = ex.build_api_list("demo", spec[1])
    assert "GET /api/items | keyword, page, size" in text
    assert "GET /api/items/{itemId}\n" in text
    assert "PUT /api/items/legacy" in text


def test_react_router_nested_and_dynamic_routes(ex, tmp_path):
    src = tmp_path / "fe"
    src.mkdir()
    (src / "App.jsx").write_text(
        '''
        <Routes>
          <Route element={<Layout />}>
            <Route path="/" element={<Main />} />
            <Route path="/posts/:id" element={<Post />} />
          </Route>
          <Route path="/mypage">
            <Route path="posts" element={<Mine />} />
          </Route>
          <Route path="*" element={<NotFound />} />
        </Routes>
        ''',
        encoding="utf-8",
    )
    routes = ex.extract_routes(src)
    assert routes == ["/", "/posts/{id}", "/mypage", "/mypage/posts"]


def test_run_writes_three_files(ex, source, tmp_path):
    out = tmp_path / "out"
    summary = ex.run("demo", [source], None, out, "http://x")
    assert summary["endpoints"] == 7
    assert json.loads((out / "demo-swagger.json").read_text(encoding="utf-8"))["openapi"] == "3.0.3"
    assert (out / "demo-api-list.txt").is_file()
    assert (out / "demo-url-list.txt").read_text(encoding="utf-8").strip().endswith("/")


def test_examples_follow_declared_constraints(ex, tmp_path):
    root = tmp_path / "java2"
    root.mkdir()
    (root / "Phone.java").write_text(
        r"""
        public class PhoneRequest {
            @NotBlank
            @Pattern(regexp = "^\d{11}$")
            private String phoneNumber;

            @Min(2)
            private Integer recruitCount;

            @Size(min = 4, max = 10)
            private String title;
        }
        """,
        encoding="utf-8",
    )
    index = ex.JavaIndex([root])
    schemas: dict = {}
    ex.type_schema("PhoneRequest", index, schemas)
    props = schemas["PhoneRequest"]["properties"]
    assert props["phoneNumber"]["example"] == "12345678901"
    assert props["recruitCount"]["example"] == 2
    assert props["title"]["example"] == "aaaa"
