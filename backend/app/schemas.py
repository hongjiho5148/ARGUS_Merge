from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class SourceOption(BaseModel):
    id: str
    label: str


class SourceOptionsResponse(BaseModel):
    sources: list[SourceOption]


class InventoryStats(BaseModel):
    total_endpoints: int = 0
    frontend_endpoints: int = 0
    api_endpoints: int = 0
    write_endpoints: int = 0
    with_body: int = 0
    with_query: int = 0
    schema_coverage_pct: int = 0
    schema_enriched: int = 0
    targets: dict[str, int] = Field(default_factory=dict)
    sources_used: list[str] = Field(default_factory=list)
    sources_missing: list[str] = Field(default_factory=list)


class BuildInventoryResponse(BaseModel):
    ok: bool
    stats: InventoryStats
    artifacts: dict[str, str] = Field(default_factory=dict)
    message: str = ""


class EndpointSummary(BaseModel):
    id: str
    method: str
    path: str
    base_url: str
    kind: str
    tags: list[str]
    sources: list[str]
    input_count: int
    inputs_preview: list[str]


class EndpointListResponse(BaseModel):
    total: int
    items: list[EndpointSummary]


class InputParamSummary(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    in_: str = Field(alias="in")
    name: str
    type: str = "string"
    required: bool = False
    sample: str | None = None
    role: str = "input"
    sources: list[str] = Field(default_factory=list)


class HeaderFieldSummary(BaseModel):
    name: str
    sample: str | None = None
    role: str = "meta"
    required: bool = False
    sources: list[str] = Field(default_factory=list)


class AccountAccessSummary(BaseModel):
    auth_mode: str
    account_email: str | None = None
    login_url: str | None = None
    login_label: str | None = None
    http_status: int | None = None
    status: str = ""
    note: str = ""
    allowed: bool = False


class LoginEntryPointSummary(BaseModel):
    url: str
    label: str


class LoginAccountEntrySummary(BaseModel):
    email: str
    successful_login_urls: list[str] = Field(default_factory=list)
    failed_login_urls: list[str] = Field(default_factory=list)
    exclusive_login_url: str | None = None
    entry_specific: bool = False


class LoginEntryReportResponse(BaseModel):
    available: bool
    checked_at: str | None = None
    session_count: int = 0
    login_entries: list[LoginEntryPointSummary] = Field(default_factory=list)
    accounts: list[LoginAccountEntrySummary] = Field(default_factory=list)
    entry_specific_accounts: list[str] = Field(default_factory=list)


class EndpointDetailResponse(BaseModel):
    found: bool
    id: str = ""
    method: str = ""
    path: str = ""
    base_url: str = ""
    kind: str = ""
    tags: list[str] = Field(default_factory=list)
    auth: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    request_params: list[InputParamSummary] = Field(default_factory=list)
    response_params: list[InputParamSummary] = Field(default_factory=list)
    request_headers: list[HeaderFieldSummary] = Field(default_factory=list)
    response_headers: list[HeaderFieldSummary] = Field(default_factory=list)
    account_access: list[AccountAccessSummary] = Field(default_factory=list)


class VerifyInventoryResponse(BaseModel):
    ok: bool
    stats: InventoryStats
    summary: dict[str, int | str] = Field(default_factory=dict)
    artifacts: dict[str, str] = Field(default_factory=dict)
    message: str = ""


class VerifyResultSummary(BaseModel):
    endpoint_id: str
    method: str
    path: str
    base_url: str
    url: str
    http_status: int | None = None
    status: str
    note: str = ""
    include_in_final: bool
    discovered: bool = False


class VerifyReportSummary(BaseModel):
    total_checked: int = 0
    confirmed: int = 0
    params_issues: int = 0
    rejected: int = 0
    verified_count: int = 0
    final_count: int = 0
    discovered_count: int = 0
    probe_runs: int = 0
    accounts_logged_in: int = 0


class VerifyReportResponse(BaseModel):
    available: bool
    checked_at: str | None = None
    summary: VerifyReportSummary = Field(default_factory=VerifyReportSummary)
    total: int = 0
    items: list[VerifyResultSummary] = Field(default_factory=list)


class DiscoverProgressResponse(BaseModel):
    running: bool = False
    phase: str = ""
    message: str = ""
    step: int = 0
    total_steps: int = 0
    updated_at: str | None = None


class TestAccountEntry(BaseModel):
    id: str
    email: str = ""
    password: str = ""


class TestAccountsResponse(BaseModel):
    accounts: list[TestAccountEntry]


class SaveTestAccountsRequest(BaseModel):
    accounts: list[TestAccountEntry]


class SaveTestAccountsResponse(BaseModel):
    ok: bool
    accounts: list[TestAccountEntry]
    message: str = ""


class BaseUrlEntry(BaseModel):
    id: str
    url: str = ""


class BaseUrlsResponse(BaseModel):
    urls: list[BaseUrlEntry]


class SaveBaseUrlsRequest(BaseModel):
    urls: list[BaseUrlEntry]


class SaveBaseUrlsResponse(BaseModel):
    ok: bool
    urls: list[BaseUrlEntry]
    message: str = ""


class LoginEndpointEntry(BaseModel):
    id: str
    url: str = ""
    kind: Literal["api", "page"] = "api"


class LoginEndpointResolved(BaseModel):
    url: str
    label: str
    source: str
    kind: str = "api"


class LoginEndpointsResponse(BaseModel):
    endpoints: list[LoginEndpointEntry]
    resolved: list[LoginEndpointResolved] = Field(default_factory=list)


class SaveLoginEndpointsRequest(BaseModel):
    endpoints: list[LoginEndpointEntry]


class SaveLoginEndpointsResponse(BaseModel):
    ok: bool
    endpoints: list[LoginEndpointEntry]
    resolved: list[LoginEndpointResolved] = Field(default_factory=list)
    message: str = ""


class DiagnosisCatalogModule(BaseModel):
    id: str
    title: str
    chapter: int
    registered: bool = False
    implemented: bool = False
    diagnosable: bool = True
    review_later: bool = False
    status_label: str | None = None
    engine: str = "pending"


class DiagnosisCatalogResponse(BaseModel):
    modules: list[DiagnosisCatalogModule]
    total: int = 0


class DiagnosisProgressResponse(BaseModel):
    running: bool = False
    section_id: str | None = None
    phase: str = ""
    message: str = ""
    endpoints_done: int = 0
    endpoints_total: int = 0
    requests_sent: int = 0
    requests_cap: int | None = None
    percent: int = 0
    updated_at: str | None = None


class DiagnosisFindingSummary(BaseModel):
    severity: str = "info"
    message: str = ""
    evidence: dict = Field(default_factory=dict)


class DiagnosisSectionReportResponse(BaseModel):
    section_id: str
    title: str
    chapter: int
    status: str = "pending"
    implemented: bool = False
    message: str = ""
    checked_at: str | None = None
    findings: list[DiagnosisFindingSummary] = Field(default_factory=list)


class DiagnosisRunSectionResponse(BaseModel):
    ok: bool
    report: DiagnosisSectionReportResponse


class DiagnosisRunAllResponse(BaseModel):
    ok: bool
    total: int = 0
    reports: list[DiagnosisSectionReportResponse] = Field(default_factory=list)


class DiagnosisG41RunOptions(BaseModel):
    """Per-run overrides for guideline 4-1 cookie manipulation scan."""

    probe_mode: Literal["base_only", "sample", "full"] | None = None
    sample_size: int | None = Field(default=None, ge=5, le=500)
    max_endpoints: int | None = Field(default=None, ge=10, le=500)
    timeout: float | None = Field(default=None, ge=1.0, le=60.0)
    max_pairs_per_endpoint: int | None = Field(default=None, ge=2, le=50)
    cross_cookie_enabled: bool | None = None
    tamper_enabled: bool | None = None
    tamper_max_endpoints: int | None = Field(default=None, ge=5, le=200)
    cookie_attr_enabled: bool | None = None
    cookie_attr_strict: bool | None = None
    auth_required_only: bool | None = None


class DiagnosisG15RunOptions(BaseModel):
    """Per-run overrides for guideline 1-5 open redirect / CORS scan."""

    probe_mode: Literal["base_only", "sample", "full"] | None = None
    sample_size: int | None = Field(default=None, ge=10, le=500)
    timeout: float | None = Field(default=None, ge=1.0, le=60.0)
    zap_enabled: bool | None = None
    zap_max_minutes: int | None = Field(default=None, ge=1, le=120)
    cors_enabled: bool | None = None
    crossdomain_enabled: bool | None = None
    redirect_sink_base: str | None = None
    max_phase_a_jobs: int | None = Field(default=None, ge=20, le=5000)
    max_phase_b_jobs: int | None = Field(default=None, ge=20, le=10000)


class DiagnosisG22RunOptions(BaseModel):
    """Per-run overrides for guideline 2-2 scan (merged into config for one execution)."""

    zap_enabled: bool | None = None
    httpx_enabled: bool | None = None
    min_score: int | None = Field(default=None, ge=0, le=20)
    max_candidates: int | None = Field(default=None, ge=0, le=500)
    zap_max_minutes: int | None = Field(default=None, ge=1, le=120)
    scan_all_inventory: bool | None = None
    idor_probe_enabled: bool | None = None


class DiagnosisG72RunOptions(BaseModel):
    """Per-run overrides for guideline 7-2 directory listing scan."""

    probe_mode: Literal["base_only", "sample", "full"] | None = None
    sample_size: int | None = Field(default=None, ge=1, le=500)
    use_extended_wordlist: bool | None = None
    timeout: float | None = Field(default=None, ge=1.0, le=60.0)
    extra_probe_paths: list[str] | None = None
    zap_enabled: bool | None = None
    zap_max_minutes: int | None = Field(default=None, ge=1, le=120)


class DiagnosisG73RunOptions(BaseModel):
    """Per-run overrides for guideline 7-3 header disclosure scan."""

    strict: bool | None = None
    include_cdn_headers: bool | None = None
    timeout: float | None = Field(default=None, ge=1.0, le=60.0)
    extra_probe_paths: list[str] | None = None
    probe_mode: Literal["base_only", "sample", "full"] | None = None
    sample_size: int | None = Field(default=None, ge=1, le=500)
    zap_enabled: bool | None = None
    zap_max_minutes: int | None = Field(default=None, ge=1, le=120)


class DiagnosisG71RunOptions(BaseModel):
    """Per-run overrides for guideline 7-1 insecure HTTP method scan."""

    strict_risky: bool | None = None
    timeout: float | None = Field(default=None, ge=1.0, le=60.0)
    extra_probe_paths: list[str] | None = None
    probe_mode: Literal["base_only", "sample", "full"] | None = None
    sample_size: int | None = Field(default=None, ge=1, le=500)
    zap_enabled: bool | None = None
    zap_max_minutes: int | None = Field(default=None, ge=1, le=120)


class DiagnosisG74RunOptions(BaseModel):
    """Per-run overrides for guideline 7-4 weak security configuration scan."""

    strict: bool | None = None
    check_cookies: bool | None = None
    timeout: float | None = Field(default=None, ge=1.0, le=60.0)
    extra_probe_paths: list[str] | None = None
    probe_mode: Literal["base_only", "sample", "full"] | None = None
    sample_size: int | None = Field(default=None, ge=1, le=500)
    zap_enabled: bool | None = None
    zap_max_minutes: int | None = Field(default=None, ge=1, le=120)


class DiagnosisG61RunOptions(BaseModel):
    """Per-run overrides for guideline 6-1 error-page disclosure scan."""

    probe_mode: Literal["sample", "full"] | None = None
    sample_size: int | None = Field(default=None, ge=5, le=500)
    max_endpoints: int | None = Field(default=None, ge=0, le=500)
    max_requests: int | None = Field(
        default=None,
        ge=0,
        description="0 = unlimited (exhaustive); positive values are capped at >=100",
    )
    timeout: float | None = Field(default=None, ge=1.0, le=60.0)
    interval_sec: float | None = Field(default=None, ge=0.0, le=2.0)
    httpx_enabled: bool | None = None
    zap_enabled: bool | None = None
    zap_unified_enabled: bool | None = None
    zap_supplemental_enabled: bool | None = None
    zap_max_requests: int | None = Field(default=None, ge=0, description="0 = unlimited")
    zap_max_minutes: int | None = Field(default=None, ge=1, le=480)
    zap_seed_cap: int | None = Field(
        default=None,
        ge=0,
        description="0 = seed every probe URL for ZAP supplemental",
    )


class DiagnosisG52RunOptions(BaseModel):
    """Per-run overrides for guideline 5-2 sensitive data in request/response scan."""

    probe_mode: Literal["sample", "full"] | None = None
    sample_size: int | None = Field(default=None, ge=5, le=500)
    max_endpoints: int | None = Field(default=None, ge=0, le=5000)
    timeout: float | None = Field(default=None, ge=1.0, le=60.0)
    interval_sec: float | None = Field(default=None, ge=0.0, le=2.0)
    check_request_url: bool | None = None
    check_request_body: bool | None = None
    check_response_body: bool | None = None
    check_http_plain: bool | None = None
    enable_auth_modes: bool | None = None


class DiagnosisG62RunOptions(BaseModel):
    """Per-run overrides for guideline 6-2 login failure uniformity scan."""

    strict: bool | None = None
    timeout: float | None = Field(default=None, ge=1.0, le=60.0)
    wrong_password: str | None = None
    probe_account_email: str | None = None
    zap_enabled: bool | None = None
    zap_max_minutes: int | None = Field(default=None, ge=1, le=30)


class DiagnosisG35RunOptions(BaseModel):
    """Per-run overrides for guideline 3-5 search-engine inventory scan."""

    probe_mode: Literal["base_only", "sample", "full"] | None = None
    sample_size: int | None = Field(default=None, ge=1, le=500)
    timeout: float | None = Field(default=None, ge=1.0, le=60.0)
    extra_probe_paths: list[str] | None = None


class DiagnosisG36RunOptions(BaseModel):
    """Per-run overrides for guideline 3-6 backup/test file scan."""

    probe_mode: Literal["base_only", "sample", "full"] | None = None
    sample_size: int | None = Field(default=None, ge=1, le=500)
    timeout: float | None = Field(default=None, ge=1.0, le=60.0)
    extra_probe_paths: list[str] | None = None


class DiagnosisG32RunOptions(BaseModel):
    """Per-run overrides for guideline 3-2 auth failure count limit scan."""

    max_attempts: int | None = Field(default=None, ge=3, le=25)
    timeout: float | None = Field(default=None, ge=1.0, le=60.0)
    interval_sec: float | None = Field(default=None, ge=0.0, le=2.0)
    wrong_password: str | None = None
    probe_account_email: str | None = None
    strict: bool | None = None
    max_login_entries: int | None = Field(default=None, ge=0, le=50)


class DiagnosisG34RunOptions(BaseModel):
    """Per-run overrides for guideline 3-4 admin separation scan."""

    inventory_scope: Literal["login_only", "full"] | None = None


class DiagnosisG21RunOptions(BaseModel):
    """Per-run overrides for guideline 2-1 malicious upload scan."""

    httpx_enabled: bool | None = None
    zap_enabled: bool | None = None
    max_targets: int | None = Field(default=None, ge=1, le=200)
    zap_passive_wait_seconds: int | None = Field(default=None, ge=0, le=300)
    timeout: float | None = Field(default=None, ge=1.0, le=60.0)
    allowed_extensions: list[str] | None = None
    interval_sec: float | None = Field(default=None, ge=0.0, le=5.0)
    enable_auth_modes: bool | None = None
    max_requests: int | None = Field(default=None, ge=0)


class DiagnosisG42RunOptions(BaseModel):
    """Per-run overrides for guideline 4-2 token/session safety scan."""

    timeout: float | None = Field(default=None, ge=1.0, le=60.0)
    relogin_enabled: bool | None = None
    duplicate_login_enabled: bool | None = None
    duplicate_login_ip_enabled: bool | None = None
    logout_enabled: bool | None = None
    client_logout_enabled: bool | None = None
    probe_account_email: str | None = None


class DiagnosisRunSectionRequest(BaseModel):
    g15: DiagnosisG15RunOptions | None = None
    g21: DiagnosisG21RunOptions | None = None
    g41: DiagnosisG41RunOptions | None = None
    g22: DiagnosisG22RunOptions | None = None
    g32: DiagnosisG32RunOptions | None = None
    g34: DiagnosisG34RunOptions | None = None
    g35: DiagnosisG35RunOptions | None = None
    g36: DiagnosisG36RunOptions | None = None
    g42: DiagnosisG42RunOptions | None = None
    g52: DiagnosisG52RunOptions | None = None
    g61: DiagnosisG61RunOptions | None = None
    g62: DiagnosisG62RunOptions | None = None
    g71: DiagnosisG71RunOptions | None = None
    g72: DiagnosisG72RunOptions | None = None
    g73: DiagnosisG73RunOptions | None = None
    g74: DiagnosisG74RunOptions | None = None


class ReplayFindingSummary(BaseModel):
    severity: str | None = None
    message: str | None = None
    finding_id: str | None = None
    rule_id: str | None = None


class ReplayListResponse(BaseModel):
    section_id: str
    total: int = 0
    findings: list[ReplayFindingSummary] = Field(default_factory=list)


class ReplayStepResult(BaseModel):
    step_id: str
    action: str
    ok: bool
    message: str = ""
    artifacts: dict[str, str] = Field(default_factory=dict)


class ReplayRunResultResponse(BaseModel):
    finding_id: str
    ok: bool
    output_dir: str = ""
    message: str = ""
    steps: list[ReplayStepResult] = Field(default_factory=list)


class ReplayRunRequest(BaseModel):
    finding_id: str | None = None
    use_playwright: bool = True


class ReplayRunSectionResponse(BaseModel):
    ok: bool
    section_id: str
    results: list[ReplayRunResultResponse] = Field(default_factory=list)
