export type SourceId = "url_list" | "api_list" | "openapi";

export type SourceFiles = {
  url_list: File | null;
  api_list: File | null;
  openapi: File[];
  gradle_deps: File[];
};

export interface SourceOption {
  id: SourceId;
  label: string;
}

export interface SourceOptionsResponse {
  sources: SourceOption[];
}

export interface BuildSourceSelection {
  url_list_enabled: boolean;
  api_list_enabled: boolean;
  openapi_enabled: boolean;
  gradle_deps_enabled: boolean;
}

export interface BuildInventoryPayload {
  selection: BuildSourceSelection;
  files: SourceFiles;
}

export interface InventoryStats {
  total_endpoints: number;
  frontend_endpoints: number;
  api_endpoints: number;
  write_endpoints: number;
  with_body: number;
  with_query: number;
  schema_coverage_pct: number;
  schema_enriched: number;
  targets: Record<string, number>;
  sources_used: string[];
  sources_missing: string[];
}

export interface EndpointSummary {
  id: string;
  method: string;
  path: string;
  base_url: string;
  kind: string;
  tags: string[];
  sources: string[];
  input_count: number;
  inputs_preview: string[];
}

export interface EndpointListResponse {
  total: number;
  items: EndpointSummary[];
}

export interface InputParamDetail {
  in: string;
  name: string;
  type: string;
  required: boolean;
  sample: string | null;
  role: string;
  sources: string[];
}

export interface HeaderFieldDetail {
  name: string;
  sample: string | null;
  role: string;
  required: boolean;
  sources: string[];
}

export interface AccountAccessDetail {
  auth_mode: string;
  account_email: string | null;
  login_url: string | null;
  login_label: string | null;
  http_status: number | null;
  status: string;
  note: string;
  allowed: boolean;
}

export interface LoginEntryPoint {
  url: string;
  label: string;
}

export interface LoginAccountEntry {
  email: string;
  successful_login_urls: string[];
  failed_login_urls: string[];
  exclusive_login_url: string | null;
  entry_specific: boolean;
}

export interface LoginEntryReportResponse {
  available: boolean;
  checked_at: string | null;
  session_count: number;
  login_entries: LoginEntryPoint[];
  accounts: LoginAccountEntry[];
  entry_specific_accounts: string[];
}

export interface EndpointDetail {
  found: boolean;
  id: string;
  method: string;
  path: string;
  base_url: string;
  kind: string;
  tags: string[];
  auth: string[];
  sources: string[];
  request_params: InputParamDetail[];
  response_params: InputParamDetail[];
  request_headers: HeaderFieldDetail[];
  response_headers: HeaderFieldDetail[];
  account_access: AccountAccessDetail[];
}

export interface BuildResponse {
  ok: boolean;
  stats: InventoryStats;
  artifacts: Record<string, string | string[]>;
  message: string;
}

export interface VerifyResponse {
  ok: boolean;
  stats: InventoryStats;
  summary: Record<string, number | string>;
  artifacts: Record<string, string>;
  message: string;
}

export interface DiscoverProgressResponse {
  running: boolean;
  phase: string;
  message: string;
  step: number;
  total_steps: number;
  updated_at: string | null;
}

export interface DiagnosisProgressResponse {
  running: boolean;
  section_id: string | null;
  phase: string;
  message: string;
  endpoints_done: number;
  endpoints_total: number;
  requests_sent: number;
  requests_cap: number | null;
  percent: number;
  updated_at: string | null;
}

export interface VerifyReportSummary {
  total_checked: number;
  confirmed: number;
  params_issues: number;
  rejected: number;
  verified_count: number;
  final_count: number;
  discovered_count: number;
  probe_runs?: number;
  accounts_logged_in?: number;
}

export interface VerifyResultSummary {
  endpoint_id: string;
  method: string;
  path: string;
  base_url: string;
  url: string;
  http_status: number | null;
  status: string;
  note: string;
  include_in_final: boolean;
  discovered: boolean;
}

export interface VerifyReportResponse {
  available: boolean;
  checked_at: string | null;
  summary: VerifyReportSummary;
  total: number;
  items: VerifyResultSummary[];
}

export interface TestAccountEntry {
  id: string;
  email: string;
  password: string;
}

export interface TestAccountsResponse {
  accounts: TestAccountEntry[];
}

export interface SaveTestAccountsResponse {
  ok: boolean;
  accounts: TestAccountEntry[];
  message: string;
}

export interface BaseUrlEntry {
  id: string;
  url: string;
}

export interface BaseUrlsResponse {
  urls: BaseUrlEntry[];
}

export interface SaveBaseUrlsResponse {
  ok: boolean;
  urls: BaseUrlEntry[];
  message: string;
}

export type LoginEndpointKind = "api" | "page";

export interface LoginEndpointEntry {
  id: string;
  url: string;
  kind: LoginEndpointKind;
}

export interface LoginEndpointResolved {
  url: string;
  label: string;
  source: string;
  kind: string;
}

export interface LoginEndpointsResponse {
  endpoints: LoginEndpointEntry[];
  resolved: LoginEndpointResolved[];
}

export interface SaveLoginEndpointsResponse {
  ok: boolean;
  endpoints: LoginEndpointEntry[];
  resolved: LoginEndpointResolved[];
  message: string;
}

export type InventoryView = "ready" | "verified";
export type VerifyOutcome = "final" | "discovered" | "rejected";

export interface DiagnosisCatalogModule {
  id: string;
  title: string;
  chapter: number;
  registered: boolean;
  implemented: boolean;
  diagnosable: boolean;
  review_later: boolean;
  status_label: string | null;
  engine: string;
}

export interface DiagnosisCatalogResponse {
  modules: DiagnosisCatalogModule[];
  total: number;
}

export interface DiagnosisFindingSummary {
  severity: string;
  message: string;
  evidence: Record<string, unknown>;
}

export interface DiagnosisSectionReport {
  section_id: string;
  title: string;
  chapter: number;
  status: string;
  implemented: boolean;
  message: string;
  checked_at: string | null;
  findings: DiagnosisFindingSummary[];
}

export interface DiagnosisRunSectionResponse {
  ok: boolean;
  report: DiagnosisSectionReport;
}

export interface DiagnosisG15RunOptionsPayload {
  probe_mode?: "base_only" | "sample" | "full";
  sample_size?: number;
  timeout?: number;
  zap_enabled?: boolean;
  zap_max_minutes?: number;
  cors_enabled?: boolean;
  crossdomain_enabled?: boolean;
  redirect_sink_base?: string;
  max_phase_a_jobs?: number;
  max_phase_b_jobs?: number;
}

export interface DiagnosisG12RunOptionsPayload {
  max_targets?: number;
  scan_all_inventory?: boolean;
  injector_enabled?: boolean;
  direct_enabled?: boolean;
  zap_enabled?: boolean;
  zap_max_minutes?: number;
  verification_mode?: "strict" | "balanced" | "aggressive";
  injection_types?: string[];
  include_unsafe_methods?: boolean;
  keep_all_results?: boolean;
}

export interface DiagnosisG22RunOptionsPayload {
  httpx_enabled?: boolean;
  zap_enabled?: boolean;
  idor_probe_enabled?: boolean;
  scan_all_inventory?: boolean;
  max_candidates?: number;
  zap_max_minutes?: number;
}

export interface DiagnosisG72RunOptionsPayload {
  probe_mode?: "base_only" | "sample" | "full";
  sample_size?: number;
  use_extended_wordlist?: boolean;
  timeout?: number;
  extra_probe_paths?: string[];
}

export interface DiagnosisG52RunOptionsPayload {
  probe_mode?: "sample" | "full";
  sample_size?: number;
  max_endpoints?: number;
  timeout?: number;
  interval_sec?: number;
  check_request_url?: boolean;
  check_request_body?: boolean;
  check_response_body?: boolean;
  check_http_plain?: boolean;
  enable_auth_modes?: boolean;
}

export interface DiagnosisG61RunOptionsPayload {
  probe_mode?: "sample" | "full";
  sample_size?: number;
  max_endpoints?: number;
  max_requests?: number;
  timeout?: number;
  interval_sec?: number;
  zap_enabled?: boolean;
  zap_unified_enabled?: boolean;
  zap_supplemental_enabled?: boolean;
  zap_max_requests?: number;
  zap_max_minutes?: number;
  zap_seed_cap?: number;
  httpx_enabled?: boolean;
}

export interface DiagnosisG71RunOptionsPayload {
  strict_risky?: boolean;
  timeout?: number;
  extra_probe_paths?: string[];
  probe_mode?: "base_only" | "sample" | "full";
  sample_size?: number;
  zap_enabled?: boolean;
  zap_max_minutes?: number;
}

export interface DiagnosisG73RunOptionsPayload {
  strict?: boolean;
  include_cdn_headers?: boolean;
  timeout?: number;
  extra_probe_paths?: string[];
  probe_mode?: "base_only" | "sample" | "full";
  sample_size?: number;
}

export interface DiagnosisG74RunOptionsPayload {
  strict?: boolean;
  check_cookies?: boolean;
  timeout?: number;
  extra_probe_paths?: string[];
  probe_mode?: "base_only" | "sample" | "full";
  sample_size?: number;
  zap_enabled?: boolean;
  zap_max_minutes?: number;
}

export interface DiagnosisG62RunOptionsPayload {
  strict?: boolean;
  timeout?: number;
  wrong_password?: string;
  probe_account_email?: string;
  zap_enabled?: boolean;
  zap_max_minutes?: number;
}

export interface DiagnosisG35RunOptionsPayload {
  probe_mode?: "base_only" | "sample" | "full";
  sample_size?: number;
  timeout?: number;
  extra_probe_paths?: string[];
}

export interface DiagnosisG36RunOptionsPayload {
  probe_mode?: "base_only" | "sample" | "full";
  sample_size?: number;
  timeout?: number;
  extra_probe_paths?: string[];
}

export interface DiagnosisG32RunOptionsPayload {
  max_attempts?: number;
  timeout?: number;
  interval_sec?: number;
  wrong_password?: string;
  probe_account_email?: string;
  strict?: boolean;
  max_login_entries?: number;
}

export interface DiagnosisG34RunOptionsPayload {
  inventory_scope?: "login_only" | "full";
}

export interface DiagnosisG42RunOptionsPayload {
  timeout?: number;
  relogin_enabled?: boolean;
  duplicate_login_enabled?: boolean;
  duplicate_login_ip_enabled?: boolean;
  logout_enabled?: boolean;
  client_logout_enabled?: boolean;
  probe_account_email?: string;
}

export interface DiagnosisG41RunOptionsPayload {
  probe_mode?: "base_only" | "sample" | "full";
  sample_size?: number;
  max_endpoints?: number;
  timeout?: number;
  max_pairs_per_endpoint?: number;
  cross_cookie_enabled?: boolean;
  tamper_enabled?: boolean;
  tamper_max_endpoints?: number;
  cookie_attr_enabled?: boolean;
  cookie_attr_strict?: boolean;
}

export interface DiagnosisRunSectionRequest {
  g12?: DiagnosisG12RunOptionsPayload;
  g15?: DiagnosisG15RunOptionsPayload;
  g41?: DiagnosisG41RunOptionsPayload;
  g22?: DiagnosisG22RunOptionsPayload;
  g32?: DiagnosisG32RunOptionsPayload;
  g34?: DiagnosisG34RunOptionsPayload;
  g35?: DiagnosisG35RunOptionsPayload;
  g36?: DiagnosisG36RunOptionsPayload;
  g42?: DiagnosisG42RunOptionsPayload;
  g52?: DiagnosisG52RunOptionsPayload;
  g61?: DiagnosisG61RunOptionsPayload;
  g62?: DiagnosisG62RunOptionsPayload;
  g71?: DiagnosisG71RunOptionsPayload;
  g72?: DiagnosisG72RunOptionsPayload;
  g73?: DiagnosisG73RunOptionsPayload;
  g74?: DiagnosisG74RunOptionsPayload;
}
