import type {
  BaseUrlEntry,
  BaseUrlsResponse,
  BuildInventoryPayload,
  BuildResponse,
  DiscoverProgressResponse,
  DiagnosisProgressResponse,
  EndpointListResponse,
  EndpointDetail,
  InventoryStats,
  SaveBaseUrlsResponse,
  SaveLoginEndpointsResponse,
  SaveTestAccountsResponse,
  SourceOptionsResponse,
  TestAccountEntry,
  TestAccountsResponse,
  VerifyReportResponse,
  VerifyResponse,
  LoginEndpointEntry,
  LoginEndpointsResponse,
  LoginEntryReportResponse,
  DiagnosisCatalogResponse,
  DiagnosisSectionReport,
  DiagnosisRunSectionResponse,
  DiagnosisRunSectionRequest,
} from "../types";

const BASE = "/api";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, init);
  if (!res.ok) {
    const detail = await res.text();
    throw new Error(detail || `HTTP ${res.status}`);
  }
  return res.json() as Promise<T>;
}

export function fetchHealth(): Promise<{ status: string; service: string }> {
  return request("/health");
}

export function fetchStats(inventory: "ready" | "verified" = "ready"): Promise<InventoryStats> {
  const sp = new URLSearchParams({ inventory });
  return request(`/inventory/stats?${sp.toString()}`);
}

export function fetchSourceOptions(): Promise<SourceOptionsResponse> {
  return request("/inventory/source-options");
}

export function buildInventory(payload: BuildInventoryPayload): Promise<BuildResponse> {
  const { selection, files } = payload;
  const fd = new FormData();
  fd.append("url_list_enabled", String(selection.url_list_enabled));
  fd.append("api_list_enabled", String(selection.api_list_enabled));
  fd.append("openapi_enabled", String(selection.openapi_enabled));
  fd.append("gradle_deps_enabled", String(selection.gradle_deps_enabled));
  if (selection.url_list_enabled && files.url_list) {
    fd.append("url_list_file", files.url_list);
  }
  if (selection.api_list_enabled && files.api_list) {
    fd.append("api_list_file", files.api_list);
  }
  if (selection.openapi_enabled && files.openapi.length > 0) {
    for (const file of files.openapi) {
      fd.append("openapi_files", file);
    }
  }
  if (selection.gradle_deps_enabled && files.gradle_deps.length > 0) {
    for (const file of files.gradle_deps) {
      fd.append("gradle_deps_files", file);
    }
  }
  return request("/inventory/build", { method: "POST", body: fd });
}

export function verifyInventory(options: {
  use_httpx?: boolean;
  use_spider?: boolean;
  use_ajax_spider?: boolean;
}): Promise<VerifyResponse> {
  const sp = new URLSearchParams();
  sp.set("use_httpx", String(options.use_httpx ?? true));
  sp.set("use_spider", String(options.use_spider ?? false));
  sp.set("use_ajax_spider", String(options.use_ajax_spider ?? false));
  return request(`/inventory/verify?${sp.toString()}`, { method: "POST" });
}

export function fetchDiscoverProgress(): Promise<DiscoverProgressResponse> {
  return request("/inventory/discover/progress");
}

export function fetchDiagnosisProgress(): Promise<DiagnosisProgressResponse> {
  return request("/diagnosis/progress");
}

export function fetchVerifyReport(params: {
  outcome?: "final" | "discovered" | "rejected";
  q?: string;
  limit?: number;
}): Promise<VerifyReportResponse> {
  const sp = new URLSearchParams();
  if (params.outcome) sp.set("outcome", params.outcome);
  if (params.q) sp.set("q", params.q);
  if (params.limit != null) sp.set("limit", String(params.limit));
  const qs = sp.toString();
  return request(`/inventory/verify-report${qs ? `?${qs}` : ""}`);
}

export function fetchEndpoints(params: {
  q?: string;
  source?: string;
  inventory?: "ready" | "verified";
  limit?: number;
  offset?: number;
}): Promise<EndpointListResponse> {
  const sp = new URLSearchParams();
  if (params.q) sp.set("q", params.q);
  if (params.source) sp.set("source", params.source);
  if (params.inventory) sp.set("inventory", params.inventory);
  if (params.limit != null) sp.set("limit", String(params.limit));
  if (params.offset != null) sp.set("offset", String(params.offset));
  const qs = sp.toString();
  return request(`/inventory/endpoints${qs ? `?${qs}` : ""}`);
}

export function fetchEndpointDetail(
  endpointId: string,
  inventory?: "ready" | "verified",
): Promise<EndpointDetail> {
  const sp = new URLSearchParams({ endpoint_id: endpointId });
  if (inventory) sp.set("inventory", inventory);
  return request(`/inventory/endpoints/detail?${sp.toString()}`);
}

export function fetchLoginEntryReport(): Promise<LoginEntryReportResponse> {
  return request("/inventory/login-entry-report");
}

export function fetchTestAccounts(): Promise<TestAccountsResponse> {
  return request("/test-accounts");
}

export function saveTestAccounts(accounts: TestAccountEntry[]): Promise<SaveTestAccountsResponse> {
  return request("/test-accounts", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ accounts }),
  });
}

export function fetchBaseUrls(): Promise<BaseUrlsResponse> {
  return request("/base-urls");
}

export function saveBaseUrls(urls: BaseUrlEntry[]): Promise<SaveBaseUrlsResponse> {
  return request("/base-urls", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ urls }),
  });
}

export function fetchLoginEndpoints(): Promise<LoginEndpointsResponse> {
  return request("/login-endpoints");
}

export function saveLoginEndpoints(
  endpoints: LoginEndpointEntry[],
): Promise<SaveLoginEndpointsResponse> {
  return request("/login-endpoints", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ endpoints }),
  });
}

export function fetchDiagnosisCatalog(): Promise<DiagnosisCatalogResponse> {
  return request("/diagnosis/catalog");
}

export function fetchDiagnosisReport(sectionId: string): Promise<DiagnosisSectionReport> {
  return request(`/diagnosis/modules/${encodeURIComponent(sectionId)}/report`);
}

export function runDiagnosisSection(
  sectionId: string,
  body?: DiagnosisRunSectionRequest,
): Promise<DiagnosisRunSectionResponse> {
  return request(`/diagnosis/modules/${encodeURIComponent(sectionId)}/run`, {
    method: "POST",
    headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
}
