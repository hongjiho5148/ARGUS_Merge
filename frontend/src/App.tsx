import { useCallback, useEffect, useState } from "react";
import {
  ChevronDown,
  Crosshair,
  Database,
  RefreshCw,
  ShieldCheck,
  Stethoscope,
} from "lucide-react";
import argusLogo from "./assets/argus_logo.png";
import { BuildSourcePanel } from "./components/BuildSourcePanel";
import {
  BaseUrlsPanel,
  buildSavedBaseUrlsSnapshot,
  createEmptyBaseUrl,
} from "./components/BaseUrlsPanel";
import type { SavedBaseUrlsSnapshot } from "./components/BaseUrlsPanel";
import {
  TestAccountsPanel,
  buildSavedSnapshot,
  createEmptyAccount,
} from "./components/TestAccountsPanel";
import type { SavedAccountsSnapshot } from "./components/TestAccountsPanel";
import {
  LoginEndpointsPanel,
  buildSavedLoginEndpointsSnapshot,
  createEmptyLoginEndpoint,
} from "./components/LoginEndpointsPanel";
import type { SavedLoginEndpointsSnapshot } from "./components/LoginEndpointsPanel";
import { LoginEntriesPanel } from "./components/LoginEntriesPanel";
import { VerifyResultsPanel } from "./components/VerifyResultsPanel";
import { VerifyStartDialog } from "./components/VerifyStartDialog";
import { DiagnosisPage } from "./components/DiagnosisPage";
import { OutcomeTag } from "./components/OutcomeTag";
import { EndpointTable } from "./components/EndpointTable";
import { Panel, StatCard } from "./components/ui";
import {
  buildInventory,
  fetchBaseUrls,
  fetchDiscoverProgress,
  fetchEndpoints,
  fetchHealth,
  fetchSourceOptions,
  fetchStats,
  fetchTestAccounts,
  fetchLoginEndpoints,
  fetchLoginEntryReport,
  fetchVerifyReport,
  saveBaseUrls,
  saveLoginEndpoints,
  saveTestAccounts,
  verifyInventory,
} from "./lib/api";
import { DEFAULT_VERIFY_OPTIONS, type VerifyOptions } from "./lib/verifyOptions";
import type {
  BaseUrlEntry,
  EndpointSummary,
  InventoryStats,
  SourceFiles,
  SourceId,
  TestAccountEntry,
  VerifyReportSummary,
  VerifyResultSummary,
  InventoryView,
  VerifyOutcome,
  LoginEndpointEntry,
  LoginEndpointResolved,
  LoginEntryReportResponse,
} from "./types";

const EMPTY_STATS: InventoryStats = {
  total_endpoints: 0,
  frontend_endpoints: 0,
  api_endpoints: 0,
  write_endpoints: 0,
  with_body: 0,
  with_query: 0,
  schema_coverage_pct: 0,
  schema_enriched: 0,
  targets: {},
  sources_used: [],
  sources_missing: [],
};

const EMPTY_FILES: SourceFiles = {
  url_list: null,
  api_list: null,
  openapi: [],
  gradle_deps: [],
};

const EMPTY_LOGIN_ENTRY_REPORT: LoginEntryReportResponse = {
  available: false,
  checked_at: null,
  session_count: 0,
  login_entries: [],
  accounts: [],
  entry_specific_accounts: [],
};

const EMPTY_VERIFY_SUMMARY: VerifyReportSummary = {
  total_checked: 0,
  confirmed: 0,
  params_issues: 0,
  rejected: 0,
  verified_count: 0,
  final_count: 0,
  discovered_count: 0,
};

const SOURCE_DISPLAY: Record<string, string> = {
  url_list: "URL List",
  api_list: "API List",
  openapi: "Swagger",
  zap_discover: "ZAP Discover",
  zap_traffic: "ZAP Traffic",
  traffic: "Traffic",
  probe: "Probe",
  zap_probe: "ZAP Probe",
};

function targetLines(targets: Record<string, number>): string[] {
  return Object.entries(targets)
    .sort(([a], [b]) => a.localeCompare(b, undefined, { numeric: true }))
    .map(([port, count]) => `${port}: ${count}`);
}

type AppPage = "attack-surface" | "diagnosis";

function App() {
  const [page, setPage] = useState<AppPage>("attack-surface");
  const [stats, setStats] = useState<InventoryStats>(EMPTY_STATS);
  const [endpoints, setEndpoints] = useState<EndpointSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [filter, setFilter] = useState("");
  const [sourceFilter, setSourceFilter] = useState("");
  const [loading, setLoading] = useState(false);
  const [building, setBuilding] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [discoverProgress, setDiscoverProgress] = useState<string>("");
  const [panelOpen, setPanelOpen] = useState(false);
  const [sourceOptions, setSourceOptions] = useState<Awaited<ReturnType<typeof fetchSourceOptions>>["sources"]>([]);
  const [sourceFiles, setSourceFiles] = useState<SourceFiles>(EMPTY_FILES);
  const [baseUrls, setBaseUrls] = useState<BaseUrlEntry[]>([]);
  const [savedBaseUrlsSnapshot, setSavedBaseUrlsSnapshot] = useState<SavedBaseUrlsSnapshot>({});
  const [savingBaseUrls, setSavingBaseUrls] = useState(false);
  const [baseUrlSaveError, setBaseUrlSaveError] = useState("");
  const [testAccounts, setTestAccounts] = useState<TestAccountEntry[]>([]);
  const [savedAccountsSnapshot, setSavedAccountsSnapshot] = useState<SavedAccountsSnapshot>({});
  const [savingAccounts, setSavingAccounts] = useState(false);
  const [accountSaveError, setAccountSaveError] = useState("");
  const [loginEndpoints, setLoginEndpoints] = useState<LoginEndpointEntry[]>([]);
  const [resolvedLoginEndpoints, setResolvedLoginEndpoints] = useState<LoginEndpointResolved[]>(
    [],
  );
  const [savedLoginEndpointsSnapshot, setSavedLoginEndpointsSnapshot] =
    useState<SavedLoginEndpointsSnapshot>({});
  const [savingLoginEndpoints, setSavingLoginEndpoints] = useState(false);
  const [loginEndpointSaveError, setLoginEndpointSaveError] = useState("");
  const [online, setOnline] = useState<boolean | null>(null);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [verifyAvailable, setVerifyAvailable] = useState(false);
  const [verifyCheckedAt, setVerifyCheckedAt] = useState<string | null>(null);
  const [verifySummary, setVerifySummary] = useState<VerifyReportSummary>(EMPTY_VERIFY_SUMMARY);
  const [inventoryView, setInventoryView] = useState<InventoryView>("ready");
  const [readyTotal, setReadyTotal] = useState(0);
  const [verifiedTotal, setVerifiedTotal] = useState(0);
  const [verifyOutcome, setVerifyOutcome] = useState<VerifyOutcome>("final");
  const [verifyFilter, setVerifyFilter] = useState("");
  const [verifyResults, setVerifyResults] = useState<VerifyResultSummary[]>([]);
  const [verifyTotal, setVerifyTotal] = useState(0);
  const [verifyOptions, setVerifyOptions] = useState<VerifyOptions>(DEFAULT_VERIFY_OPTIONS);
  const [verifyDialogOpen, setVerifyDialogOpen] = useState(false);
  const [loginEntryReport, setLoginEntryReport] = useState<LoginEntryReportResponse>(
    EMPTY_LOGIN_ENTRY_REPORT,
  );

  const loadLoginEntryReport = useCallback(async () => {
    try {
      setLoginEntryReport(await fetchLoginEntryReport());
    } catch {
      setLoginEntryReport(EMPTY_LOGIN_ENTRY_REPORT);
    }
  }, []);

  const loadVerifyReport = useCallback(async (outcome: VerifyOutcome, q?: string) => {
    try {
      const report = await fetchVerifyReport({
        outcome,
        q: q || undefined,
        limit: 500,
      });
      setVerifyAvailable(report.available);
      setVerifyCheckedAt(report.checked_at);
      setVerifySummary(report.summary);
      setVerifyResults(report.items);
      setVerifyTotal(report.total);
    } catch {
      setVerifyAvailable(false);
      setVerifyResults([]);
      setVerifyTotal(0);
    }
  }, []);

  const loadInventory = useCallback(
    async (view: InventoryView, pathFilter?: string, srcFilter?: string) => {
      const ep = await fetchEndpoints({
        q: pathFilter || undefined,
        source: srcFilter || undefined,
        inventory: view,
        limit: 500,
      });
      setEndpoints(ep.items);
      setTotal(ep.total);
      const s = await fetchStats(view);
      setStats(s);
      if (view === "ready") setReadyTotal(s.total_endpoints);
      else setVerifiedTotal(s.total_endpoints);
    },
    [],
  );

  const refreshCounts = useCallback(async () => {
    const [readyStats, verifiedStats] = await Promise.all([
      fetchStats("ready"),
      fetchStats("verified"),
    ]);
    setReadyTotal(readyStats.total_endpoints);
    setVerifiedTotal(verifiedStats.total_endpoints);
  }, []);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      await fetchHealth();
      setOnline(true);
      await refreshCounts();
      await loadInventory(inventoryView, filter, sourceFilter);
      await loadVerifyReport(verifyOutcome, verifyFilter);
      await loadLoginEntryReport();
    } catch (e) {
      setOnline(false);
      setError(e instanceof Error ? e.message : "API 연결 실패");
    } finally {
      setLoading(false);
    }
  }, [
    filter,
    sourceFilter,
    inventoryView,
    verifyOutcome,
    verifyFilter,
    loadInventory,
    loadVerifyReport,
    loadLoginEntryReport,
    refreshCounts,
  ]);

  useEffect(() => {
    if (online) void loadLoginEntryReport();
  }, [online, loadLoginEntryReport]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    if (online !== true) return;
    void loadInventory(inventoryView, filter, sourceFilter);
  }, [online, inventoryView, filter, sourceFilter, loadInventory]);

  useEffect(() => {
    if (online !== true) return;
    void loadVerifyReport(verifyOutcome, verifyFilter);
  }, [online, verifyOutcome, verifyFilter, loadVerifyReport]);

  useEffect(() => {
    fetchSourceOptions()
      .then((res) => setSourceOptions(res.sources))
      .catch(() => {});
    fetchTestAccounts()
      .then((res) => {
        setTestAccounts(res.accounts);
        setSavedAccountsSnapshot(buildSavedSnapshot(res.accounts));
      })
      .catch(() => {});
    fetchLoginEndpoints()
      .then((res) => {
        setLoginEndpoints(res.endpoints);
        setResolvedLoginEndpoints(res.resolved);
        setSavedLoginEndpointsSnapshot(buildSavedLoginEndpointsSnapshot(res.endpoints));
      })
      .catch(() => {});
    fetchBaseUrls()
      .then((res) => {
        setBaseUrls(res.urls);
        setSavedBaseUrlsSnapshot(buildSavedBaseUrlsSnapshot(res.urls));
      })
      .catch(() => {});
  }, []);

  const handleFileSelect = (id: SourceId | "gradle_deps", file: File | File[] | null) => {
    setSourceFiles((prev) => {
      if (id === "openapi") {
        return { ...prev, openapi: Array.isArray(file) ? file : file ? [file] : [] };
      }
      if (id === "gradle_deps") {
        return { ...prev, gradle_deps: Array.isArray(file) ? file : file ? [file] : [] };
      }
      return { ...prev, [id]: Array.isArray(file) ? (file[0] ?? null) : file };
    });
  };

  const handleAddBaseUrl = () => {
    setBaseUrlSaveError("");
    setBaseUrls((prev) => [...prev, createEmptyBaseUrl()]);
  };

  const handleBaseUrlChange = (id: string, value: string) => {
    setBaseUrlSaveError("");
    setBaseUrls((prev) => prev.map((u) => (u.id === id ? { ...u, url: value } : u)));
  };

  const handleRemoveBaseUrl = (id: string) => {
    setBaseUrlSaveError("");
    setBaseUrls((prev) => prev.filter((u) => u.id !== id));
  };

  const handleSaveBaseUrls = async () => {
    setSavingBaseUrls(true);
    setBaseUrlSaveError("");
    try {
      const res = await saveBaseUrls(baseUrls);
      setBaseUrls(res.urls);
      setSavedBaseUrlsSnapshot(buildSavedBaseUrlsSnapshot(res.urls));
    } catch (e) {
      setBaseUrlSaveError(e instanceof Error ? e.message : "Base URL 저장에 실패했습니다.");
    } finally {
      setSavingBaseUrls(false);
    }
  };

  const handleAddAccount = () => {
    setAccountSaveError("");
    setTestAccounts((prev) => [...prev, createEmptyAccount()]);
  };

  const handleAccountChange = (
    id: string,
    field: keyof Omit<TestAccountEntry, "id">,
    value: string,
  ) => {
    setAccountSaveError("");
    setTestAccounts((prev) =>
      prev.map((a) => (a.id === id ? { ...a, [field]: value } : a)),
    );
  };

  const handleRemoveAccount = (id: string) => {
    setAccountSaveError("");
    setTestAccounts((prev) => prev.filter((a) => a.id !== id));
  };

  const handleAddLoginEndpoint = () => {
    setLoginEndpointSaveError("");
    setLoginEndpoints((prev) => [...prev, createEmptyLoginEndpoint()]);
  };

  const handleLoginEndpointChange = (id: string, field: "url" | "kind", value: string) => {
    setLoginEndpointSaveError("");
    setLoginEndpoints((prev) =>
      prev.map((e) => (e.id === id ? { ...e, [field]: value } : e)),
    );
  };

  const handleRemoveLoginEndpoint = (id: string) => {
    setLoginEndpointSaveError("");
    setLoginEndpoints((prev) => prev.filter((e) => e.id !== id));
  };

  const handleSaveLoginEndpoints = async () => {
    setSavingLoginEndpoints(true);
    setLoginEndpointSaveError("");
    try {
      const res = await saveLoginEndpoints(loginEndpoints);
      setLoginEndpoints(res.endpoints);
      setResolvedLoginEndpoints(res.resolved);
      setSavedLoginEndpointsSnapshot(buildSavedLoginEndpointsSnapshot(res.endpoints));
    } catch (e) {
      setLoginEndpointSaveError(
        e instanceof Error ? e.message : "Login Endpoints 저장에 실패했습니다.",
      );
    } finally {
      setSavingLoginEndpoints(false);
    }
  };

  const handleSaveAccounts = async () => {
    setSavingAccounts(true);
    setAccountSaveError("");
    try {
      const res = await saveTestAccounts(testAccounts);
      setTestAccounts(res.accounts);
      setSavedAccountsSnapshot(buildSavedSnapshot(res.accounts));
    } catch (e) {
      setAccountSaveError(e instanceof Error ? e.message : "계정 저장에 실패했습니다.");
    } finally {
      setSavingAccounts(false);
    }
  };

  const handleVerify = async (opts: VerifyOptions) => {
    if (!opts.useHttpx && !opts.useSpider && !opts.useAjaxSpider) {
      setError("Select at least one verify option.");
      return;
    }
    setVerifyOptions(opts);
    setVerifyDialogOpen(false);
    setVerifying(true);
    setDiscoverProgress("Starting…");
    setMessage("");
    setError("");
    const poll = window.setInterval(() => {
      void fetchDiscoverProgress()
        .then((p) => {
          if (p.message) {
            setDiscoverProgress(
              p.running && p.total_steps > 0
                ? `[${p.step}/${p.total_steps}] ${p.message}`
                : p.message,
            );
          }
        })
        .catch(() => {});
    }, 1500);
    try {
      const res = await verifyInventory({
        use_httpx: opts.useHttpx,
        use_spider: opts.useSpider,
        use_ajax_spider: opts.useAjaxSpider,
      });
      setStats(res.stats);
      if (!res.ok) {
        setError(res.message);
      } else {
        setMessage(res.message);
        setInventoryView("verified");
      }
      await refreshCounts();
      await loadInventory("verified", filter, sourceFilter);
      await loadVerifyReport(verifyOutcome, verifyFilter);
      await loadLoginEntryReport();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Verify failed");
    } finally {
      window.clearInterval(poll);
      setVerifying(false);
      setDiscoverProgress("");
    }
  };

  const handleBuild = async () => {
    setBuilding(true);
    setMessage("");
    setError("");
    try {
      const res = await buildInventory({
        selection: {
          url_list_enabled: sourceFiles.url_list != null,
          api_list_enabled: sourceFiles.api_list != null,
          openapi_enabled: sourceFiles.openapi.length > 0,
          gradle_deps_enabled: sourceFiles.gradle_deps.length > 0,
        },
        files: sourceFiles,
      });
      if (!res.ok) {
        setError(res.message);
        return;
      }
      setStats(res.stats);
      setMessage(res.message);
      setPanelOpen(false);
      setInventoryView("ready");
      await refreshCounts();
      await loadInventory("ready", filter || undefined, sourceFilter || undefined);
    } catch (e) {
      setError(e instanceof Error ? e.message : "빌드 실패");
    } finally {
      setBuilding(false);
    }
  };

  return (
    <div className="flex min-h-full">
      <aside className="flex w-56 shrink-0 flex-col border-r border-cyber-border bg-cyber-panel/40">
        <div className="border-b border-cyber-border px-2 py-3">
          <img src={argusLogo} alt="ARGUS" className="block w-full object-contain object-center" />
        </div>
        <nav className="flex flex-1 flex-col gap-1 p-3 text-sm">
          <NavItem
            icon={Crosshair}
            label="Attack Surface"
            active={page === "attack-surface"}
            onClick={() => setPage("attack-surface")}
          />
          <NavItem
            icon={Stethoscope}
            label="Diagnosis"
            active={page === "diagnosis"}
            onClick={() => setPage("diagnosis")}
          />
        </nav>
        <div className="border-t border-cyber-border p-4 text-xs text-cyber-muted">
          <div className="flex items-center gap-2">
            <span
              className={`h-2 w-2 rounded-full ${
                online === null ? "bg-cyber-muted" : online ? "bg-cyber-accent" : "bg-cyber-danger"
              }`}
            />
            {online === null ? "연결 확인 중…" : online ? "Backend online" : "Backend offline"}
          </div>
        </div>
      </aside>

      <main className="flex flex-1 flex-col overflow-hidden">
        {page === "diagnosis" ? (
          <DiagnosisPage />
        ) : (
          <>
        <header className="flex items-center justify-between border-b border-cyber-border bg-cyber-panel/30 px-8 py-4">
          <div>
            <h2 className="font-display text-xl font-semibold text-white">Attack Surface Map</h2>
          </div>
          <div className="flex gap-2">
            <button
              type="button"
              onClick={() => void refresh()}
              disabled={loading}
              className="flex items-center gap-2 rounded-lg border border-cyber-border px-4 py-2 text-xs text-cyber-muted transition hover:border-cyber-accent/40 hover:text-cyber-accent disabled:opacity-50"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
              Refresh
            </button>
            <button
              type="button"
              onClick={() => setPanelOpen((v) => !v)}
              className={`flex items-center gap-2 rounded-lg border px-4 py-2 text-xs font-semibold transition ${
                panelOpen
                  ? "border-cyber-accent bg-cyber-accent/20 text-cyber-accent"
                  : "border-cyber-accent/50 bg-cyber-accent/10 text-cyber-accent hover:bg-cyber-accent/20"
              }`}
            >
              <Database className="h-3.5 w-3.5" />
              Build Attack Tree
            </button>
          </div>
        </header>

        <div className="flex-1 overflow-y-auto p-8">
          {(message || error) && (
            <div
              className={`mb-6 rounded-lg border px-4 py-3 text-xs ${
                error
                  ? "border-cyber-danger/40 bg-cyber-danger/10 text-cyber-danger"
                  : "border-cyber-accent/30 bg-cyber-accent/5 text-cyber-accent"
              }`}
            >
              {error || message}
            </div>
          )}

          <BuildSourcePanel
            open={panelOpen}
            sources={sourceOptions}
            files={sourceFiles}
            building={building}
            onFileSelect={handleFileSelect}
            onBuild={() => void handleBuild()}
            onClose={() => setPanelOpen(false)}
          />

          <BaseUrlsPanel
            open={panelOpen}
            urls={baseUrls}
            savedSnapshot={savedBaseUrlsSnapshot}
            saving={savingBaseUrls}
            saveError={baseUrlSaveError}
            onAdd={handleAddBaseUrl}
            onChange={handleBaseUrlChange}
            onRemove={handleRemoveBaseUrl}
            onSave={() => void handleSaveBaseUrls()}
          />

          <TestAccountsPanel
            open={panelOpen}
            accounts={testAccounts}
            savedSnapshot={savedAccountsSnapshot}
            saving={savingAccounts}
            saveError={accountSaveError}
            onAdd={handleAddAccount}
            onChange={handleAccountChange}
            onRemove={handleRemoveAccount}
            onSave={() => void handleSaveAccounts()}
          />

          <LoginEndpointsPanel
            open={panelOpen}
            endpoints={loginEndpoints}
            resolved={resolvedLoginEndpoints}
            savedSnapshot={savedLoginEndpointsSnapshot}
            saving={savingLoginEndpoints}
            saveError={loginEndpointSaveError}
            onAdd={handleAddLoginEndpoint}
            onChange={handleLoginEndpointChange}
            onRemove={handleRemoveLoginEndpoint}
            onSave={() => void handleSaveLoginEndpoints()}
          />

          <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
            <StatCard label="Total" value={stats.total_endpoints} accent="text-cyber-accent" />
            <StatCard label="Web URLs" value={stats.frontend_endpoints} accent="text-sky-400" />
            <StatCard label="API Endpoints" value={stats.api_endpoints} />
            <StatCard label="Write Surface" value={stats.write_endpoints} accent="text-rose-400" />
            <StatCard label="Body Known" value={stats.with_body} accent="text-violet-400" />
            <StatCard label="Query Known" value={stats.with_query} accent="text-amber-400" />
            <StatCard
              label="Schema Coverage"
              value={`${stats.schema_coverage_pct}%`}
              accent="text-cyber-accent"
            />
            <StatCard label="Targets" lines={targetLines(stats.targets)} accent="text-sky-400" />
          </div>

          <Panel
            title={`ENDPOINTS (${total})`}
            action={
              <div className="flex flex-wrap items-center justify-center gap-2">
                <OutcomeTag
                  active={inventoryView === "ready"}
                  label="Ready"
                  count={readyTotal}
                  onClick={() => setInventoryView("ready")}
                  tone="ready"
                />
                <OutcomeTag
                  active={inventoryView === "verified"}
                  label="Verified"
                  count={verifiedTotal}
                  onClick={() => setInventoryView("verified")}
                  tone="verified"
                />
                <div className="relative">
                  <select
                    value={sourceFilter}
                    onChange={(e) => setSourceFilter(e.target.value)}
                    className="min-w-[8.75rem] appearance-none rounded border border-cyber-border bg-cyber-bg py-1.5 pl-3 pr-8 text-left text-xs text-white focus:border-cyber-accent/50 focus:outline-none"
                  >
                    <option value="">All sources</option>
                    <option value="url_list">URL List</option>
                    <option value="api_list">API List</option>
                    <option value="openapi">Swagger</option>
                    <option value="zap_discover">ZAP Discover</option>
                  </select>
                  <ChevronDown
                    className="pointer-events-none absolute right-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-cyber-muted"
                    strokeWidth={2}
                  />
                </div>
                <input
                  type="search"
                  placeholder="Filter path…"
                  value={filter}
                  onChange={(e) => setFilter(e.target.value)}
                  className="rounded border border-cyber-border bg-cyber-bg px-3 py-1.5 text-xs text-white placeholder:text-cyber-muted focus:border-cyber-accent/50 focus:outline-none"
                />
              </div>
            }
            trailing={
              <button
                type="button"
                onClick={() => setVerifyDialogOpen(true)}
                disabled={verifying || readyTotal === 0 || online === false}
                className="flex items-center gap-1.5 rounded-lg border border-violet-400/50 bg-violet-500/15 px-4 py-1.5 text-xs font-semibold text-violet-300 transition hover:bg-violet-500/25 disabled:opacity-40"
              >
                <ShieldCheck className={`h-3.5 w-3.5 ${verifying ? "animate-pulse" : ""}`} />
                {verifying ? "Discovering…" : "Verify"}
              </button>
            }
          >
            {discoverProgress ? (
              <p className="mb-3 text-xs text-violet-300">{discoverProgress}</p>
            ) : null}
            <div className="max-h-[min(28rem,calc(100vh-18rem))] overflow-x-auto overflow-y-auto rounded-lg border border-cyber-border/40">
              <EndpointTable
                endpoints={endpoints}
                emptyMessage={
                  online === false
                    ? "백엔드를 먼저 실행하세요"
                    : inventoryView === "verified"
                      ? "Verify 실행 후 Verified 탭에서 완성본을 확인하세요"
                      : '파일 선택 후 "Merge & Build" 실행'
                }
                sourceDisplay={SOURCE_DISPLAY}
                inventory={inventoryView}
              />
            </div>
          </Panel>

          <div className="mt-6">
            <VerifyResultsPanel
            available={verifyAvailable}
            checkedAt={verifyCheckedAt}
            summary={verifySummary}
            outcome={verifyOutcome}
            onOutcomeChange={setVerifyOutcome}
            filter={verifyFilter}
            onFilterChange={setVerifyFilter}
            items={verifyResults}
            total={verifyTotal}
            />
          </div>

          <div className="mt-6">
            <LoginEntriesPanel report={loginEntryReport} />
          </div>
        </div>
          </>
        )}
      </main>

      <VerifyStartDialog
        open={verifyDialogOpen && !verifying}
        initialOptions={verifyOptions}
        onClose={() => setVerifyDialogOpen(false)}
        onStart={(opts) => void handleVerify(opts)}
      />
    </div>
  );
}

function NavItem({
  icon: Icon,
  label,
  active,
  disabled,
  onClick,
}: {
  icon: React.ComponentType<{ className?: string; strokeWidth?: number }>;
  label: string;
  active?: boolean;
  disabled?: boolean;
  onClick?: () => void;
}) {
  return (
    <button
      type="button"
      disabled={disabled}
      onClick={onClick}
      className={`flex items-center gap-2 rounded-lg px-3 py-2 text-left transition ${
        disabled
          ? "cursor-not-allowed text-cyber-muted/40"
          : active
            ? "bg-cyber-accent/10 text-cyber-accent"
            : "text-cyber-muted hover:bg-cyber-border/30 hover:text-white"
      }`}
    >
      <Icon className="h-4 w-4" strokeWidth={1.5} />
      {label}
    </button>
  );
}

export default App;
