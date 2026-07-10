import { useState } from "react";
import { ChevronDown } from "lucide-react";
import type { DiagnosisSectionReport } from "../../types";

const STATUS_STYLES: Record<string, string> = {
  pass: "border-emerald-400/50 bg-emerald-500/10 text-emerald-300",
  warn: "border-amber-400/50 bg-amber-500/10 text-amber-300",
  warning: "border-amber-400/50 bg-amber-500/10 text-amber-300",
  fail: "border-rose-400/50 bg-rose-500/10 text-rose-300",
  error: "border-rose-400/50 bg-rose-500/10 text-rose-300",
  skipped: "border-amber-400/40 bg-amber-500/5 text-amber-200/80",
  not_implemented: "border-cyber-border/60 bg-cyber-bg/40 text-cyber-muted",
  not_diagnosable: "border-amber-400/50 bg-amber-500/10 text-amber-300",
  pending: "border-cyber-border/60 bg-cyber-bg/40 text-cyber-muted",
  no_targets: "border-amber-400/40 bg-amber-500/5 text-amber-200/80",
};

const SEVERITY_STYLES: Record<string, string> = {
  high: "text-rose-300",
  medium: "text-amber-300",
  low: "text-sky-300",
  info: "text-cyber-muted",
};

export function StatusBadge({ status }: { status: string }) {
  const cls = STATUS_STYLES[status] ?? STATUS_STYLES.pending;
  return (
    <span className={`rounded border px-1.5 py-0.5 font-mono text-[9px] uppercase ${cls}`}>
      {status}
    </span>
  );
}
function FindingEvidence({ evidence }: { evidence: Record<string, unknown> }) {
  const rows: { label: string; value: string }[] = [];
  const add = (label: string, key: string) => {
    const v = evidence[key];
    if (v !== undefined && v !== null && v !== "") {
      rows.push({ label, value: String(v) });
    }
  };

  add("Login URL", "login_url");
  add("Login label", "login_label");
  add("Probe mode", "probe_mode");
  add("Reason", "reason");
  add("Remediation", "remediation");

  const scenarioA = evidence.scenario_a as Record<string, unknown> | undefined;
  if (scenarioA) {
    const msg = scenarioA.primary_message ?? scenarioA.body_preview ?? "";
    rows.push({
      label: "A · exists + wrong PW",
      value: `${scenarioA.http_status ?? "—"} · ${scenarioA.email ?? ""} · ${String(msg).slice(0, 160)}`,
    });
  }
  const scenarioB = evidence.scenario_b as Record<string, unknown> | undefined;
  if (scenarioB) {
    const msg = scenarioB.primary_message ?? scenarioB.body_preview ?? "";
    rows.push({
      label: "B · missing + wrong PW",
      value: `${scenarioB.http_status ?? "—"} · ${scenarioB.email ?? ""} · ${String(msg).slice(0, 160)}`,
    });
  }
  const scenarioC = evidence.scenario_c as Record<string, unknown> | undefined;
  if (scenarioC) {
    const msg = scenarioC.primary_message ?? scenarioC.body_preview ?? "";
    rows.push({
      label: "C · missing + valid PW",
      value: `${scenarioC.http_status ?? "—"} · ${scenarioC.email ?? ""} · ${String(msg).slice(0, 160)}`,
    });
  }
  const diffs = evidence.differences;
  if (Array.isArray(diffs) && diffs.length > 0) {
    rows.push({ label: "Differences", value: diffs.map(String).join(" · ") });
  }

  add("Classification", "classification");
  add("Trigger", "trigger_label");
  add("Trigger code", "trigger");
  add("Rule", "rule_id");
  add("Category", "category");
  add("Direction", "direction");
  add("Field", "field_path");
  add("Sample", "sample");
  add("Param", "param");
  add("Param in", "param_in");
  add("Payload", "payload");
  add("Payloads tried", "payloads_tried_count");
  add("HTTP", "http_status");
  add("Baseline HTTP", "baseline_http_status");
  add("Baseline SHA256", "baseline_sha256");
  add("Response SHA256", "response_sha256");
  add("Same body as baseline", "bodies_identical");
  add("Payload leak confirmed", "payload_leak_confirmed");
  add("PDF text overlap", "pdf_text_overlap");
  add("Extracted text preview", "extracted_text_preview");
  add("Content-Type", "content_type");
  add("Content-Disposition", "content_disposition");
  add("Baseline attachment", "baseline_attachment");
  add("Listing type", "listing_type");
  add("Matched patterns", "matched_patterns");
  add("File links", "file_link_count");
  add("Body preview", "body_preview");
  add("Anonymous HTTP", "anonymous_http_status");
  add("Authenticated HTTP", "authenticated_http_status");
  add("Account", "account_email");
  add("Auth comparison", "auth_comparison");
  add("URL", "url");
  add("Base URL", "base_url");
  add("Header", "header");
  add("Header value", "header_value");
  add("Affected count", "affected_count");
  add("ZAP plugin", "plugin_id");

  const patterns = evidence.matched_patterns;
  if (Array.isArray(patterns) && patterns.length > 0) {
    rows.push({ label: "Patterns", value: patterns.map(String).join(", ") });
  }
  const affected = evidence.affected_urls;
  if (Array.isArray(affected) && affected.length > 1) {
    const preview = affected
      .slice(0, 8)
      .map(String)
      .join(", ");
    rows.push({
      label: "Affected URLs",
      value: affected.length > 8 ? `${preview}, … (+${affected.length - 8})` : preview,
    });
  }
  const affectedExts = evidence.affected_extensions;
  if (Array.isArray(affectedExts) && affectedExts.length > 1) {
    rows.push({
      label: "Affected extensions",
      value: affectedExts.map((e) => `.${e}`).join(", "),
    });
  }

  const tried = evidence.payloads_tried;
  if (Array.isArray(tried) && tried.length > 0) {
    const summary = tried
      .slice(0, 12)
      .map((t) => {
        const row = t as Record<string, unknown>;
        const cat = row.category ?? "?";
        const p = row.payload ?? "";
        return `${p} → ${cat}`;
      })
      .join("; ");
    rows.push({
      label: "Payload results",
      value: tried.length > 12 ? `${summary}; … (+${tried.length - 12})` : summary,
    });
  }

  if (rows.length === 0) return null;

  const leak = evidence.payload_leak_markers;
  if (Array.isArray(leak) && leak.length > 0) {
    rows.push({ label: "Payload leak markers", value: leak.map(String).join("; ") });
  }
  const sensitive = evidence.sensitive_markers;
  if (Array.isArray(sensitive) && sensitive.length > 0) {
    rows.push({ label: "Sensitive markers", value: sensitive.map(String).join("; ") });
  }

  return (
    <dl className="mt-2 space-y-1 border-t border-cyber-border/20 pt-2 text-[10px]">
      {rows.map(({ label, value }) => (
        <div key={label} className="grid grid-cols-[7rem_1fr] gap-2">
          <dt className="text-cyber-muted">{label}</dt>
          <dd className="break-all font-mono text-cyan-300/80">{value}</dd>
        </div>
      ))}
    </dl>
  );
}

function FindingListItem({
  f,
}: {
  f: { severity: string; message: string; evidence?: Record<string, unknown> };
}) {
  return (
    <li className="rounded border border-cyber-border/30 bg-cyber-panel/30 px-3 py-2">
      <div className="flex items-start gap-2">
        <span
          className={`shrink-0 font-mono text-[10px] uppercase ${SEVERITY_STYLES[f.severity] ?? SEVERITY_STYLES.info}`}
        >
          {f.severity}
        </span>
        <span className="text-xs text-white/90">{f.message}</span>
      </div>
      {f.evidence && Object.keys(f.evidence).length > 0 ? (
        <FindingEvidence evidence={f.evidence} />
      ) : null}
    </li>
  );
}

function findingBucket(f: {
  severity: string;
  evidence?: Record<string, unknown>;
}): "httpx" | "zap" | "info" | "inventory" | "other" {
  if (f.severity === "info") return "info";
  const ev = f.evidence;
  if (ev?.rule_id === "2-2-design") return "info";
  const engine = String(ev?.engine ?? ev?.source ?? "");
  if (engine === "inventory") return "inventory";
  if (engine === "httpx") return "httpx";
  if (engine === "zap") return "zap";
  return "other";
}

function CollapsibleFindingsSection({
  title,
  subtitle,
  count,
  defaultOpen,
  findings,
}: {
  title: string;
  subtitle?: string;
  count: number;
  defaultOpen: boolean;
  findings: { severity: string; message: string; evidence?: Record<string, unknown> }[];
}) {
  const [open, setOpen] = useState(defaultOpen);
  if (count === 0) return null;

  return (
    <div className="mb-3 overflow-hidden rounded-lg border border-cyber-border/50 bg-cyber-bg/20">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center gap-2 px-3 py-2 text-left transition hover:bg-cyber-accent/5"
      >
        <ChevronDown className={`h-4 w-4 shrink-0 text-cyber-muted transition ${open ? "rotate-180" : ""}`} />
        <span className="text-xs font-semibold text-white">{title}</span>
        <span className="font-mono text-[10px] text-cyan-300/90">{count}</span>
        {subtitle ? <span className="ml-1 text-[10px] text-cyber-muted">{subtitle}</span> : null}
      </button>
      {open ? (
        <ul className="space-y-2 border-t border-cyber-border/30 px-3 py-2">
          {findings.map((f, i) => (
            <FindingListItem key={`${title}-${f.severity}-${i}`} f={f} />
          ))}
        </ul>
      ) : null}
    </div>
  );
}

function GroupedFindingsPanel({
  findings,
  sectionId,
}: {
  findings: { severity: string; message: string; evidence?: Record<string, unknown> }[];
  sectionId: string;
}) {
  const httpx = findings.filter((f) => findingBucket(f) === "httpx");
  const zap = findings.filter((f) => findingBucket(f) === "zap");
  const inventory = findings.filter((f) => findingBucket(f) === "inventory");
  const info = findings.filter((f) => findingBucket(f) === "info");
  const other = findings.filter((f) => findingBucket(f) === "other");

  if (findings.length === 0) {
    return <p className="text-xs text-cyber-muted">finding 없음</p>;
  }

  const httpxSubtitle =
    sectionId === "2-2" ? "· ARGUS 통합 로직 (본진)" : "· httpx probe";
  const zapSubtitle =
    sectionId === "2-2" ? "· unified + native supplemental" : "· ZAP scan";

  return (
    <>
      <CollapsibleFindingsSection
        title="httpx"
        subtitle={httpxSubtitle}
        count={httpx.length}
        defaultOpen={false}
        findings={httpx}
      />
      <CollapsibleFindingsSection
        title="ZAP"
        subtitle={zapSubtitle}
        count={zap.length}
        defaultOpen={false}
        findings={zap}
      />
      <CollapsibleFindingsSection
        title="inventory"
        subtitle="· api-tree + login report 분석"
        count={inventory.length}
        defaultOpen={sectionId === "3-4"}
        findings={inventory}
      />
      <CollapsibleFindingsSection
        title="info"
        count={info.length}
        defaultOpen={sectionId === "3-4"}
        findings={info}
      />
      {other.length > 0 ? (
        <CollapsibleFindingsSection
          title="기타"
          count={other.length}
          defaultOpen={false}
          findings={other}
        />
      ) : null}
    </>
  );
}

function ZapStatsLine({ zap }: { zap: unknown }) {
  if (!zap) return null;
  const z = zap as {
    error?: string;
    alerts?: number;
    unified_findings?: number;
    native_findings?: number;
    findings?: number;
  };
  const unified =
    typeof z.unified_findings === "number" ? ` · unified ${z.unified_findings}` : "";
  const native = typeof z.native_findings === "number" ? ` · native ${z.native_findings}` : "";
  const total = typeof z.findings === "number" ? z.findings : z.alerts;
  return (
    <>
      {" · ZAP "}
      {typeof z.error === "string"
        ? `(스킵: ${z.error})`
        : `완료 · findings ${String(total ?? 0)}${unified}${native}`}
    </>
  );
}

export function DiagnosisReportPanel({ report }: { report: DiagnosisSectionReport }) {
  const statsMessages = new Set([
    "1-5 scan statistics",
    "2-1 scan statistics",
    "4-1 scan statistics",
    "4-2 scan statistics",
    "2-2 scan statistics",
    "3-2 scan statistics",
    "3-4 scan statistics",
    "3-5 scan statistics",
    "3-6 scan statistics",
    "5-2 scan statistics",
    "6-1 scan statistics",
    "6-2 scan statistics",
    "7-1 scan statistics",
    "7-2 scan statistics",
    "7-3 scan statistics",
    "7-4 scan statistics",
  ]);
  const findings = report.findings.filter((f) => !statsMessages.has(f.message));
  const statsFinding = report.findings.find((f) => statsMessages.has(f.message));
  const stats = statsFinding?.evidence?.stats as Record<string, unknown> | undefined;
  const isG15Stats = statsFinding?.message === "1-5 scan statistics";
  const isG21Stats = statsFinding?.message === "2-1 scan statistics";
  const isG41Stats = statsFinding?.message === "4-1 scan statistics";
  const isG42Stats = statsFinding?.message === "4-2 scan statistics";
  const isG22Stats = statsFinding?.message === "2-2 scan statistics";
  const isG71Stats = statsFinding?.message === "7-1 scan statistics";
  const isG72Stats = statsFinding?.message === "7-2 scan statistics";
  const isG73Stats = statsFinding?.message === "7-3 scan statistics";
  const isG74Stats = statsFinding?.message === "7-4 scan statistics";
  const isG52Stats = statsFinding?.message === "5-2 scan statistics";
  const isG61Stats = statsFinding?.message === "6-1 scan statistics";
  const isG62Stats = statsFinding?.message === "6-2 scan statistics";
  const isG32Stats = statsFinding?.message === "3-2 scan statistics";
  const isG34Stats = statsFinding?.message === "3-4 scan statistics";
  const isG35Stats = statsFinding?.message === "3-5 scan statistics";
  const isG36Stats = statsFinding?.message === "3-6 scan statistics";

  return (
    <div className="border-t border-cyber-border/40 bg-cyber-bg/30 px-4 py-3">
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <StatusBadge status={report.status} />
        {report.checked_at ? (
          <span className="text-[10px] text-cyber-muted">{report.checked_at}</span>
        ) : null}
        {report.message ? (
          <span className="text-xs text-cyber-muted">{report.message}</span>
        ) : null}
      </div>

      {stats ? (
        <div className="mb-3 rounded border border-cyber-border/40 bg-cyber-panel/40 px-3 py-2 text-[11px] text-cyber-muted">
          {isG15Stats ? (
            <>
              sink{" "}
              <span className="font-mono text-cyan-300/90">{String(stats.sink_base ?? "—")}</span>
              {" · mode "}
              <span className="font-mono text-cyan-300/90">{String(stats.probe_mode ?? "sample")}</span>
              {typeof stats.phase_a_jobs === "number" ? (
                <span> · phase A {stats.phase_a_jobs}</span>
              ) : null}
              {typeof stats.phase_b_jobs === "number" ? (
                <span> · phase B {stats.phase_b_jobs}</span>
              ) : null}
              {typeof (stats.redirect as { open_redirects?: number })?.open_redirects === "number" &&
              (stats.redirect as { open_redirects?: number }).open_redirects! > 0 ? (
                <span className="text-rose-300/90">
                  {" "}
                  · open redirect {(stats.redirect as { open_redirects?: number }).open_redirects}
                </span>
              ) : null}
              {typeof (stats.cors as { issues?: number })?.issues === "number" &&
              (stats.cors as { issues?: number }).issues! > 0 ? (
                <span className="text-amber-300/90">
                  {" "}
                  · CORS {(stats.cors as { issues?: number }).issues}
                </span>
              ) : null}
            </>
          ) : null}
          {isG21Stats ? (
            <>
              <span className="font-mono text-cyan-300/90">{String(stats.source ?? "inventory")}</span>
              {" · 대상 "}
              <span className="font-mono text-cyan-300/90">
                {String(stats.targets_probed ?? stats.targets ?? "—")}
              </span>
              {typeof stats.upload_endpoints_found === "number" ? (
                <span> / api-tree 탐지 {stats.upload_endpoints_found}</span>
              ) : null}
              {stats.truncated_to ? (
                <span className="text-amber-300/80"> · max {String(stats.truncated_to)}로 제한</span>
              ) : null}
              {typeof (stats.httpx as { findings?: number })?.findings === "number" ? (
                <span> · httpx finding {(stats.httpx as { findings?: number }).findings}</span>
              ) : null}
              <ZapStatsLine zap={stats.zap} />
              {typeof stats.collapsed_issues === "number" ? (
                <span className={stats.collapsed_issues > 0 ? "text-rose-300/90" : "text-emerald-300/90"}>
                  {" "}
                  · unique issue {stats.collapsed_issues}
                </span>
              ) : null}
              {typeof stats.raw_issues === "number" && typeof stats.collapsed_issues === "number" &&
              stats.raw_issues > stats.collapsed_issues ? (
                <span className="text-cyber-muted"> (raw {stats.raw_issues} → deduped)</span>
              ) : null}
              {stats.auth_configured === false ? (
                <span className="text-amber-300/90"> · auth skip</span>
              ) : typeof stats.auth_sessions === "number" && stats.auth_sessions > 0 ? (
                <span className="text-cyan-300/80">
                  {" "}
                  · {1 + stats.auth_sessions} passes ({stats.auth_sessions} auth)
                </span>
              ) : null}
            </>
          ) : null}
          {isG41Stats ? (
            <>
              sessions{" "}
              <span className="font-mono text-cyan-300/90">{String(stats.sessions ?? "—")}</span>
              {" · mode "}
              <span className="font-mono text-cyan-300/90">{String(stats.probe_mode ?? "sample")}</span>
              {typeof stats.endpoints === "number" ? (
                <span> · endpoints {stats.endpoints}</span>
              ) : null}
              {Array.isArray(stats.session_emails) && stats.session_emails.length > 0 ? (
                <span className="text-cyan-300/80">
                  {" "}
                  · accounts {stats.session_emails.length}
                </span>
              ) : null}
              {typeof stats.auth_source === "string" ? (
                <span className="text-cyan-300/80"> · auth {stats.auth_source}</span>
              ) : null}
              {typeof (stats.cookie_attr as { issues?: number })?.issues === "number" ? (
                <span>
                  {" "}
                  · cookie flags {(stats.cookie_attr as { issues?: number }).issues}
                  {typeof (stats.cookie_attr as { from_cache?: number })?.from_cache === "number" &&
                  (stats.cookie_attr as { from_cache?: number }).from_cache! > 0 ? (
                    <span className="text-cyan-300/80">
                      {" "}
                      (cache {(stats.cookie_attr as { from_cache?: number }).from_cache})
                    </span>
                  ) : null}
                </span>
              ) : null}
              {typeof (stats.cross_cookie as { cross_accepted?: number })?.cross_accepted ===
                "number" &&
              (stats.cross_cookie as { cross_accepted?: number }).cross_accepted! > 0 ? (
                <span className="text-rose-300/90">
                  {" "}
                  · cross {(stats.cross_cookie as { cross_accepted?: number }).cross_accepted}
                </span>
              ) : null}
              {typeof (stats.tamper as { tamper_accepted?: number })?.tamper_accepted === "number" &&
              (stats.tamper as { tamper_accepted?: number }).tamper_accepted! > 0 ? (
                <span className="text-rose-300/90">
                  {" "}
                  · tamper {(stats.tamper as { tamper_accepted?: number }).tamper_accepted}
                </span>
              ) : null}
              {typeof (stats.by_severity as { high?: number })?.high === "number" &&
              (stats.by_severity as { high?: number }).high! > 0 ? (
                <span className="text-rose-300/90">
                  {" "}
                  · high {(stats.by_severity as { high?: number }).high}
                </span>
              ) : null}
            </>
          ) : null}
          {isG42Stats ? (
            <>
              sessions{" "}
              <span className="font-mono text-cyan-300/90">{String(stats.sessions ?? "—")}</span>
              {typeof stats.auth_source === "string" ? (
                <span className="text-cyan-300/80"> · auth {stats.auth_source}</span>
              ) : null}
              {typeof (stats.token_analysis as { tokens_analyzed?: number })?.tokens_analyzed ===
              "number" ? (
                <span>
                  {" "}
                  · tokens analyzed{" "}
                  {(stats.token_analysis as { tokens_analyzed?: number }).tokens_analyzed}
                </span>
              ) : null}
              {typeof (stats.by_severity as { high?: number })?.high === "number" &&
              (stats.by_severity as { high?: number }).high! > 0 ? (
                <span className="text-rose-300/90">
                  {" "}
                  · high {(stats.by_severity as { high?: number }).high}
                </span>
              ) : null}
              {typeof (stats.by_severity as { medium?: number })?.medium === "number" &&
              (stats.by_severity as { medium?: number }).medium! > 0 ? (
                <span className="text-amber-300/90">
                  {" "}
                  · medium {(stats.by_severity as { medium?: number }).medium}
                </span>
              ) : null}
              {typeof stats.client_logout_findings === "number" ? (
                <span> · client logout findings {stats.client_logout_findings}</span>
              ) : null}
              {stats.auth_logout_gap ? (
                <span className="text-amber-300/80"> · no server logout API</span>
              ) : null}
              {typeof stats.duplicate_login_ip_findings === "number" ? (
                <span> · cross-IP login {stats.duplicate_login_ip_findings}</span>
              ) : null}
            </>
          ) : null}
          {isG22Stats ? (
            <>
              대상{" "}
              <span className="font-mono text-cyan-300/90">
                {String((stats.candidates as { total?: number })?.total ?? "—")}
              </span>
              {stats.selection_mode === "all_inventory" ? (
                <span className="text-amber-300/90"> · api-tree 전체</span>
              ) : (
                <span> · 2-2 후보 상위</span>
              )}
              {typeof stats.inventory_endpoints === "number" ? (
                <span> / inventory {stats.inventory_endpoints}</span>
              ) : null}
              {stats.httpx ? " · httpx 프로브 완료" : null}
              {typeof stats.httpx_findings === "number" ? (
                <span> · httpx finding {stats.httpx_findings}</span>
              ) : null}
              <ZapStatsLine zap={stats.zap} />
              {typeof stats.zap_findings === "number" && stats.zap_findings > 0 ? (
                <span> · zap finding {stats.zap_findings}</span>
              ) : null}
            </>
          ) : null}
          {isG72Stats ? (
            <>
              <span className="font-mono text-cyan-300/90">{String(stats.probe_mode ?? "base_only")}</span>
              {" · "}
              probe{" "}
              <span className="font-mono text-cyan-300/90">{String(stats.probed ?? "—")}</span>
              {typeof stats.wordlist_paths === "number" ? (
                <span> · wordlist {stats.wordlist_paths}</span>
              ) : null}
              {typeof stats.collapsed_issues === "number" ? (
                <span> · unique finding {stats.collapsed_issues}</span>
              ) : null}
              {typeof stats.raw_issues === "number" &&
              typeof stats.collapsed_issues === "number" &&
              stats.raw_issues > stats.collapsed_issues ? (
                <span className="text-cyber-muted"> (raw {stats.raw_issues} → deduped)</span>
              ) : null}
              {stats.httpx ? " · httpx 프로브 완료" : null}
              <ZapStatsLine zap={stats.zap} />
              {stats.inventory_fallback ? (
                <span className="text-amber-300/90"> · api-tree 없음</span>
              ) : null}
            </>
          ) : null}
          {isG71Stats ? (
            <>
              <span className="font-mono text-cyan-300/90">{String(stats.probe_mode ?? "base_only")}</span>
              {" · "}
              probe{" "}
              <span className="font-mono text-cyan-300/90">{String(stats.probed ?? "—")}</span>
              {typeof stats.targets === "number" ? (
                <span> / URL {stats.targets}</span>
              ) : null}
              {typeof stats.collapsed_issues === "number" ? (
                <span> · unique finding {stats.collapsed_issues}</span>
              ) : typeof stats.issues === "number" ? (
                <span> · finding {stats.issues}</span>
              ) : null}
              {typeof stats.raw_issues === "number" && typeof stats.collapsed_issues === "number" &&
              stats.raw_issues > stats.collapsed_issues ? (
                <span className="text-cyber-muted">
                  {" "}
                  (raw {stats.raw_issues} → deduped)
                </span>
              ) : null}
              {typeof stats.unreachable === "number" && stats.unreachable > 0 ? (
                <span className="text-amber-300/90"> · unreachable {stats.unreachable}</span>
              ) : null}
              {stats.httpx ? " · httpx 프로브 완료" : null}
              <ZapStatsLine zap={stats.zap} />
              {stats.strict_risky ? (
                <span className="text-rose-300/80"> · strict risky</span>
              ) : (
                <span> · TRACE/TRACK only</span>
              )}
              {stats.inventory_fallback ? (
                <span className="text-amber-300/90"> · api-tree 없음 (base만)</span>
              ) : null}
            </>
          ) : null}
          {isG73Stats ? (
            <>
              <span className="font-mono text-cyan-300/90">{String(stats.probe_mode ?? "base_only")}</span>
              {" · "}
              probe{" "}
              <span className="font-mono text-cyan-300/90">{String(stats.probed ?? "—")}</span>
              {typeof stats.targets === "number" ? (
                <span> / URL {stats.targets}</span>
              ) : null}
              {typeof stats.inventory_endpoints === "number" && stats.inventory_endpoints > 0 ? (
                <span> · inventory {stats.inventory_endpoints}</span>
              ) : null}
              {typeof stats.collapsed_issues === "number" ? (
                <span> · unique finding {stats.collapsed_issues}</span>
              ) : typeof stats.issues === "number" ? (
                <span> · finding {stats.issues}</span>
              ) : null}
              {typeof stats.raw_issues === "number" && typeof stats.collapsed_issues === "number" &&
              stats.raw_issues > stats.collapsed_issues ? (
                <span className="text-cyber-muted">
                  {" "}
                  (raw {stats.raw_issues} → deduped)
                </span>
              ) : null}
              {typeof stats.unreachable === "number" && stats.unreachable > 0 ? (
                <span className="text-amber-300/90"> · unreachable {stats.unreachable}</span>
              ) : null}
              {stats.httpx ? " · httpx 프로브 완료" : null}
              <ZapStatsLine zap={stats.zap} />
              {stats.strict ? (
                <span className="text-rose-300/80"> · strict</span>
              ) : (
                <span> · standard</span>
              )}
              {stats.inventory_fallback ? (
                <span className="text-amber-300/90"> · api-tree 없음 (base만)</span>
              ) : null}
            </>
          ) : null}
          {isG74Stats ? (
            <>
              <span className="font-mono text-cyan-300/90">{String(stats.probe_mode ?? "base_only")}</span>
              {" · "}
              probe{" "}
              <span className="font-mono text-cyan-300/90">{String(stats.probed ?? "—")}</span>
              {typeof stats.targets === "number" ? (
                <span> / URL {stats.targets}</span>
              ) : null}
              {typeof stats.collapsed_issues === "number" ? (
                <span> · unique finding {stats.collapsed_issues}</span>
              ) : typeof stats.issues === "number" ? (
                <span> · finding {stats.issues}</span>
              ) : null}
              {typeof stats.raw_issues === "number" && typeof stats.collapsed_issues === "number" &&
              stats.raw_issues > stats.collapsed_issues ? (
                <span className="text-cyber-muted">
                  {" "}
                  (raw {stats.raw_issues} → deduped)
                </span>
              ) : null}
              {typeof stats.unreachable === "number" && stats.unreachable > 0 ? (
                <span className="text-amber-300/90"> · unreachable {stats.unreachable}</span>
              ) : null}
              {stats.httpx ? " · httpx 프로브 완료" : null}
              <ZapStatsLine zap={stats.zap} />
              {stats.strict ? (
                <span className="text-rose-300/80"> · strict</span>
              ) : (
                <span> · standard</span>
              )}
              {stats.check_cookies === false ? (
                <span> · cookies off</span>
              ) : (
                <span> · cookies</span>
              )}
              {stats.inventory_fallback ? (
                <span className="text-amber-300/90"> · api-tree 없음 (base만)</span>
              ) : null}
            </>
          ) : null}
          {isG32Stats ? (
            <>
              login entries{" "}
              <span className="font-mono text-cyan-300/90">{String(stats.login_entries ?? "—")}</span>
              {" · attempts "}
              <span className="font-mono text-cyan-300/90">{String(stats.max_attempts ?? "—")}</span>
              {typeof stats.limit_detected === "number" ? (
                <span className="text-emerald-300/90"> · limit ok {stats.limit_detected}</span>
              ) : null}
              {typeof stats.no_limit === "number" && stats.no_limit > 0 ? (
                <span className="text-rose-300/90"> · no limit {stats.no_limit}</span>
              ) : null}
              {stats.strict ? (
                <span className="text-rose-300/80"> · strict</span>
              ) : (
                <span> · standard</span>
              )}
            </>
          ) : null}
          {isG34Stats ? (
            <>
              login{" "}
              <span className="font-mono text-cyan-300/90">
                user {String(stats.user_login_entries ?? "—")} / admin {String(stats.admin_login_entries ?? "—")}
              </span>
              {" · admin UI "}
              <span className="font-mono text-cyan-300/90">{String(stats.admin_frontend_paths ?? "—")}</span>
              {" · admin API "}
              <span className="font-mono text-cyan-300/90">{String(stats.admin_api_paths ?? "—")}</span>
              {typeof (stats.by_severity as { medium?: number })?.medium === "number" &&
              (stats.by_severity as { medium?: number }).medium! > 0 ? (
                <span className="text-amber-300/90">
                  {" "}
                  · medium {(stats.by_severity as { medium?: number }).medium}
                </span>
              ) : null}
              {Array.isArray(stats.admin_subdomain_pairs) && stats.admin_subdomain_pairs.length > 0 ? (
                <span className="text-emerald-300/90"> · subdomain 분리</span>
              ) : null}
              {typeof stats.guessable_paths === "number" && stats.guessable_paths > 0 ? (
                <span> · guessable path {stats.guessable_paths}</span>
              ) : null}
            </>
          ) : null}
          {isG35Stats ? (
            <>
              <span className="font-mono text-cyan-300/90">{String(stats.probe_mode ?? "sample")}</span>
              {" · robots "}
              <span className="font-mono text-cyan-300/90">
                {String((stats.robots as { robots_probed?: number })?.robots_probed ?? "—")}
              </span>
              {" · pages "}
              <span className="font-mono text-cyan-300/90">
                {String(
                  (stats.pages_anonymous as { pages_probed?: number })?.pages_probed ??
                    (stats.pages as { pages_probed?: number })?.pages_probed ??
                    "—",
                )}
              </span>
              {typeof (stats.pages_anonymous as { with_noindex?: number })?.with_noindex === "number" ? (
                <span className="text-emerald-300/90">
                  {" "}
                  · anon noindex {(stats.pages_anonymous as { with_noindex?: number }).with_noindex}
                </span>
              ) : null}
              {typeof (stats.pages_authenticated as { with_noindex?: number })?.with_noindex === "number" ? (
                <span className="text-cyan-300/90">
                  {" "}
                  · auth noindex {(stats.pages_authenticated as { with_noindex?: number }).with_noindex}
                </span>
              ) : null}
              {stats.auth_configured === false ? (
                <span className="text-amber-300/90"> · auth skip</span>
              ) : typeof stats.auth_sessions === "number" && stats.auth_sessions > 0 ? (
                <span className="text-cyan-300/80">
                  {" "}
                  · {1 + stats.auth_sessions} passes ({stats.auth_sessions} auth)
                </span>
              ) : stats.auth_configured ? (
                <span className="text-cyan-300/80"> · multi pass</span>
              ) : null}
              {typeof stats.robots === "object" && stats.robots !== null ? (
                <span>
                  {" "}
                  · robots present {(stats.robots as { robots_present?: number }).robots_present ?? 0}
                  /missing {(stats.robots as { robots_missing?: number }).robots_missing ?? 0}
                </span>
              ) : null}
              {typeof stats.frontend_bases === "number" && stats.frontend_bases > 0 ? (
                <span> · frontend base {stats.frontend_bases}</span>
              ) : null}
              {stats.inventory_fallback ? (
                <span className="text-amber-300/90"> · api-tree 없음</span>
              ) : null}
            </>
          ) : null}
          {isG36Stats ? (
            <>
              <span className="font-mono text-cyan-300/90">{String(stats.probe_mode ?? "base_only")}</span>
              {" · probed "}
              <span className="font-mono text-cyan-300/90">{String(stats.probed ?? "—")}</span>
              {typeof stats.wordlist_total === "number" ? (
                <span> · wordlist {stats.wordlist_total}</span>
              ) : null}
              {typeof stats.collapsed_issues === "number" ? (
                <span className="text-rose-300/90"> · issues {stats.collapsed_issues}</span>
              ) : null}
              {typeof stats.httpx_findings === "number" ? (
                <span> · httpx {stats.httpx_findings}</span>
              ) : null}
              {stats.auth_configured === false ? (
                <span className="text-amber-300/90"> · auth skip</span>
              ) : typeof stats.auth_sessions === "number" && stats.auth_sessions > 0 ? (
                <span className="text-cyan-300/80">
                  {" "}
                  · {1 + stats.auth_sessions} passes ({stats.auth_sessions} auth)
                </span>
              ) : stats.auth_configured ? (
                <span className="text-cyan-300/80"> · multi pass</span>
              ) : null}
              {typeof (stats.authenticated as { issues?: number })?.issues === "number" &&
              (stats.authenticated as { issues?: number }).issues! > 0 ? (
                <span className="text-rose-300/90">
                  {" "}
                  · auth issues {(stats.authenticated as { issues?: number }).issues}
                </span>
              ) : null}
              {stats.inventory_fallback ? (
                <span className="text-amber-300/90"> · api-tree 없음</span>
              ) : null}
            </>
          ) : null}
          {isG52Stats ? (
            <>
              mode{" "}
              <span className="font-mono text-cyan-300/90">{String(stats.probe_mode ?? "sample")}</span>
              {" · endpoints "}
              <span className="font-mono text-cyan-300/90">
                {String(stats.endpoints_probed ?? "—")}/{String(stats.endpoints_selected ?? stats.endpoints_total ?? "—")}
              </span>
              {typeof (stats.coverage as { requests?: number })?.requests === "number" ? (
                <span>
                  {" "}
                  · HTTP {(stats.coverage as { requests?: number }).requests}
                  {typeof (stats.coverage as { responses_with_body?: number })?.responses_with_body === "number" ? (
                    <span>
                      {" "}
                      (body {(stats.coverage as { responses_with_body?: number }).responses_with_body})
                    </span>
                  ) : null}
                </span>
              ) : null}
              {typeof (stats.coverage as { status_2xx?: number })?.status_2xx === "number" ? (
                <span className="text-cyan-300/80">
                  {" "}
                  · 2xx {(stats.coverage as { status_2xx?: number }).status_2xx}
                </span>
              ) : null}
              {typeof (stats.coverage as { status_401?: number })?.status_401 === "number" &&
              (stats.coverage as { status_401?: number }).status_401! > 0 ? (
                <span className="text-amber-300/90">
                  {" "}
                  · 401 {(stats.coverage as { status_401?: number }).status_401}
                </span>
              ) : null}
              {typeof (stats.coverage as { connection_errors?: number })?.connection_errors ===
                "number" &&
              (stats.coverage as { connection_errors?: number }).connection_errors! > 0 ? (
                <span className="text-rose-300/90">
                  {" "}
                  · unreachable {(stats.coverage as { connection_errors?: number }).connection_errors}
                </span>
              ) : null}
              {typeof stats.issues === "number" ? (
                <span className={stats.issues > 0 ? "text-rose-300/90" : "text-emerald-300/90"}>
                  {" "}
                  · unmasked PII {stats.issues}
                </span>
              ) : null}
              {typeof (stats.coverage as { emails_seen?: number })?.emails_seen === "number" &&
              (stats.coverage as { emails_seen?: number }).emails_seen! > 0 ? (
                <span>
                  {" "}
                  · emails in JSON {(stats.coverage as { emails_seen?: number }).emails_seen}
                </span>
              ) : null}
              {typeof (stats.coverage as { phones_seen?: number })?.phones_seen === "number" &&
              (stats.coverage as { phones_seen?: number }).phones_seen! > 0 ? (
                <span>
                  {" "}
                  · phones in JSON {(stats.coverage as { phones_seen?: number }).phones_seen}
                </span>
              ) : null}
              {typeof stats.raw_issues === "number" && typeof stats.collapsed_issues === "number" &&
              stats.raw_issues > stats.collapsed_issues ? (
                <span> · raw {stats.raw_issues}</span>
              ) : null}
              {typeof stats.auth_passes === "number" ? (
                <span> · auth passes {stats.auth_passes}</span>
              ) : null}
              {stats.inventory === false ? (
                <span className="text-amber-300/90"> · api-tree 없음</span>
              ) : null}
            </>
          ) : null}
          {isG61Stats ? (
            <>
              mode{" "}
              <span className="font-mono text-cyan-300/90">{String(stats.probe_mode ?? "sample")}</span>
              {" · endpoints "}
              <span className="font-mono text-cyan-300/90">
                {String(stats.endpoints_probed ?? "—")}/{String(stats.endpoints_total ?? "—")}
              </span>
              {" · requests "}
              <span className="font-mono text-cyan-300/90">
                {String(stats.requests_sent ?? "—")}/{String(stats.requests_cap ?? "—")}
              </span>
              {" · payloads "}
              <span className="font-mono text-cyan-300/90">{String(stats.payloads ?? "—")}</span>
              {typeof stats.httpx_leaks === "number" ? (
                <span> · httpx leaks {stats.httpx_leaks}</span>
              ) : typeof stats.leaks === "number" && stats.leaks > 0 ? (
                <span className="text-rose-300/90"> · leaks {stats.leaks}</span>
              ) : null}
              {typeof stats.zap_unified_leaks === "number" ? (
                <span> · ZAP unified {stats.zap_unified_leaks}</span>
              ) : null}
              {typeof stats.zap_native_alerts === "number" && stats.zap_native_alerts > 0 ? (
                <span className="text-rose-300/90"> · ZAP native {stats.zap_native_alerts}</span>
              ) : null}
              {typeof stats.auth_passes === "number" ? (
                <span> · auth passes {stats.auth_passes}</span>
              ) : null}
              <ZapStatsLine zap={stats.zap} />
              {stats.inventory === false ? (
                <span className="text-amber-300/90"> · api-tree 없음</span>
              ) : null}
            </>
          ) : null}
          {isG62Stats ? (
            <>
              login entries{" "}
              <span className="font-mono text-cyan-300/90">{String(stats.login_entries ?? "—")}</span>
              {" · probed "}
              <span className="font-mono text-cyan-300/90">{String(stats.probed ?? "—")}</span>
              {typeof stats.uniform === "number" ? (
                <span className="text-emerald-300/90"> · uniform {stats.uniform}</span>
              ) : null}
              {typeof stats.enumeration_risk === "number" && stats.enumeration_risk > 0 ? (
                <span className="text-rose-300/90"> · enumeration {stats.enumeration_risk}</span>
              ) : null}
              {stats.strict ? (
                <span className="text-rose-300/80"> · strict</span>
              ) : (
                <span> · standard</span>
              )}
              {typeof stats.accounts_available === "number" ? (
                <span> · accounts {stats.accounts_available}</span>
              ) : null}
              <ZapStatsLine zap={stats.zap} />
              {typeof stats.zap_findings === "number" && stats.zap_findings > 0 ? (
                <span className="text-rose-300/90"> · zap 40023 {stats.zap_findings}</span>
              ) : null}
            </>
          ) : null}
        </div>
      ) : null}

      {findings.length === 0 ? (
        <p className="text-xs text-cyber-muted">finding 없음</p>
      ) : (
        <GroupedFindingsPanel findings={findings} sectionId={report.section_id} />
      )}
    </div>
  );
}
