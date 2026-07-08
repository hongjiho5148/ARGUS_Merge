/** Transform 7-3 diagnosis findings into matrix + grouped views. */

export type G73Finding = {
  severity: string;
  message: string;
  evidence?: Record<string, unknown>;
};

export const G73_REASON_LABELS: Record<string, string> = {
  version_disclosed: "버전 노출",
  product_name_disclosed: "제품명 노출",
  environment_disclosed: "환경명 노출",
  stack_or_server_disclosed: "스택/서버 정보",
};

const HEADER_COLUMN_PRIORITY = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"];

export type G73MergedFinding = {
  severity: string;
  baseUrl: string;
  header: string;
  headerValue: string;
  reason: string;
  reasonLabel: string;
  remediation: string | null;
  affectedCount: number;
  affectedUrls: string[];
  sampleUrl: string | null;
  sources: ("httpx" | "zap")[];
  httpStatus: string | number | null;
};

export type G73BaseUrlGroup = {
  baseUrl: string;
  displayLabel: string;
  maxAffectedCount: number;
  findings: G73MergedFinding[];
};

export type G73MatrixCell = {
  severity: string;
  value: string;
  count: number;
};

export type G73MatrixRow = {
  baseUrl: string;
  displayLabel: string;
  maxAffectedCount: number;
  cells: Record<string, G73MatrixCell>;
};

export type G73ReasonSummary = {
  reason: string;
  label: string;
  count: number;
};

function isG73HeaderFinding(f: G73Finding): boolean {
  const ev = f.evidence;
  if (!ev) return false;
  return ev.rule_id === "7-3-header-disclosure" && typeof ev.header === "string";
}

function engineSource(ev: Record<string, unknown>): "httpx" | "zap" | null {
  const engine = String(ev.engine ?? ev.source ?? "");
  if (engine === "httpx") return "httpx";
  if (engine === "zap") return "zap";
  return null;
}

function isStructuredReason(reason: string): boolean {
  return reason in G73_REASON_LABELS;
}

function reasonLabel(reason: string): string {
  return G73_REASON_LABELS[reason] ?? reason;
}

export function formatG73BaseLabel(baseUrl: string): string {
  try {
    const u = new URL(baseUrl);
    const port = u.port ? `:${u.port}` : "";
    return `${u.hostname}${port}`;
  } catch {
    return baseUrl.replace(/^https?:\/\//, "").replace(/\/$/, "");
  }
}

export function formatG73HeaderLabel(header: string): string {
  if (header === "server") return "Server";
  if (header === "x-powered-by") return "X-Powered-By";
  return header;
}

function mergeKey(f: G73Finding): string | null {
  const ev = f.evidence;
  if (!ev?.header) return null;
  return [
    f.severity,
    String(ev.base_url ?? ""),
    String(ev.header),
    String(ev.header_value ?? ""),
  ].join("|");
}

export function mergeG73Findings(findings: G73Finding[]): {
  merged: G73MergedFinding[];
  other: G73Finding[];
} {
  const other: G73Finding[] = [];
  const map = new Map<
    string,
    {
      severity: string;
      ev: Record<string, unknown>;
      urls: Set<string>;
      sources: Set<"httpx" | "zap">;
    }
  >();

  for (const f of findings) {
    if (!isG73HeaderFinding(f)) {
      other.push(f);
      continue;
    }
    const key = mergeKey(f);
    if (!key) {
      other.push(f);
      continue;
    }
    const ev = f.evidence ?? {};
    const url = String(ev.url ?? "");
    const affected = ev.affected_urls;
    const urlList = Array.isArray(affected) ? affected.map(String) : url ? [url] : [];

    const existing = map.get(key);
    if (!existing) {
      map.set(key, {
        severity: f.severity,
        ev: { ...ev },
        urls: new Set(urlList.filter(Boolean)),
        sources: new Set(engineSource(ev) ? [engineSource(ev)!] : []),
      });
      continue;
    }
    for (const u of urlList) {
      if (u) existing.urls.add(u);
    }
    const src = engineSource(ev);
    if (src) existing.sources.add(src);
    const existingReason = String(existing.ev.reason ?? "");
    const nextReason = String(ev.reason ?? "");
    if (isStructuredReason(nextReason) && !isStructuredReason(existingReason)) {
      existing.ev.reason = nextReason;
    }
    if (ev.remediation && !existing.ev.remediation) {
      existing.ev.remediation = ev.remediation;
    }
    if (typeof ev.affected_count === "number") {
      const prev = Number(existing.ev.affected_count ?? 0);
      existing.ev.affected_count = Math.max(prev, ev.affected_count);
    }
  }

  const merged: G73MergedFinding[] = [];
  for (const { severity, ev, urls, sources } of map.values()) {
    const urlArr = [...urls].sort();
    const affectedCount =
      urlArr.length > 0 ? urlArr.length : typeof ev.affected_count === "number" ? ev.affected_count : 1;
    const reason = String(ev.reason ?? "");

    merged.push({
      severity,
      baseUrl: String(ev.base_url ?? "—"),
      header: String(ev.header ?? ""),
      headerValue: String(ev.header_value ?? ""),
      reason,
      reasonLabel: reasonLabel(reason),
      remediation: ev.remediation != null ? String(ev.remediation) : null,
      affectedCount,
      affectedUrls: urlArr,
      sampleUrl: urlArr[0] ?? (ev.url != null ? String(ev.url) : null),
      sources: [...sources].sort() as ("httpx" | "zap")[],
      httpStatus: ev.http_status != null ? (ev.http_status as string | number) : null,
    });
  }

  merged.sort((a, b) => {
    const base = a.baseUrl.localeCompare(b.baseUrl);
    if (base !== 0) return base;
    const ha = headerSortKey(a.header);
    const hb = headerSortKey(b.header);
    if (ha !== hb) return ha - hb;
    return a.headerValue.localeCompare(b.headerValue);
  });

  return { merged, other };
}

function headerSortKey(header: string): number {
  const idx = HEADER_COLUMN_PRIORITY.indexOf(header);
  return idx >= 0 ? idx : HEADER_COLUMN_PRIORITY.length;
}

export function buildG73ReasonSummary(merged: G73MergedFinding[]): G73ReasonSummary[] {
  const counts = new Map<string, number>();
  for (const f of merged) {
    const key = isStructuredReason(f.reason) ? f.reason : "_other";
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  const items: G73ReasonSummary[] = [];
  for (const [reason, count] of counts) {
    items.push({
      reason,
      label: reason === "_other" ? "기타" : reasonLabel(reason),
      count,
    });
  }
  return items.sort((a, b) => b.count - a.count);
}

export function buildG73Matrix(merged: G73MergedFinding[]): {
  rows: G73MatrixRow[];
  columns: string[];
} {
  const byBase = new Map<string, G73MatrixRow>();
  const headerSet = new Set<string>();

  for (const f of merged) {
    headerSet.add(f.header);
    let row = byBase.get(f.baseUrl);
    if (!row) {
      row = {
        baseUrl: f.baseUrl,
        displayLabel: formatG73BaseLabel(f.baseUrl),
        maxAffectedCount: 0,
        cells: {},
      };
      byBase.set(f.baseUrl, row);
    }
    row.maxAffectedCount = Math.max(row.maxAffectedCount, f.affectedCount);
    const prev = row.cells[f.header];
    if (!prev || severityRank(f.severity) >= severityRank(prev.severity)) {
      row.cells[f.header] = {
        severity: f.severity,
        value: f.headerValue,
        count: f.affectedCount,
      };
    } else if (prev) {
      prev.count = Math.max(prev.count, f.affectedCount);
    }
  }

  const columns = [...headerSet].sort((a, b) => {
    const ka = headerSortKey(a);
    const kb = headerSortKey(b);
    if (ka !== kb) return ka - kb;
    return a.localeCompare(b);
  });

  const rows = [...byBase.values()].sort((a, b) => a.displayLabel.localeCompare(b.displayLabel));
  return { rows, columns };
}

function severityRank(sev: string): number {
  if (sev === "high") return 3;
  if (sev === "medium") return 2;
  if (sev === "low") return 1;
  return 0;
}

export function groupG73ByBaseUrl(merged: G73MergedFinding[]): G73BaseUrlGroup[] {
  const groups = new Map<string, G73BaseUrlGroup>();

  for (const f of merged) {
    let g = groups.get(f.baseUrl);
    if (!g) {
      g = {
        baseUrl: f.baseUrl,
        displayLabel: formatG73BaseLabel(f.baseUrl),
        maxAffectedCount: 0,
        findings: [],
      };
      groups.set(f.baseUrl, g);
    }
    g.findings.push(f);
    g.maxAffectedCount = Math.max(g.maxAffectedCount, f.affectedCount);
  }

  return [...groups.values()].sort((a, b) => a.displayLabel.localeCompare(b.displayLabel));
}

export function truncateG73Value(value: string, max = 18): string {
  if (value.length <= max) return value;
  return `${value.slice(0, max - 1)}…`;
}
