/** Per-run options for guideline 2-2 diagnosis (sent to POST /diagnosis/modules/2-2/run). */

export type G22DiagnosisPreset = "minimal" | "full" | "manual";

export interface G22DiagnosisOptions {
  useHttpx: boolean;
  useZap: boolean;
  /** Cross-account IDOR on export/download path params (requires ≥2 test accounts). */
  idorProbe: boolean;
  /** When true, every row in api-tree (no 2-2 score filter, no max cap). */
  scanAllInventory: boolean;
  maxCandidates: number;
  zapMaxMinutes: number;
}

/** 동작 확인 — httpx 후보 40개, ZAP OFF. */
export const MINIMAL_G22_OPTIONS: G22DiagnosisOptions = {
  useHttpx: true,
  useZap: false,
  idorProbe: true,
  scanAllInventory: false,
  maxCandidates: 40,
  zapMaxMinutes: 20,
};

/** 전수 — api-tree 전체 + httpx + ZAP. */
export const FULL_G22_OPTIONS: G22DiagnosisOptions = {
  useHttpx: true,
  useZap: true,
  idorProbe: true,
  scanAllInventory: true,
  maxCandidates: 80,
  zapMaxMinutes: 20,
};

export const DEFAULT_G22_OPTIONS = MINIMAL_G22_OPTIONS;

/** @deprecated use MINIMAL without httpx for design-only */
export const QUICK_G22_OPTIONS: G22DiagnosisOptions = {
  useHttpx: false,
  useZap: false,
  idorProbe: false,
  scanAllInventory: false,
  maxCandidates: 80,
  zapMaxMinutes: 20,
};

/** @deprecated use MINIMAL_G22_OPTIONS */
export const STANDARD_G22_OPTIONS = MINIMAL_G22_OPTIONS;

export function g22OptionsForPreset(preset: G22DiagnosisPreset): G22DiagnosisOptions {
  if (preset === "full") return { ...FULL_G22_OPTIONS };
  if (preset === "minimal") return { ...MINIMAL_G22_OPTIONS };
  return { ...MINIMAL_G22_OPTIONS };
}

export const G22_PRESET_LABELS: Record<G22DiagnosisPreset, string> = {
  minimal: "최소 진단",
  full: "전체 진단",
  manual: "수동 입력",
};

export function g22OptionsToPayload(options: G22DiagnosisOptions) {
  const g22: Record<string, boolean | number> = {
    httpx_enabled: options.useHttpx,
    zap_enabled: options.useZap,
    idor_probe_enabled: options.idorProbe,
    scan_all_inventory: options.scanAllInventory,
    zap_max_minutes: options.zapMaxMinutes,
  };
  if (!options.scanAllInventory) {
    g22.max_candidates = options.maxCandidates;
  }
  return { g22 };
}

export function g22OptionsSummary(options: G22DiagnosisOptions): string {
  const parts: string[] = ["설계 리뷰"];
  if (options.scanAllInventory) parts.push("api-tree 전체");
  else parts.push(`후보 상위 ${options.maxCandidates}`);
  if (options.useHttpx) parts.push("httpx · traversal+forced browse");
  if (options.useZap) parts.push("ZAP · unified + supplemental");
  if (options.idorProbe && (options.useHttpx || options.useZap)) parts.push("IDOR (2계정+)");
  if (!options.useHttpx && !options.useZap) parts.push("only");
  return parts.join(" · ");
}
