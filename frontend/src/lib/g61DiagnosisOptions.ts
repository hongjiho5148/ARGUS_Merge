/** Per-run options for guideline 6-1 diagnosis (POST /diagnosis/modules/6-1/run). */

export type G61ProbeMode = "sample" | "full";

export type G61DiagnosisPreset = "minimal" | "full" | "manual";

export interface G61DiagnosisOptions {
  probeMode: G61ProbeMode;
  sampleSize: number;
  maxEndpoints: number;
  /** 0 = unlimited (no request cap). */
  maxRequests: number;
  timeout: number;
  intervalSec: number;
  useHttpx: boolean;
  useZap: boolean;
  zapUnified: boolean;
  zapSupplemental: boolean;
  /** 0 = unlimited. */
  zapMaxRequests: number;
  zapMaxMinutes: number;
  /** 0 = seed every probe URL for ZAP supplemental. */
  zapSeedCap: number;
}

/** 동작 확인 — api-tree 샘플 20개, httpx only. */
export const MINIMAL_G61_OPTIONS: G61DiagnosisOptions = {
  probeMode: "sample",
  sampleSize: 20,
  maxEndpoints: 40,
  maxRequests: 2000,
  timeout: 10,
  intervalSec: 0.02,
  useHttpx: true,
  useZap: false,
  zapUnified: false,
  zapSupplemental: false,
  zapMaxRequests: 0,
  zapMaxMinutes: 15,
  zapSeedCap: 200,
};

/** 전체 전수 — Full, httpx + ZAP, 상한 없음. */
export const FULL_G61_OPTIONS: G61DiagnosisOptions = {
  probeMode: "full",
  sampleSize: 500,
  maxEndpoints: 0,
  maxRequests: 0,
  timeout: 12,
  intervalSec: 0.02,
  useHttpx: true,
  useZap: true,
  zapUnified: true,
  zapSupplemental: true,
  zapMaxRequests: 0,
  zapMaxMinutes: 120,
  zapSeedCap: 0,
};

export const DEFAULT_G61_OPTIONS = MINIMAL_G61_OPTIONS;

/** @deprecated use MINIMAL_G61_OPTIONS */
export const G61_SMOKE_PRESET = MINIMAL_G61_OPTIONS;

/** @deprecated use FULL_G61_OPTIONS */
export const G61_EXHAUSTIVE_PRESET = FULL_G61_OPTIONS;

export function g61RequestCapLabel(cap: number): string {
  return cap <= 0 ? "무제한" : cap.toLocaleString();
}

export function g61OptionsForPreset(preset: G61DiagnosisPreset): G61DiagnosisOptions {
  if (preset === "full") return { ...FULL_G61_OPTIONS };
  if (preset === "minimal") return { ...MINIMAL_G61_OPTIONS };
  return { ...MINIMAL_G61_OPTIONS };
}

export const G61_PRESET_LABELS: Record<G61DiagnosisPreset, string> = {
  minimal: "최소 진단",
  full: "전체 진단",
  manual: "수동 입력",
};

export function g61OptionsToPayload(options: G61DiagnosisOptions) {
  return {
    g61: {
      probe_mode: options.probeMode,
      sample_size: options.sampleSize,
      max_endpoints: options.maxEndpoints,
      max_requests: options.maxRequests,
      timeout: options.timeout,
      interval_sec: options.intervalSec,
      httpx_enabled: options.useHttpx,
      zap_enabled: options.useZap,
      zap_unified_enabled: options.zapUnified,
      zap_supplemental_enabled: options.zapSupplemental,
      zap_max_requests: options.zapMaxRequests,
      zap_max_minutes: options.zapMaxMinutes,
      zap_seed_cap: options.zapSeedCap,
    },
  };
}

export function g61ScopeLabel(options: G61DiagnosisOptions): string {
  if (options.probeMode === "full") {
    return options.maxEndpoints > 0
      ? `Full ≤${options.maxEndpoints} API`
      : "Full · api-tree 전체 API";
  }
  return `Sample · ${options.sampleSize} API`;
}

export function g61OptionsSummary(options: G61DiagnosisOptions): string {
  const parts: string[] = [
    options.useHttpx ? "httpx" : "no httpx",
    g61ScopeLabel(options),
    `httpx ${g61RequestCapLabel(options.maxRequests)}`,
    `timeout ${options.timeout}s`,
  ];
  if (options.useZap) {
    const zapParts: string[] = [];
    if (options.zapUnified) zapParts.push("unified");
    if (options.zapSupplemental) zapParts.push("90022/10023");
    parts.push(
      `ZAP ${zapParts.join("+") || "on"} · ${g61RequestCapLabel(options.zapMaxRequests)} · ${options.zapMaxMinutes}m`,
    );
  } else {
    parts.push("ZAP off");
  }
  return parts.join(" · ");
}
