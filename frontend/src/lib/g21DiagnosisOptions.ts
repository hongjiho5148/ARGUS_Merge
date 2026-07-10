/** Per-run options for guideline 2-1 diagnosis (sent to POST /diagnosis/modules/2-1/run). */

export type G21DiagnosisPreset = "minimal" | "full" | "manual";

export interface G21DiagnosisOptions {
  useHttpx: boolean;
  useZap: boolean;
  maxTargets: number;
  zapPassiveWaitSeconds: number;
}

/** 동작 확인 — httpx만, 대상 상위 20개, ZAP OFF. */
export const MINIMAL_G21_OPTIONS: G21DiagnosisOptions = {
  useHttpx: true,
  useZap: false,
  maxTargets: 20,
  zapPassiveWaitSeconds: 60,
};

/** 전수 — httpx + ZAP, 대상 상한 200개. */
export const FULL_G21_OPTIONS: G21DiagnosisOptions = {
  useHttpx: true,
  useZap: true,
  maxTargets: 200,
  zapPassiveWaitSeconds: 90,
};

export const DEFAULT_G21_OPTIONS = MINIMAL_G21_OPTIONS;

export function g21OptionsForPreset(preset: G21DiagnosisPreset): G21DiagnosisOptions {
  if (preset === "full") return { ...FULL_G21_OPTIONS };
  return { ...MINIMAL_G21_OPTIONS };
}

export const G21_PRESET_LABELS: Record<G21DiagnosisPreset, string> = {
  minimal: "최소 진단",
  full: "전체 진단",
  manual: "수동 입력",
};

export function g21OptionsToPayload(options: G21DiagnosisOptions) {
  const g21: Record<string, boolean | number> = {
    httpx_enabled: options.useHttpx,
    zap_enabled: options.useZap,
    max_targets: options.maxTargets,
  };
  if (options.useZap) {
    g21.zap_passive_wait_seconds = options.zapPassiveWaitSeconds;
  }
  return { g21 };
}

export function g21OptionsSummary(options: G21DiagnosisOptions): string {
  const parts: string[] = [`대상 상위 ${options.maxTargets}`];
  if (options.useHttpx) parts.push("httpx · 확장자 우회/경로 노출");
  if (options.useZap) parts.push(`ZAP · supplemental (${options.zapPassiveWaitSeconds}s)`);
  if (!options.useHttpx && !options.useZap) parts.push("엔진 없음");
  return parts.join(" · ");
}
