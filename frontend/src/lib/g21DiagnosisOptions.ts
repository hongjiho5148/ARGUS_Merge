/** Per-run options for guideline 2-1 diagnosis (sent to POST /diagnosis/modules/2-1/run). */

export type G21DiagnosisPreset = "minimal" | "full" | "manual";

export interface G21DiagnosisOptions {
  useHttpx: boolean;
  useZap: boolean;
  maxTargets: number;
  zapPassiveWaitSeconds: number;
  intervalSec: number;       // 요청 간격(초) — 0: 제한 없음
  enableAuthModes: boolean;  // 인증 계정 패스 활성화
  maxRequests: number;       // 총 요청 한도 — 0: 무제한
}

/** 최소 검사 — httpx만, 최대 20개, ZAP OFF, 인증 패스 포함. */
export const MINIMAL_G21_OPTIONS: G21DiagnosisOptions = {
  useHttpx: true,
  useZap: false,
  maxTargets: 20,
  zapPassiveWaitSeconds: 60,
  intervalSec: 0,
  enableAuthModes: true,
  maxRequests: 0,
};

/** 전체 — httpx + ZAP, 최대 200개. */
export const FULL_G21_OPTIONS: G21DiagnosisOptions = {
  useHttpx: true,
  useZap: true,
  maxTargets: 200,
  zapPassiveWaitSeconds: 90,
  intervalSec: 0,
  enableAuthModes: true,
  maxRequests: 0,
};

export const DEFAULT_G21_OPTIONS = MINIMAL_G21_OPTIONS;

export function g21OptionsForPreset(preset: G21DiagnosisPreset): G21DiagnosisOptions {
  if (preset === "full") return { ...FULL_G21_OPTIONS };
  return { ...MINIMAL_G21_OPTIONS };
}

export const G21_PRESET_LABELS: Record<G21DiagnosisPreset, string> = {
  minimal: "최소 검사",
  full: "전체 검사",
  manual: "직접 입력",
};

export function g21OptionsToPayload(options: G21DiagnosisOptions) {
  const g21: Record<string, boolean | number | string[]> = {
    httpx_enabled: options.useHttpx,
    zap_enabled: options.useZap,
    max_targets: options.maxTargets,
    enable_auth_modes: options.enableAuthModes,
  };
  if (options.intervalSec > 0) {
    g21.interval_sec = options.intervalSec;
  }
  if (options.maxRequests > 0) {
    g21.max_requests = options.maxRequests;
  }
  if (options.useZap) {
    g21.zap_passive_wait_seconds = options.zapPassiveWaitSeconds;
  }
  return { g21 };
}

export function g21OptionsSummary(options: G21DiagnosisOptions): string {
  const parts: string[] = [`최대 대상 ${options.maxTargets}`];
  if (options.useHttpx) parts.push("httpx 확장자 우회·경로 탐지");
  if (options.useZap) parts.push(`ZAP 수동 supplemental (${options.zapPassiveWaitSeconds}s)`);
  if (!options.useHttpx && !options.useZap) parts.push("엔진 없음");
  if (!options.enableAuthModes) parts.push("인증 패스 비활성화");
  if (options.intervalSec > 0) parts.push(`요청 간격 ${options.intervalSec}s`);
  if (options.maxRequests > 0) parts.push(`최대 요청 ${options.maxRequests}`);
  return parts.join(" · ");
}
