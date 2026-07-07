/** Per-run options for guideline 3-2 diagnosis (POST /diagnosis/modules/3-2/run). */

export type G32DiagnosisPreset = "minimal" | "full" | "manual";

export interface G32DiagnosisOptions {
  maxAttempts: number;
  timeout: number;
  intervalSec: number;
  probeAccountEmail: string;
  strict: boolean;
  /** 0 = all login entries; positive = cap for smoke runs. */
  maxLoginEntries: number;
}

/** 동작 확인 — 첫 login 1개, 6회 시도, strict OFF. */
export const MINIMAL_G32_OPTIONS: G32DiagnosisOptions = {
  maxAttempts: 6,
  timeout: 8,
  intervalSec: 0.1,
  probeAccountEmail: "",
  strict: false,
  maxLoginEntries: 1,
};

/** 전수 — 모든 login entry, 25회, strict ON. */
export const FULL_G32_OPTIONS: G32DiagnosisOptions = {
  maxAttempts: 25,
  timeout: 10,
  intervalSec: 0.05,
  probeAccountEmail: "",
  strict: true,
  maxLoginEntries: 0,
};

export const DEFAULT_G32_OPTIONS = MINIMAL_G32_OPTIONS;

export function g32OptionsForPreset(preset: G32DiagnosisPreset): G32DiagnosisOptions {
  if (preset === "full") return { ...FULL_G32_OPTIONS };
  if (preset === "minimal") return { ...MINIMAL_G32_OPTIONS };
  return { ...MINIMAL_G32_OPTIONS };
}

export const G32_PRESET_LABELS: Record<G32DiagnosisPreset, string> = {
  minimal: "최소 진단",
  full: "전체 진단",
  manual: "수동 입력",
};

export function g32OptionsToPayload(options: G32DiagnosisOptions) {
  const g32: Record<string, boolean | number | string> = {
    max_attempts: options.maxAttempts,
    timeout: options.timeout,
    interval_sec: options.intervalSec,
    strict: options.strict,
    max_login_entries: options.maxLoginEntries,
  };
  const email = options.probeAccountEmail.trim();
  if (email) {
    g32.probe_account_email = email;
  }
  return { g32 };
}

export function g32OptionsSummary(options: G32DiagnosisOptions): string {
  const parts = [
    "httpx lockout",
    options.maxLoginEntries > 0 ? `login ${options.maxLoginEntries}` : "login 전체",
    `${options.maxAttempts} attempts`,
    options.strict ? "strict" : "standard",
    `timeout ${options.timeout}s`,
  ];
  if (options.probeAccountEmail.trim()) {
    parts.push(`account ${options.probeAccountEmail.trim()}`);
  } else {
    parts.push("auto account");
  }
  return parts.join(" · ");
}
