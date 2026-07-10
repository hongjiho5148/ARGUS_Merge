import type { G21DiagnosisOptions } from "../lib/g21DiagnosisOptions";

function Check({
  label,
  hint,
  checked,
  disabled,
  onChange,
}: {
  label: string;
  hint: string;
  checked: boolean;
  disabled?: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <label
      className={`flex cursor-pointer items-start gap-2 rounded-lg border px-3 py-2 transition ${
        disabled
          ? "cursor-not-allowed border-cyber-border/30 opacity-40"
          : checked
            ? "border-cyan-400/40 bg-cyan-500/10"
            : "border-cyber-border/50 hover:border-cyber-border"
      }`}
    >
      <input type="checkbox" checked={checked} disabled={disabled} onChange={(e) => onChange(e.target.checked)} className="mt-0.5 accent-cyan-400" />
      <span>
        <span className="block text-xs font-medium text-white">{label}</span>
        <span className="block text-[10px] leading-relaxed text-cyber-muted">{hint}</span>
      </span>
    </label>
  );
}

function NumField({
  label,
  hint,
  value,
  min,
  max,
  disabled,
  onChange,
}: {
  label: string;
  hint: string;
  value: number;
  min: number;
  max: number;
  disabled?: boolean;
  onChange: (v: number) => void;
}) {
  return (
    <label className="block">
      <span className="mb-1 block text-[10px] font-medium text-white">{label}</span>
      <span className="mb-1.5 block text-[10px] text-cyber-muted">{hint}</span>
      <input type="number" min={min} max={max} disabled={disabled} value={value} onChange={(e) => onChange(Number(e.target.value))} className="w-full rounded-lg border border-cyber-border/60 bg-cyber-bg px-3 py-2 font-mono text-xs text-white disabled:opacity-40" />
    </label>
  );
}

export function G21DiagnosisOptionsPanel({
  options,
  onChange,
  disabled,
}: {
  options: G21DiagnosisOptions;
  onChange: (next: G21DiagnosisOptions) => void;
  disabled?: boolean;
}) {
  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-cyber-border/40 bg-cyber-bg/30 p-3">
        <p className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">Scan methods</p>
        <p className="mb-2 text-[10px] text-cyber-muted">
          업로드 대상은 config의 upload_endpoints 또는 api-tree 자동탐지로 결정됩니다.
        </p>
        <div className="grid gap-2 sm:grid-cols-2">
          <Check
            label="httpx probe"
            hint="악성 확장자 업로드 시도 및 경로/주소 노출 탐지"
            checked={options.useHttpx}
            disabled={disabled}
            onChange={(useHttpx) => onChange({ ...options, useHttpx })}
          />
          <Check
            label="ZAP scan"
            hint="수동 스캔 + native supplemental — Docker ZAP 필요"
            checked={options.useZap}
            disabled={disabled}
            onChange={(useZap) => onChange({ ...options, useZap })}
          />
        </div>
      </div>

      <div className="rounded-xl border border-cyber-border/40 bg-cyber-bg/30 p-3">
        <p className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">Auth</p>
        <Check
          label="인증 패스 활성화 (enable_auth_modes)"
          hint="테스트 계정이 등록된 경우 anonymous 외에 인증된 사용자 패스도 실행"
          checked={options.enableAuthModes}
          disabled={disabled}
          onChange={(enableAuthModes) => onChange({ ...options, enableAuthModes })}
        />
      </div>

      <div className="rounded-xl border border-cyber-border/40 bg-cyber-bg/30 p-3">
        <p className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">Limits</p>
        <div className="grid gap-3 sm:grid-cols-2">
          <NumField
            label="Max targets"
            hint="업로드 대상 엔드포인트 수 상한"
            value={options.maxTargets}
            min={1}
            max={200}
            disabled={disabled}
            onChange={(maxTargets) => onChange({ ...options, maxTargets })}
          />
          <NumField
            label="Max requests (0=무제한)"
            hint="전체 요청 총량 한도 — 초과 시 중단"
            value={options.maxRequests}
            min={0}
            max={10000}
            disabled={disabled}
            onChange={(maxRequests) => onChange({ ...options, maxRequests })}
          />
          <NumField
            label="Interval (sec)"
            hint="요청 간 대기 시간 — rate-limit 대응 (0=없음)"
            value={options.intervalSec}
            min={0}
            max={5}
            disabled={disabled}
            onChange={(intervalSec) => onChange({ ...options, intervalSec })}
          />
          <NumField
            label="ZAP passive wait (sec)"
            hint="ZAP 수동스캔 채널 대기 시간"
            value={options.zapPassiveWaitSeconds}
            min={0}
            max={300}
            disabled={disabled || !options.useZap}
            onChange={(zapPassiveWaitSeconds) => onChange({ ...options, zapPassiveWaitSeconds })}
          />
        </div>
      </div>
    </div>
  );
}
