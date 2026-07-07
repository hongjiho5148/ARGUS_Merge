import type { G22DiagnosisOptions } from "../lib/g22DiagnosisOptions";

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

export function G22DiagnosisOptionsPanel({
  options,
  onChange,
  disabled,
}: {
  options: G22DiagnosisOptions;
  onChange: (next: G22DiagnosisOptions) => void;
  disabled?: boolean;
}) {
  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-cyber-border/40 bg-cyber-bg/30 p-3">
        <p className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">Targets</p>
        <Check
          label="api-tree 전체 확인"
          hint="해제: 2-2 점수 상위 N개. 체크: api-tree 전 행, 제한 없음"
          checked={options.scanAllInventory}
          disabled={disabled}
          onChange={(scanAllInventory) => onChange({ ...options, scanAllInventory })}
        />
      </div>
      <div className="rounded-xl border border-cyber-border/40 bg-cyber-bg/30 p-3">
        <p className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">Scan methods</p>
        <p className="mb-2 text-[10px] text-cyber-muted">설계 리뷰(후보 API · path/filename 파라미터)는 항상 실행됩니다.</p>
        <div className="grid gap-2 sm:grid-cols-2">
          <Check label="httpx probe" hint="traversal · forced browse wordlist" checked={options.useHttpx} disabled={disabled} onChange={(useHttpx) => onChange({ ...options, useHttpx, idorProbe: useHttpx || options.useZap ? options.idorProbe : false })} />
          <Check label="ZAP scan" hint="unified + native 0/40035 — Docker ZAP 필요" checked={options.useZap} disabled={disabled} onChange={(useZap) => onChange({ ...options, useZap, idorProbe: useZap || options.useHttpx ? options.idorProbe : false })} />
        </div>
        <div className="mt-2">
          <Check label="IDOR (cross-account)" hint="test-accounts 2개 이상" checked={options.idorProbe} disabled={disabled || (!options.useHttpx && !options.useZap)} onChange={(idorProbe) => onChange({ ...options, idorProbe })} />
        </div>
      </div>
      <div className="rounded-xl border border-cyber-border/40 bg-cyber-bg/30 p-3">
        <p className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">Limits</p>
        <div className="grid gap-3 sm:grid-cols-2">
          <NumField label="Max candidates" hint="2-2 후보 API 상한" value={options.maxCandidates} min={1} max={500} disabled={disabled || options.scanAllInventory} onChange={(maxCandidates) => onChange({ ...options, maxCandidates })} />
          <NumField label="ZAP max minutes" hint="Active scan 최대 대기" value={options.zapMaxMinutes} min={1} max={120} disabled={disabled || !options.useZap} onChange={(zapMaxMinutes) => onChange({ ...options, zapMaxMinutes })} />
        </div>
      </div>
    </div>
  );
}
