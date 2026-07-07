import type { G32DiagnosisOptions } from "../lib/g32DiagnosisOptions";

function Check({
  label,
  hint,
  checked,
  onChange,
}: {
  label: string;
  hint: string;
  checked: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <label
      className={`flex cursor-pointer items-start gap-2 rounded-lg border px-3 py-2 transition ${
        checked
          ? "border-cyan-400/40 bg-cyan-500/10"
          : "border-cyber-border/50 hover:border-cyber-border"
      }`}
    >
      <input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} className="mt-0.5 accent-cyan-400" />
      <span>
        <span className="block text-xs font-medium text-white">{label}</span>
        <span className="block text-[10px] leading-relaxed text-cyber-muted">{hint}</span>
      </span>
    </label>
  );
}

export function G32DiagnosisOptionsPanel({
  options,
  onChange,
}: {
  options: G32DiagnosisOptions;
  onChange: (next: G32DiagnosisOptions) => void;
}) {
  return (
    <div className="space-y-3">
      <p className="text-[10px] text-cyber-muted">
        각 로그인 URL에 대해 <strong className="text-white/80">동일 계정 + 틀린 비밀번호</strong>를
        연속 시도합니다. 계정 잠금·429·응답 변경이 없으면 fail.
        <strong className="mt-1 block text-amber-300/90">Test Account가 잠길 수 있습니다.</strong>
      </p>
      <label className="block">
        <span className="mb-1 block text-[10px] font-medium text-white">최대 실패 시도 횟수</span>
        <input type="number" min={3} max={25} value={options.maxAttempts} onChange={(e) => onChange({ ...options, maxAttempts: Number(e.target.value) })} className="w-full rounded-lg border border-cyber-border/60 bg-cyber-bg px-3 py-2 font-mono text-xs text-white" />
      </label>
      <label className="block">
        <span className="mb-1 block text-[10px] font-medium text-white">Login entry 상한</span>
        <span className="mb-1.5 block text-[10px] text-cyber-muted">0 = 전체 login URL</span>
        <input type="number" min={0} max={20} value={options.maxLoginEntries} onChange={(e) => onChange({ ...options, maxLoginEntries: Number(e.target.value) })} className="w-full rounded-lg border border-cyber-border/60 bg-cyber-bg px-3 py-2 font-mono text-xs text-white" />
      </label>
      <Check label="Strict 비교" hint="HTTP status·message·error code·body shape 변경까지 lockout 신호로 인정" checked={options.strict} onChange={(strict) => onChange({ ...options, strict })} />
      <label className="block">
        <span className="mb-1 block text-[10px] font-medium text-white">Probe 계정 이메일 (선택)</span>
        <input type="text" value={options.probeAccountEmail} onChange={(e) => onChange({ ...options, probeAccountEmail: e.target.value })} placeholder="lockout-probe@example.com" className="w-full rounded-lg border border-cyber-border/60 bg-cyber-bg px-3 py-2 font-mono text-xs text-white" />
      </label>
      <label className="block">
        <span className="mb-1 block text-[10px] font-medium text-white">시도 간격 (초)</span>
        <input type="number" min={0} max={2} step={0.05} value={options.intervalSec} onChange={(e) => onChange({ ...options, intervalSec: Number(e.target.value) })} className="w-full rounded-lg border border-cyber-border/60 bg-cyber-bg px-3 py-2 font-mono text-xs text-white" />
      </label>
      <label className="block">
        <span className="mb-1 block text-[10px] font-medium text-white">Timeout (초)</span>
        <input type="number" min={1} max={60} value={options.timeout} onChange={(e) => onChange({ ...options, timeout: Number(e.target.value) })} className="w-full rounded-lg border border-cyber-border/60 bg-cyber-bg px-3 py-2 font-mono text-xs text-white" />
      </label>
    </div>
  );
}
