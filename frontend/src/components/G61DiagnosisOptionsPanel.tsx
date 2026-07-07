import type { G61DiagnosisOptions, G61ProbeMode } from "../lib/g61DiagnosisOptions";

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
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        className="mt-0.5 accent-cyan-400"
      />
      <span>
        <span className="block text-xs font-medium text-white">{label}</span>
        <span className="block text-[10px] leading-relaxed text-cyber-muted">{hint}</span>
      </span>
    </label>
  );
}

function ProbeModeOption({
  mode,
  title,
  hint,
  selected,
  onSelect,
}: {
  mode: G61ProbeMode;
  title: string;
  hint: string;
  selected: boolean;
  onSelect: (mode: G61ProbeMode) => void;
}) {
  return (
    <label
      className={`flex cursor-pointer items-start gap-2 rounded-lg border px-3 py-2 transition ${
        selected
          ? "border-cyan-400/40 bg-cyan-500/10"
          : "border-cyber-border/50 hover:border-cyber-border"
      }`}
    >
      <input
        type="radio"
        name="g61-probe-mode"
        checked={selected}
        onChange={() => onSelect(mode)}
        className="mt-0.5 accent-cyan-400"
      />
      <span>
        <span className="block text-xs font-medium text-white">{title}</span>
        <span className="block text-[10px] leading-relaxed text-cyber-muted">{hint}</span>
      </span>
    </label>
  );
}

export function G61DiagnosisOptionsPanel({
  options,
  onChange,
}: {
  options: G61DiagnosisOptions;
  onChange: (next: G61DiagnosisOptions) => void;
}) {
  return (
    <div className="space-y-4">
      <p className="text-[10px] text-cyber-muted">
        오류페이지 정보 노출 — param/body/path/method/header 퍼징. max_requests=0 이면 무제한.
      </p>

      <div className="space-y-2">
        <p className="text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">범위</p>
        <ProbeModeOption
          mode="sample"
          title="Sample"
          hint="sample_size개 API 무작위 선택"
          selected={options.probeMode === "sample"}
          onSelect={(probeMode) => onChange({ ...options, probeMode })}
        />
        <ProbeModeOption
          mode="full"
          title="Full"
          hint="api-tree API 전체 (max_endpoints=0이면 상한 없음)"
          selected={options.probeMode === "full"}
          onSelect={(probeMode) => onChange({ ...options, probeMode })}
        />
      </div>

      <div className="grid grid-cols-2 gap-2">
        <label className="block text-[10px] text-cyber-muted">
          sample_size
          <input
            type="number"
            min={5}
            max={500}
            disabled={options.probeMode === "full"}
            value={options.sampleSize}
            onChange={(e) => onChange({ ...options, sampleSize: Number(e.target.value) })}
            className="mt-1 w-full rounded-lg border border-cyber-border/60 bg-cyber-bg px-2 py-1.5 text-xs text-white disabled:opacity-60"
          />
        </label>
        <label className="block text-[10px] text-cyber-muted">
          max_endpoints (0=무제한)
          <input
            type="number"
            min={0}
            max={500}
            value={options.maxEndpoints}
            onChange={(e) => onChange({ ...options, maxEndpoints: Number(e.target.value) })}
            className="mt-1 w-full rounded-lg border border-cyber-border/60 bg-cyber-bg px-2 py-1.5 text-xs text-white"
          />
        </label>
        <label className="block text-[10px] text-cyber-muted">
          max_requests (0=무제한)
          <input
            type="number"
            min={0}
            step={100}
            value={options.maxRequests}
            onChange={(e) => onChange({ ...options, maxRequests: Number(e.target.value) })}
            className="mt-1 w-full rounded-lg border border-cyber-border/60 bg-cyber-bg px-2 py-1.5 text-xs text-white"
          />
        </label>
        <label className="block text-[10px] text-cyber-muted">
          timeout (s)
          <input
            type="number"
            min={1}
            max={60}
            step={0.5}
            value={options.timeout}
            onChange={(e) => onChange({ ...options, timeout: Number(e.target.value) })}
            className="mt-1 w-full rounded-lg border border-cyber-border/60 bg-cyber-bg px-2 py-1.5 text-xs text-white"
          />
        </label>
      </div>

      <Check
        label="httpx Phase A (ARGUS fuzz)"
        hint="param/body/path/method/header 전수 퍼징"
        checked={options.useHttpx}
        onChange={(useHttpx) => onChange({ ...options, useHttpx })}
      />

      <div className="rounded-xl border border-violet-400/25 bg-violet-500/5 p-3 space-y-2">
        <p className="text-[10px] font-semibold uppercase tracking-wider text-violet-200/80">ZAP</p>
        <Check
          label="ZAP enabled"
          hint="ZapTransport 동일 fuzz + native rules"
          checked={options.useZap}
          onChange={(useZap) => onChange({ ...options, useZap })}
        />
        {options.useZap ? (
          <>
            <Check
              label="ZAP unified"
              hint="httpx와 동일 triggers"
              checked={options.zapUnified}
              onChange={(zapUnified) => onChange({ ...options, zapUnified })}
            />
            <Check
              label="ZAP supplemental (90022 + 10023)"
              hint="Native error disclosure rules"
              checked={options.zapSupplemental}
              onChange={(zapSupplemental) => onChange({ ...options, zapSupplemental })}
            />
            <div className="grid grid-cols-2 gap-2">
              <label className="block text-[10px] text-cyber-muted">
                zap_max_requests (0=무제한)
                <input
                  type="number"
                  min={0}
                  step={100}
                  value={options.zapMaxRequests}
                  onChange={(e) => onChange({ ...options, zapMaxRequests: Number(e.target.value) })}
                  className="mt-1 w-full rounded-lg border border-cyber-border/60 bg-cyber-bg px-2 py-1.5 text-xs text-white"
                />
              </label>
              <label className="block text-[10px] text-cyber-muted">
                zap_max_minutes
                <input
                  type="number"
                  min={1}
                  max={480}
                  value={options.zapMaxMinutes}
                  onChange={(e) => onChange({ ...options, zapMaxMinutes: Number(e.target.value) })}
                  className="mt-1 w-full rounded-lg border border-cyber-border/60 bg-cyber-bg px-2 py-1.5 text-xs text-white"
                />
              </label>
              <label className="col-span-2 block text-[10px] text-cyber-muted">
                zap_seed_cap (0=전체)
                <input
                  type="number"
                  min={0}
                  value={options.zapSeedCap}
                  onChange={(e) => onChange({ ...options, zapSeedCap: Number(e.target.value) })}
                  className="mt-1 w-full rounded-lg border border-cyber-border/60 bg-cyber-bg px-2 py-1.5 text-xs text-white"
                />
              </label>
            </div>
          </>
        ) : null}
      </div>
    </div>
  );
}
