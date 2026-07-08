import { useState } from "react";
import { ChevronDown } from "lucide-react";
import { CollapsibleReportSection } from "./CollapsibleReportSection";
import {
    buildG73Matrix,
    formatG73HeaderLabel,
    groupG73ByBaseUrl,
    mergeG73Findings,
    truncateG73Value,
    type G73Finding,
    type G73MergedFinding,
    type G73MatrixCell,
} from "../../lib/g73ReportView";

const SEVERITY_STYLES: Record<string, string> = {
    high: "text-rose-300",
    medium: "text-amber-300",
    low: "text-sky-300",
    info: "text-cyber-muted",
};

const SEVERITY_VALUE_STYLES: Record<string, string> = {
    high: "text-rose-300/90",
    medium: "text-amber-300/90",
    low: "text-sky-300/80",
    info: "text-cyber-muted",
};

function SourceBadges({ sources }: { sources: ("httpx" | "zap")[] }) {
    if (sources.length === 0) return null;
    const label = sources.length > 1 ? "httpx+ZAP" : sources[0];
    return (
        <span className="rounded border border-cyber-border/40 bg-cyber-bg/50 px-1 py-px font-mono text-[9px] uppercase text-cyan-300/70">
            {label}
        </span>
    );
}

function MatrixValueCell({ cell }: { cell?: G73MatrixCell }) {
    if (!cell) {
        return <span className="text-cyber-muted/40">—</span>;
    }
    const cls = SEVERITY_VALUE_STYLES[cell.severity] ?? SEVERITY_VALUE_STYLES.info;
    const title = `${cell.value} · ${cell.severity} · ${cell.count} URL(s)`;
    return (
        <span className={`font-mono text-[10px] ${cls}`} title={title}>
            {truncateG73Value(cell.value, 16)}
        </span>
    );
}

function G73SummaryMatrix({ findings }: { findings: G73Finding[] }) {
    const { merged } = mergeG73Findings(findings);
    const { rows, columns } = buildG73Matrix(merged);
    if (rows.length === 0 || columns.length === 0) return null;

    return (
        <div className="mb-3 overflow-x-auto rounded-lg border border-cyber-border/50 bg-cyber-bg/20">
            <div className="border-b border-cyber-border/30 px-3 py-2">
                <span className="text-xs font-semibold text-white">헤더 노출 요약</span>
            </div>
            <table className="w-full min-w-[28rem] text-left text-[10px]">
                <thead>
                    <tr className="border-b border-cyber-border/20 text-cyber-muted">
                        <th className="px-3 py-1.5 font-normal">Base URL</th>
                        {columns.map((col) => (
                            <th key={col} className="px-2 py-1.5 text-center font-normal">
                                {formatG73HeaderLabel(col)}
                            </th>
                        ))}
                        <th className="px-3 py-1.5 text-right font-normal">영향 URL</th>
                    </tr>
                </thead>
                <tbody>
                    {rows.map((row) => (
                        <tr key={row.baseUrl} className="border-b border-cyber-border/10 last:border-0">
                            <td className="px-3 py-1.5 font-mono text-cyan-300/90">{row.displayLabel}</td>
                            {columns.map((col) => (
                                <td key={col} className="max-w-[7rem] px-2 py-1.5 text-center">
                                    <MatrixValueCell cell={row.cells[col]} />
                                </td>
                            ))}
                            <td className="px-3 py-1.5 text-right font-mono text-cyber-muted">
                                {row.maxAffectedCount > 0 ? row.maxAffectedCount : "—"}
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
}

function G73FindingDetail({ f }: { f: G73MergedFinding }) {
    const [showUrls, setShowUrls] = useState(false);

    return (
        <div className="mt-1.5 space-y-1 border-t border-cyber-border/20 pt-1.5 text-[10px]">
            <p>
                <span className="text-cyber-muted">Value · </span>
                <span className="font-mono text-amber-300/90">{f.headerValue}</span>
            </p>
            {f.remediation ? (
                <p>
                    <span className="text-cyber-muted">Remediation · </span>
                    <span className="text-cyan-300/80">{f.remediation}</span>
                </p>
            ) : null}
            {f.httpStatus != null ? (
                <p>
                    <span className="text-cyber-muted">HTTP · </span>
                    <span className="font-mono text-cyan-300/80">{String(f.httpStatus)}</span>
                </p>
            ) : null}
            {f.sampleUrl ? (
                <p className="break-all">
                    <span className="text-cyber-muted">Sample · </span>
                    <span className="font-mono text-cyan-300/80">{f.sampleUrl}</span>
                </p>
            ) : null}
            {f.affectedUrls.length > 1 ? (
                <div>
                    <button
                        type="button"
                        onClick={() => setShowUrls((v) => !v)}
                        className="text-cyan-400/80 hover:text-cyan-300"
                    >
                        {showUrls ? "URL 목록 접기" : `영향 URL ${f.affectedUrls.length}개 보기`}
                    </button>
                    {showUrls ? (
                        <ul className="mt-1 max-h-32 space-y-0.5 overflow-y-auto font-mono text-cyan-300/70">
                            {f.affectedUrls.map((u) => (
                                <li key={u} className="break-all">
                                    {u}
                                </li>
                            ))}
                        </ul>
                    ) : null}
                </div>
            ) : null}
        </div>
    );
}

function G73FindingRow({ f }: { f: G73MergedFinding }) {
    const [open, setOpen] = useState(false);
    const pages =
        f.affectedCount > 1 ? `${f.affectedCount} pages` : f.sampleUrl ? "1 page" : "";

    return (
        <li className="rounded border border-cyber-border/25 bg-cyber-panel/20 px-2.5 py-1.5">
            <button
                type="button"
                onClick={() => setOpen((v) => !v)}
                className="flex w-full items-start gap-2 text-left"
            >
                <ChevronDown
                    className={`mt-0.5 h-3.5 w-3.5 shrink-0 text-cyber-muted transition ${open ? "rotate-180" : ""}`}
                />
                <span
                    className={`shrink-0 font-mono text-[9px] uppercase ${SEVERITY_STYLES[f.severity] ?? SEVERITY_STYLES.info}`}
                >
                    {f.severity}
                </span>
                <span className="min-w-0 flex-1 text-xs text-white/90">
                    <span className="font-mono text-cyan-300/80">{formatG73HeaderLabel(f.header)}</span>
                    <span className="text-cyber-muted"> = </span>
                    <span className="font-mono text-amber-300/85">{truncateG73Value(f.headerValue, 40)}</span>
                    <span className="text-cyber-muted"> · </span>
                    <span className="text-white/70">{f.reasonLabel}</span>
                </span>
                {pages ? (
                    <span className="shrink-0 font-mono text-[10px] text-cyber-muted">{pages}</span>
                ) : null}
                <SourceBadges sources={f.sources} />
            </button>
            {open ? <G73FindingDetail f={f} /> : null}
        </li>
    );
}

function G73BaseUrlSection({ group }: { group: ReturnType<typeof groupG73ByBaseUrl>[number] }) {
    const [open, setOpen] = useState(false);
    const issueCount = group.findings.length;

    return (
        <div className="mb-2 overflow-hidden rounded-lg border border-cyber-border/40 bg-cyber-bg/15">
            <button
                type="button"
                onClick={() => setOpen((v) => !v)}
                className="flex w-full items-center gap-2 px-3 py-2 text-left transition hover:bg-cyber-accent/5"
            >
                <ChevronDown
                    className={`h-4 w-4 shrink-0 text-cyber-muted transition ${open ? "rotate-180" : ""}`}
                />
                <span className="font-mono text-xs text-cyan-300/90">{group.displayLabel}</span>
                <span className="text-[10px] text-cyber-muted">
                    {issueCount} header{issueCount !== 1 ? "s" : ""}
                    {group.maxAffectedCount > 0 ? ` · up to ${group.maxAffectedCount} URLs` : ""}
                </span>
            </button>
            {open ? (
                <ul className="space-y-1.5 border-t border-cyber-border/25 px-2 py-2">
                    {group.findings.map((f) => (
                        <G73FindingRow key={`${f.header}-${f.headerValue}-${f.reason}`} f={f} />
                    ))}
                </ul>
            ) : null}
        </div>
    );
}

function OtherFindingItem({
    f,
}: {
    f: { severity: string; message: string; evidence?: Record<string, unknown> };
}) {
    const err = f.evidence?.error;
    return (
        <li className="rounded border border-cyber-border/30 bg-cyber-panel/30 px-3 py-2">
            <div className="flex items-start gap-2">
                <span
                    className={`shrink-0 font-mono text-[10px] uppercase ${SEVERITY_STYLES[f.severity] ?? SEVERITY_STYLES.info}`}
                >
                    {f.severity}
                </span>
                <div className="min-w-0 flex-1">
                    <span className="text-xs text-white/90">{f.message}</span>
                    {err ? (
                        <p className="mt-1 font-mono text-[10px] text-cyber-muted">{String(err)}</p>
                    ) : null}
                </div>
            </div>
        </li>
    );
}

export function G73FindingsPanel({ findings }: { findings: G73Finding[] }) {
    const { merged, other } = mergeG73Findings(findings);
    const groups = groupG73ByBaseUrl(merged);

    if (findings.length === 0) {
        return <p className="text-xs text-cyber-muted">finding 없음</p>;
    }

    return (
        <>
            <G73SummaryMatrix findings={findings} />
            {groups.length > 0 ? (
                <CollapsibleReportSection title="상세 (origin별)">
                    {groups.map((g) => (
                        <G73BaseUrlSection key={g.baseUrl} group={g} />
                    ))}
                </CollapsibleReportSection>
            ) : null}
            {other.length > 0 ? (
                <CollapsibleReportSection title="기타">
                    <ul className="space-y-2">
                        {other.map((f, i) => (
                            <OtherFindingItem key={`other-${i}`} f={f} />
                        ))}
                    </ul>
                </CollapsibleReportSection>
            ) : null}
        </>
    );
}