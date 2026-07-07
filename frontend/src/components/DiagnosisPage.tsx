import { useCallback, useEffect, useMemo, useState } from "react";
import { AlertCircle, ChevronDown, Loader2, Stethoscope } from "lucide-react";
import { G12DiagnosisStartDialog } from "./G12DiagnosisStartDialog";
import { G32DiagnosisStartDialog } from "./G32DiagnosisStartDialog";
import { G34DiagnosisStartDialog } from "./G34DiagnosisStartDialog";
import { G35DiagnosisStartDialog } from "./G35DiagnosisStartDialog";
import { G36DiagnosisStartDialog } from "./G36DiagnosisStartDialog";
import { G42DiagnosisStartDialog } from "./G42DiagnosisStartDialog";
import { G15DiagnosisStartDialog } from "./G15DiagnosisStartDialog";
import { G41DiagnosisStartDialog } from "./G41DiagnosisStartDialog";
import { G52DiagnosisStartDialog } from "./G52DiagnosisStartDialog";
import { G61DiagnosisStartDialog } from "./G61DiagnosisStartDialog";
import { G62DiagnosisStartDialog } from "./G62DiagnosisStartDialog";
import { G71DiagnosisStartDialog } from "./G71DiagnosisStartDialog";
import { G22DiagnosisStartDialog } from "./G22DiagnosisStartDialog";
import { G72DiagnosisStartDialog } from "./G72DiagnosisStartDialog";
import { G73DiagnosisStartDialog } from "./G73DiagnosisStartDialog";
import { G74DiagnosisStartDialog } from "./G74DiagnosisStartDialog";
import { fetchDiagnosisCatalog, fetchDiagnosisProgress, fetchDiagnosisReport, runDiagnosisSection } from "../lib/api";
import {
  DEFAULT_G12_OPTIONS,
  g12OptionsSummary,
  g12OptionsToPayload,
  type G12DiagnosisOptions,
} from "../lib/g12DiagnosisOptions";
import {
  DEFAULT_G15_OPTIONS,
  g15OptionsSummary,
  g15OptionsToPayload,
  type G15DiagnosisOptions,
} from "../lib/g15DiagnosisOptions";
import {
  DEFAULT_G41_OPTIONS,
  g41OptionsSummary,
  g41OptionsToPayload,
  type G41DiagnosisOptions,
} from "../lib/g41DiagnosisOptions";
import {
  DEFAULT_G22_OPTIONS,
  g22OptionsSummary,
  g22OptionsToPayload,
  type G22DiagnosisOptions,
} from "../lib/g22DiagnosisOptions";
import {
  DEFAULT_G52_OPTIONS,
  g52OptionsToPayload,
  g52OptionsSummary,
  type G52DiagnosisOptions,
} from "../lib/g52DiagnosisOptions";
import {
  DEFAULT_G61_OPTIONS,
  g61OptionsToPayload,
  g61OptionsSummary,
  type G61DiagnosisOptions,
} from "../lib/g61DiagnosisOptions";
import {
  DEFAULT_G62_OPTIONS,
  g62OptionsToPayload,
  g62OptionsSummary,
  type G62DiagnosisOptions,
} from "../lib/g62DiagnosisOptions";
import {
  DEFAULT_G32_OPTIONS,
  g32OptionsToPayload,
  g32OptionsSummary,
  type G32DiagnosisOptions,
} from "../lib/g32DiagnosisOptions";
import {
  DEFAULT_G34_OPTIONS,
  g34OptionsToPayload,
  g34OptionsSummary,
  type G34DiagnosisOptions,
} from "../lib/g34DiagnosisOptions";
import {
  DEFAULT_G35_OPTIONS,
  g35OptionsToPayload,
  g35OptionsSummary,
  type G35DiagnosisOptions,
} from "../lib/g35DiagnosisOptions";
import {
  DEFAULT_G36_OPTIONS,
  g36OptionsToPayload,
  g36OptionsSummary,
  type G36DiagnosisOptions,
} from "../lib/g36DiagnosisOptions";
import {
  DEFAULT_G42_OPTIONS,
  g42OptionsToPayload,
  g42OptionsSummary,
  type G42DiagnosisOptions,
} from "../lib/g42DiagnosisOptions";
import {
  DEFAULT_G72_OPTIONS,
  g72OptionsToPayload,
  g72OptionsSummary,
  type G72DiagnosisOptions,
} from "../lib/g72DiagnosisOptions";
import {
  DEFAULT_G71_OPTIONS,
  g71OptionsToPayload,
  g71OptionsSummary,
  type G71DiagnosisOptions,
} from "../lib/g71DiagnosisOptions";
import {
  DEFAULT_G73_OPTIONS,
  g73OptionsToPayload,
  g73OptionsSummary,
  type G73DiagnosisOptions,
} from "../lib/g73DiagnosisOptions";
import {
  DEFAULT_G74_OPTIONS,
  g74OptionsToPayload,
  g74OptionsSummary,
  type G74DiagnosisOptions,
} from "../lib/g74DiagnosisOptions";
import { GUIDELINE_SECTIONS } from "../lib/guidelineSections";
import type { DiagnosisCatalogModule, DiagnosisProgressResponse, DiagnosisSectionReport } from "../types";
import { useProgressPoll } from "../hooks/useProgressPoll";
import { DiagnosisReportPanel, StatusBadge } from "./diagnosis/DiagnosisReportPanel";

const START_BTN =
  "flex shrink-0 items-center gap-1 rounded-lg border font-semibold transition disabled:cursor-not-allowed disabled:opacity-40";

const START_BTN_ACTIVE =
  "border-cyan-400/50 bg-cyan-500/15 text-cyan-300 hover:bg-cyan-500/25";

const START_BTN_IDLE =
  "border-cyber-border/60 bg-cyber-bg/40 text-cyber-muted hover:border-cyber-border hover:text-cyber-muted";

const UNAVAILABLE_BTN =
  "border-amber-400/50 bg-amber-500/15 text-amber-300 cursor-not-allowed";

function progressRatio(progress: DiagnosisProgressResponse): number {
  if (progress.endpoints_total > 0) {
    return Math.min(
      100,
      Math.max(0, Math.round((progress.endpoints_done * 100) / progress.endpoints_total)),
    );
  }
  return Math.min(100, Math.max(0, progress.percent));
}

function progressLabel(progress: DiagnosisProgressResponse): string {
  const ratio = progressRatio(progress);
  if (progress.phase === "zap") {
    const count =
      progress.endpoints_total > 0
        ? ` · ${progress.endpoints_done}/${progress.endpoints_total}`
        : "";
    return `ZAP ${ratio}%${count}`;
  }
  if (progress.phase === "zap_verify") {
    const count =
      progress.endpoints_total > 0
        ? ` · alert ${progress.endpoints_done}/${progress.endpoints_total}`
        : "";
    return `ZAP 검증 ${ratio}%${count}`;
  }
  if (progress.phase === "injector") {
    const count =
      progress.endpoints_total > 0
        ? ` · Direct ${progress.endpoints_done}/${progress.endpoints_total}`
        : "";
    return `Direct ${ratio}%${count}`;
  }
  return `${ratio}%`;
}

function DiagnosisStartButton({
  compact = false,
  disabled,
  loading,
  implemented,
  onClick,
}: {
  compact?: boolean;
  disabled?: boolean;
  loading?: boolean;
  implemented?: boolean;
  onClick?: () => void;
}) {
  const style = implemented ? START_BTN_ACTIVE : START_BTN_IDLE;
  return (
    <button
      type="button"
      disabled={disabled || loading}
      onClick={onClick}
      title={
        !implemented
          ? "아직 구현되지 않은 항목입니다"
          : loading
            ? "진단 실행 중…"
            : "이 항목 진단 시작"
      }
      className={`${START_BTN} ${style} ${compact ? "px-2.5 py-1 text-[10px]" : "px-4 py-1.5 text-xs"}`}
    >
      {loading ? (
        <Loader2 className={`animate-spin ${compact ? "h-3 w-3" : "h-3.5 w-3.5"}`} />
      ) : (
        <Stethoscope className={compact ? "h-3 w-3" : "h-3.5 w-3.5"} />
      )}
      {loading ? "실행 중…" : "진단 시작"}
    </button>
  );
}

function DiagnosisReviewLaterButton({ compact = false }: { compact?: boolean }) {
  return (
    <button
      type="button"
      disabled
      title="추후 검토 항목"
      className={`${START_BTN} ${UNAVAILABLE_BTN} ${compact ? "px-2.5 py-1 text-[10px]" : "px-4 py-1.5 text-xs"}`}
    >
      <AlertCircle className={compact ? "h-3 w-3" : "h-3.5 w-3.5"} />
      추후 검토
    </button>
  );
}

function DiagnosisManualCheckButton({
  label,
  compact = false,
}: {
  label: string;
  compact?: boolean;
}) {
  return (
    <button
      type="button"
      disabled
      title={label}
      className={`${START_BTN} ${UNAVAILABLE_BTN} ${compact ? "px-2.5 py-1 text-[10px]" : "px-4 py-1.5 text-xs"}`}
    >
      <AlertCircle className={compact ? "h-3 w-3" : "h-3.5 w-3.5"} />
      {label}
    </button>
  );
}

function moduleBadgeLabel(mod: {
  implemented: boolean;
  diagnosable: boolean;
  review_later: boolean;
  status_label: string | null;
  engine: string;
}): string | null {
  if (mod.implemented) return mod.engine;
  if (mod.status_label || mod.review_later) return null;
  if (!mod.diagnosable) return "미구현";
  return mod.engine !== "pending" ? mod.engine : "미구현";
}


export function DiagnosisPage() {
  const [openId, setOpenId] = useState<string | null>(null);
  const [catalog, setCatalog] = useState<Record<string, DiagnosisCatalogModule>>({});
  const [reports, setReports] = useState<Record<string, DiagnosisSectionReport>>({});
  const [runningId, setRunningId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [g12DialogOpen, setG12DialogOpen] = useState(false);
  const [g12Options, setG12Options] = useState<G12DiagnosisOptions>(DEFAULT_G12_OPTIONS);
  const [g15DialogOpen, setG15DialogOpen] = useState(false);
  const [g15Options, setG15Options] = useState<G15DiagnosisOptions>(DEFAULT_G15_OPTIONS);
  const [g41DialogOpen, setG41DialogOpen] = useState(false);
  const [g41Options, setG41Options] = useState<G41DiagnosisOptions>(DEFAULT_G41_OPTIONS);
  const [g22DialogOpen, setG22DialogOpen] = useState(false);
  const [g22Options, setG22Options] = useState<G22DiagnosisOptions>(DEFAULT_G22_OPTIONS);
  const [g72DialogOpen, setG72DialogOpen] = useState(false);
  const [g72Options, setG72Options] = useState<G72DiagnosisOptions>(DEFAULT_G72_OPTIONS);
  const [g71DialogOpen, setG71DialogOpen] = useState(false);
  const [g71Options, setG71Options] = useState<G71DiagnosisOptions>(DEFAULT_G71_OPTIONS);
  const [g73DialogOpen, setG73DialogOpen] = useState(false);
  const [g73Options, setG73Options] = useState<G73DiagnosisOptions>(DEFAULT_G73_OPTIONS);
  const [g74DialogOpen, setG74DialogOpen] = useState(false);
  const [g74Options, setG74Options] = useState<G74DiagnosisOptions>(DEFAULT_G74_OPTIONS);
  const [g32DialogOpen, setG32DialogOpen] = useState(false);
  const [g32Options, setG32Options] = useState<G32DiagnosisOptions>(DEFAULT_G32_OPTIONS);
  const [g34DialogOpen, setG34DialogOpen] = useState(false);
  const [g34Options, setG34Options] = useState<G34DiagnosisOptions>(DEFAULT_G34_OPTIONS);
  const [g35DialogOpen, setG35DialogOpen] = useState(false);
  const [g35Options, setG35Options] = useState<G35DiagnosisOptions>(DEFAULT_G35_OPTIONS);
  const [g36DialogOpen, setG36DialogOpen] = useState(false);
  const [g36Options, setG36Options] = useState<G36DiagnosisOptions>(DEFAULT_G36_OPTIONS);
  const [g42DialogOpen, setG42DialogOpen] = useState(false);
  const [g42Options, setG42Options] = useState<G42DiagnosisOptions>(DEFAULT_G42_OPTIONS);
  const [g52DialogOpen, setG52DialogOpen] = useState(false);
  const [g52Options, setG52Options] = useState<G52DiagnosisOptions>(DEFAULT_G52_OPTIONS);
  const [g61DialogOpen, setG61DialogOpen] = useState(false);
  const [g61Options, setG61Options] = useState<G61DiagnosisOptions>(DEFAULT_G61_OPTIONS);
  const [g62DialogOpen, setG62DialogOpen] = useState(false);
  const [g62Options, setG62Options] = useState<G62DiagnosisOptions>(DEFAULT_G62_OPTIONS);
  const [runningSummary, setRunningSummary] = useState<string | null>(null);
  const [runProgress, setRunProgress] = useState<DiagnosisProgressResponse | null>(null);

  useEffect(() => {
    fetchDiagnosisCatalog()
      .then((res) => {
        const map: Record<string, DiagnosisCatalogModule> = {};
        for (const m of res.modules) map[m.id] = m;
        setCatalog(map);
      })
      .catch((e: Error) => setError(e.message));
  }, []);

  const catalogById = useMemo(() => catalog, [catalog]);

  const loadReport = useCallback(async (sectionId: string) => {
    try {
      const report = await fetchDiagnosisReport(sectionId);
      setReports((prev) => ({ ...prev, [sectionId]: report }));
    } catch {
      /* no saved report yet */
    }
  }, []);

  const handleProgressUpdate = useCallback(
    (p: DiagnosisProgressResponse) => {
      if (p.running && p.section_id) {
        setRunningId(p.section_id);
        setOpenId(p.section_id);
        setRunProgress(p);
        return;
      }
      setRunProgress(p);
      setRunningId(null);
      setRunningSummary(null);
      if (p.section_id) void loadReport(p.section_id);
    },
    [loadReport],
  );

  useProgressPoll(
    true,
    fetchDiagnosisProgress,
    handleProgressUpdate,
    1200,
  );

  const handleToggle = useCallback(
    (sectionId: string) => {
      setOpenId((prev) => {
        const next = prev === sectionId ? null : sectionId;
        if (next) void loadReport(sectionId);
        return next;
      });
    },
    [loadReport],
  );

  const handleRun = useCallback(
    async (
      sectionId: string,
      options?: G12DiagnosisOptions | G15DiagnosisOptions | G41DiagnosisOptions | G42DiagnosisOptions | G22DiagnosisOptions | G32DiagnosisOptions | G34DiagnosisOptions | G35DiagnosisOptions | G36DiagnosisOptions | G52DiagnosisOptions | G61DiagnosisOptions | G62DiagnosisOptions | G71DiagnosisOptions | G72DiagnosisOptions | G73DiagnosisOptions | G74DiagnosisOptions,
    ) => {
      const mod = catalogById[sectionId];
      if (!mod?.diagnosable || !mod?.implemented) return;

      setError(null);
      setRunningId(sectionId);
      setOpenId(sectionId);
      if (sectionId === "1-2" && options && "useDirect" in options) {
        setRunningSummary(g12OptionsSummary(options as G12DiagnosisOptions));
      } else if (sectionId === "1-5" && options && "corsEnabled" in options) {
        setRunningSummary(g15OptionsSummary(options as G15DiagnosisOptions));
      } else if (sectionId === "4-1" && options && "crossCookieEnabled" in options) {
        setRunningSummary(g41OptionsSummary(options as G41DiagnosisOptions));
      } else if (sectionId === "4-2" && options && "reloginEnabled" in options) {
        setRunningSummary(g42OptionsSummary(options as G42DiagnosisOptions));
      } else if (sectionId === "2-2" && options && "useHttpx" in options) {
        setRunningSummary(g22OptionsSummary(options as G22DiagnosisOptions));
      } else if (sectionId === "7-1" && options && "strictRisky" in options) {
        setRunningSummary(g71OptionsSummary(options as G71DiagnosisOptions));
      } else if (sectionId === "3-2" && options && "maxAttempts" in options) {
        setRunningSummary(g32OptionsSummary(options as G32DiagnosisOptions));
      } else if (sectionId === "3-4" && options && "inventoryScope" in options) {
        setRunningSummary(g34OptionsSummary(options as G34DiagnosisOptions));
      } else if (sectionId === "3-5" && options && "probeMode" in options && !("requireRobotsTxt" in options)) {
        setRunningSummary(g35OptionsSummary(options as G35DiagnosisOptions));
      } else if (sectionId === "3-6" && options && "probeMode" in options && !("requireRobotsTxt" in options)) {
        setRunningSummary(g36OptionsSummary(options as G36DiagnosisOptions));
      } else if (sectionId === "7-2" && options && "probeMode" in options) {
        setRunningSummary(g72OptionsSummary(options as G72DiagnosisOptions));
      } else if (sectionId === "7-3" && options && "strict" in options && "includeCdnHeaders" in options) {
        setRunningSummary(g73OptionsSummary(options as G73DiagnosisOptions));
      } else if (sectionId === "5-2" && options && "checkResponseBody" in options) {
        setRunningSummary(g52OptionsSummary(options as G52DiagnosisOptions));
      } else if (sectionId === "6-1" && options && "maxRequests" in options) {
        setRunningSummary(g61OptionsSummary(options as G61DiagnosisOptions));
      } else if (sectionId === "6-2" && options && "probeAccountEmail" in options) {
        setRunningSummary(g62OptionsSummary(options as G62DiagnosisOptions));
      } else if (sectionId === "7-4" && options && "checkCookies" in options) {
        setRunningSummary(g74OptionsSummary(options as G74DiagnosisOptions));
      } else {
        setRunningSummary(null);
      }

      setRunProgress(null);

      try {
        let body;
        if (sectionId === "1-2" && options && "useDirect" in options) {
          body = g12OptionsToPayload(options as G12DiagnosisOptions);
        } else if (sectionId === "1-5" && options && "corsEnabled" in options) {
          body = g15OptionsToPayload(options as G15DiagnosisOptions);
        } else if (sectionId === "4-1" && options && "crossCookieEnabled" in options) {
          body = g41OptionsToPayload(options as G41DiagnosisOptions);
        } else if (sectionId === "4-2" && options && "reloginEnabled" in options) {
          body = g42OptionsToPayload(options as G42DiagnosisOptions);
        } else if (sectionId === "2-2" && options && "useHttpx" in options) {
          body = g22OptionsToPayload(options as G22DiagnosisOptions);
        } else if (sectionId === "7-1" && options && "strictRisky" in options) {
          body = g71OptionsToPayload(options as G71DiagnosisOptions);
        } else if (sectionId === "3-2" && options && "maxAttempts" in options) {
          body = g32OptionsToPayload(options as G32DiagnosisOptions);
        } else if (sectionId === "3-4" && options && "inventoryScope" in options) {
          body = g34OptionsToPayload(options as G34DiagnosisOptions);
        } else if (sectionId === "3-5" && options && "probeMode" in options && !("requireRobotsTxt" in options)) {
          body = g35OptionsToPayload(options as G35DiagnosisOptions);
        } else if (sectionId === "3-6" && options && "probeMode" in options && !("requireRobotsTxt" in options)) {
          body = g36OptionsToPayload(options as G36DiagnosisOptions);
        } else if (sectionId === "7-2" && options && "probeMode" in options) {
          body = g72OptionsToPayload(options as G72DiagnosisOptions);
        } else if (sectionId === "7-3" && options && "strict" in options && "includeCdnHeaders" in options) {
          body = g73OptionsToPayload(options as G73DiagnosisOptions);
        } else if (sectionId === "5-2" && options && "checkResponseBody" in options) {
          body = g52OptionsToPayload(options as G52DiagnosisOptions);
        } else if (sectionId === "6-1" && options && "maxRequests" in options) {
          body = g61OptionsToPayload(options as G61DiagnosisOptions);
        } else if (sectionId === "6-2" && options && "probeAccountEmail" in options) {
          body = g62OptionsToPayload(options as G62DiagnosisOptions);
        } else if (sectionId === "7-4" && options && "checkCookies" in options) {
          body = g74OptionsToPayload(options as G74DiagnosisOptions);
        }
        const res = await runDiagnosisSection(sectionId, body);
        setReports((prev) => ({ ...prev, [sectionId]: res.report }));
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      } finally {
        setRunningId(null);
        setRunningSummary(null);
        setRunProgress(null);
      }
    },
    [catalogById],
  );

  const handleStartClick = useCallback(
    (sectionId: string) => {
      const mod = catalogById[sectionId];
      if (!mod?.diagnosable || !mod?.implemented || runningId) return;
      if (sectionId === "1-2") {
        setG12DialogOpen(true);
        return;
      }
      if (sectionId === "1-5") {
        setG15DialogOpen(true);
        return;
      }
      if (sectionId === "4-1") {
        setG41DialogOpen(true);
        return;
      }
      if (sectionId === "4-2") {
        setG42DialogOpen(true);
        return;
      }
      if (sectionId === "2-2") {
        setG22DialogOpen(true);
        return;
      }
      if (sectionId === "3-2") {
        setG32DialogOpen(true);
        return;
      }
      if (sectionId === "3-4") {
        setG34DialogOpen(true);
        return;
      }
      if (sectionId === "3-5") {
        setG35DialogOpen(true);
        return;
      }
      if (sectionId === "3-6") {
        setG36DialogOpen(true);
        return;
      }
      if (sectionId === "5-2") {
        setG52DialogOpen(true);
        return;
      }
      if (sectionId === "6-1") {
        setG61DialogOpen(true);
        return;
      }
      if (sectionId === "6-2") {
        setG62DialogOpen(true);
        return;
      }
      if (sectionId === "7-1") {
        setG71DialogOpen(true);
        return;
      }
      if (sectionId === "7-2") {
        setG72DialogOpen(true);
        return;
      }
      if (sectionId === "7-3") {
        setG73DialogOpen(true);
        return;
      }
      if (sectionId === "7-4") {
        setG74DialogOpen(true);
        return;
      }
      void handleRun(sectionId);
    },
    [catalogById, handleRun, runningId],
  );

  const handleG12Start = useCallback(
    (options: G12DiagnosisOptions) => {
      setG12Options(options);
      setG12DialogOpen(false);
      void handleRun("1-2", options);
    },
    [handleRun],
  );

  const handleG15Start = useCallback(
    (options: G15DiagnosisOptions) => {
      setG15Options(options);
      setG15DialogOpen(false);
      void handleRun("1-5", options);
    },
    [handleRun],
  );

  const handleG41Start = useCallback(
    (options: G41DiagnosisOptions) => {
      setG41Options(options);
      setG41DialogOpen(false);
      void handleRun("4-1", options);
    },
    [handleRun],
  );

  const handleG34Start = useCallback(
    (options: G34DiagnosisOptions) => {
      setG34Options(options);
      setG34DialogOpen(false);
      void handleRun("3-4", options);
    },
    [handleRun],
  );

  const handleG42Start = useCallback(
    (options: G42DiagnosisOptions) => {
      setG42Options(options);
      setG42DialogOpen(false);
      void handleRun("4-2", options);
    },
    [handleRun],
  );

  const handleG32Start = useCallback(
    (options: G32DiagnosisOptions) => {
      setG32Options(options);
      setG32DialogOpen(false);
      void handleRun("3-2", options);
    },
    [handleRun],
  );

  const handleG35Start = useCallback(
    (options: G35DiagnosisOptions) => {
      setG35Options(options);
      setG35DialogOpen(false);
      void handleRun("3-5", options);
    },
    [handleRun],
  );

  const handleG36Start = useCallback(
    (options: G36DiagnosisOptions) => {
      setG36Options(options);
      setG36DialogOpen(false);
      void handleRun("3-6", options);
    },
    [handleRun],
  );

  const handleG52Start = useCallback(
    (options: G52DiagnosisOptions) => {
      setG52Options(options);
      setG52DialogOpen(false);
      void handleRun("5-2", options);
    },
    [handleRun],
  );

  const handleG61Start = useCallback(
    (options: G61DiagnosisOptions) => {
      setG61Options(options);
      setG61DialogOpen(false);
      void handleRun("6-1", options);
    },
    [handleRun],
  );

  const handleG62Start = useCallback(
    (options: G62DiagnosisOptions) => {
      setG62Options(options);
      setG62DialogOpen(false);
      void handleRun("6-2", options);
    },
    [handleRun],
  );

  const handleG22Start = useCallback(
    (options: G22DiagnosisOptions) => {
      setG22Options(options);
      setG22DialogOpen(false);
      void handleRun("2-2", options);
    },
    [handleRun],
  );

  const handleG71Start = useCallback(
    (options: G71DiagnosisOptions) => {
      setG71Options(options);
      setG71DialogOpen(false);
      void handleRun("7-1", options);
    },
    [handleRun],
  );

  const handleG72Start = useCallback(
    (options: G72DiagnosisOptions) => {
      setG72Options(options);
      setG72DialogOpen(false);
      void handleRun("7-2", options);
    },
    [handleRun],
  );

  const handleG73Start = useCallback(
    (options: G73DiagnosisOptions) => {
      setG73Options(options);
      setG73DialogOpen(false);
      void handleRun("7-3", options);
    },
    [handleRun],
  );

  const handleG74Start = useCallback(
    (options: G74DiagnosisOptions) => {
      setG74Options(options);
      setG74DialogOpen(false);
      void handleRun("7-4", options);
    },
    [handleRun],
  );

  const chapters = Array.from(new Set(GUIDELINE_SECTIONS.map((s) => s.chapter))).sort(
    (a, b) => a - b,
  );

  return (
    <div className="flex-1 overflow-y-auto p-8">
      <div className="mb-8 flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="font-display text-xl font-semibold text-white">Diagnosis</h2>
        </div>
      </div>

      {error ? (
        <div className="mb-4 flex items-start gap-2 rounded-lg border border-rose-400/40 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">
          <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
          <span>{error}</span>
        </div>
      ) : null}

      <div className="space-y-6">
        {chapters.map((chapter) => (
          <section key={chapter}>
            <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-cyber-muted">
              Chapter {chapter}
            </h3>
            <div className="overflow-hidden rounded-lg border border-cyber-border/60">
              {GUIDELINE_SECTIONS.filter((s) => s.chapter === chapter).map((section) => {
                const open = openId === section.id;
                const mod = catalogById[section.id];
                const implemented = mod?.implemented ?? false;
                const diagnosable = mod?.diagnosable ?? true;
                const reviewLater = mod?.review_later ?? false;
                const statusLabel = mod?.status_label ?? null;
                const running = runningId === section.id;
                const report = reports[section.id];
                const badgeLabel = mod
                  ? moduleBadgeLabel({
                      implemented,
                      diagnosable,
                      review_later: reviewLater,
                      status_label: statusLabel,
                      engine: mod.engine,
                    })
                  : null;

                return (
                  <div key={section.id} className="border-b border-cyber-border/40 last:border-b-0">
                    <div className="flex items-center gap-2 px-4 py-3 transition hover:bg-cyber-accent/5">
                      <button
                        type="button"
                        onClick={() => handleToggle(section.id)}
                        className="flex min-w-0 flex-1 items-center gap-3 text-left"
                      >
                        <span className="shrink-0 rounded border border-cyber-border/60 bg-cyber-bg px-2 py-0.5 font-mono text-[11px] text-cyber-accent">
                          {section.id}
                        </span>
                        <span className="flex-1 text-sm text-white">{section.title}</span>
                        {badgeLabel ? (
                          <span
                            className={`shrink-0 rounded px-1.5 py-0.5 font-mono text-[9px] ${
                              implemented
                                ? "bg-cyan-500/15 text-cyan-300"
                                : "bg-cyber-bg text-cyber-muted"
                            }`}
                          >
                            {badgeLabel}
                          </span>
                        ) : null}
                        {report ? <StatusBadge status={report.status} /> : null}
                      </button>
                      {reviewLater || (!diagnosable && !statusLabel) ? (
                        <DiagnosisReviewLaterButton compact />
                      ) : statusLabel ? (
                        <DiagnosisManualCheckButton label={statusLabel} compact />
                      ) : !diagnosable ? (
                        <DiagnosisReviewLaterButton compact />
                      ) : (
                        <DiagnosisStartButton
                          compact
                          implemented={implemented}
                          loading={running}
                          disabled={!implemented || runningId !== null}
                          onClick={() => handleStartClick(section.id)}
                        />
                      )}
                      <button
                        type="button"
                        onClick={() => handleToggle(section.id)}
                        className="shrink-0 rounded p-1 text-cyber-muted transition hover:text-white"
                        aria-label={open ? "접기" : "펼치기"}
                      >
                        <ChevronDown
                          className={`h-4 w-4 transition ${open ? "rotate-180" : ""}`}
                        />
                      </button>
                    </div>
                    {open && running ? (
                      <div className="space-y-2 border-t border-cyber-border/40 px-4 py-3 text-xs text-cyan-300/90">
                        <div className="flex items-center gap-2">
                          <Loader2 className="h-3.5 w-3.5 shrink-0 animate-spin" />
                          <span>
                            진단 실행 중…
                            {runningSummary ? ` (${runningSummary})` : null}
                          </span>
                        </div>
                        {runProgress && runProgress.section_id === section.id ? (
                          <>
                            <div className="h-1.5 overflow-hidden rounded-full bg-cyber-border/40">
                              <div
                                className="h-full rounded-full bg-cyan-400/80 transition-all duration-500"
                                style={{ width: `${Math.max(2, progressRatio(runProgress))}%` }}
                              />
                            </div>
                            <p className="font-mono text-[10px] text-cyber-muted">
                              {progressLabel(runProgress)}
                              {runProgress.requests_sent > 0
                                ? ` · 요청 ${runProgress.requests_sent.toLocaleString()}`
                                : null}
                              {runProgress.requests_cap
                                ? ` / ${runProgress.requests_cap.toLocaleString()}`
                                : runProgress.phase !== "zap" && runProgress.requests_sent > 0
                                  ? " · 무제한"
                                  : null}
                            </p>
                            {runProgress.message ? (
                              <p className="truncate text-[10px] text-white/80">{runProgress.message}</p>
                            ) : null}
                          </>
                        ) : runningSummary?.includes("ZAP") ? (
                          <p className="text-[10px] text-cyber-muted">
                            ZAP은 수십 분 걸릴 수 있습니다
                          </p>
                        ) : null}
                      </div>
                    ) : null}
                    {open && !running && report ? <DiagnosisReportPanel report={report} /> : null}
                    {open && !report && !running && reviewLater ? (
                      <div className="border-t border-amber-400/20 bg-amber-500/5 px-4 py-3 text-xs text-amber-200/90">
                        추후 검토 — 자동 진단 범위에 포함되지 않습니다.
                      </div>
                    ) : null}
                    {open && !report && !running && statusLabel ? (
                      <div className="border-t border-amber-400/20 bg-amber-500/5 px-4 py-3 text-xs text-amber-200/90">
                        {statusLabel} — 회원가입 화면에서 패스워드 정책(길이·복잡도 등)을 직접
                        확인하세요.
                      </div>
                    ) : null}
                    {open && !report && !running && diagnosable ? (
                      <div className="border-t border-cyber-border/40 px-4 py-3 text-xs text-cyber-muted">
                        저장된 리포트 없음 — 「진단 시작」을 눌러 실행하세요.
                      </div>
                    ) : null}
                  </div>
                );
              })}
            </div>
          </section>
        ))}
      </div>

      <G12DiagnosisStartDialog
        open={g12DialogOpen && !runningId}
        initialOptions={g12Options}
        onClose={() => setG12DialogOpen(false)}
        onStart={handleG12Start}
      />
      <G15DiagnosisStartDialog
        open={g15DialogOpen && !runningId}
        initialOptions={g15Options}
        onClose={() => setG15DialogOpen(false)}
        onStart={handleG15Start}
      />
      <G41DiagnosisStartDialog
        open={g41DialogOpen && !runningId}
        initialOptions={g41Options}
        onClose={() => setG41DialogOpen(false)}
        onStart={handleG41Start}
      />
      <G42DiagnosisStartDialog
        open={g42DialogOpen && !runningId}
        initialOptions={g42Options}
        onClose={() => setG42DialogOpen(false)}
        onStart={handleG42Start}
      />
      <G22DiagnosisStartDialog
        open={g22DialogOpen && !runningId}
        initialOptions={g22Options}
        onClose={() => setG22DialogOpen(false)}
        onStart={handleG22Start}
      />
      <G71DiagnosisStartDialog
        open={g71DialogOpen && !runningId}
        initialOptions={g71Options}
        onClose={() => setG71DialogOpen(false)}
        onStart={handleG71Start}
      />
      <G72DiagnosisStartDialog
        open={g72DialogOpen && !runningId}
        initialOptions={g72Options}
        onClose={() => setG72DialogOpen(false)}
        onStart={handleG72Start}
      />
      <G73DiagnosisStartDialog
        open={g73DialogOpen && !runningId}
        initialOptions={g73Options}
        onClose={() => setG73DialogOpen(false)}
        onStart={handleG73Start}
      />
      <G74DiagnosisStartDialog
        open={g74DialogOpen && !runningId}
        initialOptions={g74Options}
        onClose={() => setG74DialogOpen(false)}
        onStart={handleG74Start}
      />
      <G32DiagnosisStartDialog
        open={g32DialogOpen && !runningId}
        initialOptions={g32Options}
        onClose={() => setG32DialogOpen(false)}
        onStart={handleG32Start}
      />
      <G34DiagnosisStartDialog
        open={g34DialogOpen && !runningId}
        initialOptions={g34Options}
        onClose={() => setG34DialogOpen(false)}
        onStart={handleG34Start}
      />
      <G35DiagnosisStartDialog
        open={g35DialogOpen && !runningId}
        initialOptions={g35Options}
        onClose={() => setG35DialogOpen(false)}
        onStart={handleG35Start}
      />
      <G36DiagnosisStartDialog
        open={g36DialogOpen && !runningId}
        initialOptions={g36Options}
        onClose={() => setG36DialogOpen(false)}
        onStart={handleG36Start}
      />
      <G52DiagnosisStartDialog
        open={g52DialogOpen && !runningId}
        initialOptions={g52Options}
        onClose={() => setG52DialogOpen(false)}
        onStart={handleG52Start}
      />
      <G61DiagnosisStartDialog
        open={g61DialogOpen && !runningId}
        initialOptions={g61Options}
        onClose={() => setG61DialogOpen(false)}
        onStart={handleG61Start}
      />
      <G62DiagnosisStartDialog
        open={g62DialogOpen && !runningId}
        initialOptions={g62Options}
        onClose={() => setG62DialogOpen(false)}
        onStart={handleG62Start}
      />
    </div>
  );
}
