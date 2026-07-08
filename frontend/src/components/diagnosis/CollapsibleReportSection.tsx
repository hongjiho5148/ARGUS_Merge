import { useState, type ReactNode } from "react";
import { ChevronDown } from "lucide-react";

export function CollapsibleReportSection({
  title,
  subtitle,
  defaultOpen = false,
  children,
}: {
  title: ReactNode;
  subtitle?: string;
  defaultOpen?: boolean;
  children: ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen);

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
        <span className="flex items-center text-[10px] font-semibold uppercase tracking-wide text-cyber-muted">
          {title}
        </span>
        {subtitle ? <span className="text-[10px] text-cyber-muted/80">{subtitle}</span> : null}
      </button>
      {open ? <div className="border-t border-cyber-border/25 px-2 py-2">{children}</div> : null}
    </div>
  );
}
