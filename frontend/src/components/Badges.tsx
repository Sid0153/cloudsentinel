import type { FindingStatus, Priority, ScanStatus, Severity } from "../types/api";
import { humanize } from "./format";

// Every badge shows its text; the colour only reinforces it (never colour alone).
const BASE = "inline-flex items-center rounded px-2 py-0.5 text-xs font-semibold whitespace-nowrap";

const SEVERITY_STYLES: Record<Severity, string> = {
  CRITICAL: "bg-red-700 text-white",
  HIGH: "bg-orange-100 text-orange-900 ring-1 ring-inset ring-orange-300",
  MEDIUM: "bg-amber-50 text-amber-900 ring-1 ring-inset ring-amber-300",
  LOW: "bg-slate-100 text-slate-700 ring-1 ring-inset ring-slate-300",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`${BASE} ${SEVERITY_STYLES[severity]}`}>{severity}</span>;
}

const PRIORITY_STYLES: Record<Priority, string> = {
  P1: "bg-red-700 text-white",
  P2: "bg-orange-100 text-orange-900 ring-1 ring-inset ring-orange-300",
  P3: "bg-amber-50 text-amber-900 ring-1 ring-inset ring-amber-300",
  P4: "bg-slate-100 text-slate-700 ring-1 ring-inset ring-slate-300",
};

function priorityFor(score: number): Priority {
  if (score >= 80) return "P1";
  if (score >= 60) return "P2";
  if (score >= 40) return "P3";
  return "P4";
}

/** Risk score with its priority band, e.g. "85 · P1". */
export function RiskBadge({ score }: { score: number | null }) {
  if (score === null) {
    return <span className={`${BASE} bg-slate-50 text-slate-500`}>Not scored</span>;
  }
  const priority = priorityFor(score);
  return (
    <span
      className={`${BASE} tabular-nums ${PRIORITY_STYLES[priority]}`}
      title={`Risk ${score} of 100, priority ${priority}`}
    >
      {score} · {priority}
    </span>
  );
}

const STATUS_STYLES: Record<FindingStatus, string> = {
  OPEN: "bg-white text-slate-900 ring-1 ring-inset ring-slate-400",
  ACKNOWLEDGED: "bg-sky-50 text-sky-900 ring-1 ring-inset ring-sky-300",
  RESOLVED: "bg-emerald-50 text-emerald-900 ring-1 ring-inset ring-emerald-300",
  FALSE_POSITIVE: "bg-slate-100 text-slate-600 ring-1 ring-inset ring-slate-300",
};

export function FindingStatusBadge({ status }: { status: FindingStatus }) {
  return <span className={`${BASE} ${STATUS_STYLES[status]}`}>{humanize(status)}</span>;
}

const SCAN_STYLES: Record<ScanStatus, string> = {
  PENDING: "bg-slate-100 text-slate-700",
  RUNNING: "bg-sky-100 text-sky-900",
  COMPLETED: "bg-emerald-100 text-emerald-900",
  COMPLETED_WITH_ERRORS: "bg-amber-100 text-amber-900",
  FAILED: "bg-red-100 text-red-900",
};

export function ScanStatusBadge({ status }: { status: ScanStatus }) {
  return <span className={`${BASE} ${SCAN_STYLES[status]}`}>{humanize(status)}</span>;
}
