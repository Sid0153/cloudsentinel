import type { ReactNode } from "react";

import type { LoadState } from "../hooks/useApi";

export function PageHeader({ title, description, actions }: {
  title: string;
  description?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
        {description && <p className="mt-1 text-sm text-slate-600">{description}</p>}
      </div>
      {actions}
    </div>
  );
}

export function Card({ title, children, className = "" }: {
  title?: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`rounded-lg border border-slate-200 bg-white p-5 ${className}`}>
      {title && <h2 className="mb-3 text-sm font-semibold text-slate-700">{title}</h2>}
      {children}
    </section>
  );
}

export function Loading({ what }: { what: string }) {
  return (
    <p role="status" className="py-4 text-sm text-slate-600">
      Loading {what}…
    </p>
  );
}

export function ErrorMessage({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div role="alert" className="flex items-center gap-3 py-4 text-sm text-red-700">
      <span>{message}</span>
      {onRetry && (
        <button type="button" onClick={onRetry} className="rounded border border-red-300 px-2 py-0.5">
          Retry
        </button>
      )}
    </div>
  );
}

export function EmptyState({ children }: { children: ReactNode }) {
  return <div className="py-6 text-center text-sm text-slate-600">{children}</div>;
}

/** Lets a wide table scroll sideways inside its card instead of stretching the page. */
export function ScrollX({ children }: { children: ReactNode }) {
  return <div className="overflow-x-auto">{children}</div>;
}

/** Renders loading / error, or the children with the loaded data. */
export function Loaded<T>({ state, what, onRetry, children }: {
  state: LoadState<T>;
  what: string;
  onRetry?: () => void;
  children: (data: T) => ReactNode;
}) {
  if (state.kind === "loading") return <Loading what={what} />;
  if (state.kind === "error") return <ErrorMessage message={state.message} onRetry={onRetry} />;
  return <>{children(state.data)}</>;
}

/** A labelled number, e.g. "Open findings: 7". */
export function StatTile({ label, value, detail }: {
  label: string;
  value: ReactNode;
  detail?: ReactNode;
}) {
  return (
    <div className="rounded-lg border border-slate-200 bg-white p-4">
      <p className="text-xs font-medium uppercase tracking-wide text-slate-500">{label}</p>
      <p className="mt-1 text-2xl font-semibold tabular-nums text-slate-900">{value}</p>
      {detail && <div className="mt-1 text-xs text-slate-600">{detail}</div>}
    </div>
  );
}

/** Evidence and configuration are shown as formatted JSON text (never as HTML). */
export function JsonBlock({ value }: { value: unknown }) {
  return (
    <pre className="max-h-96 overflow-auto rounded bg-slate-900 p-3 text-xs leading-relaxed text-slate-100">
      {JSON.stringify(value, null, 2)}
    </pre>
  );
}

export function Pagination({ total, offset, limit, onChange }: {
  total: number;
  offset: number;
  limit: number;
  onChange: (offset: number) => void;
}) {
  if (total === 0) return null;
  const first = offset + 1;
  const last = Math.min(offset + limit, total);
  return (
    <div className="flex items-center justify-between border-t border-slate-100 px-4 py-3 text-sm">
      <span className="text-slate-600">
        {first}–{last} of {total}
      </span>
      <div className="flex gap-2">
        <button
          type="button"
          disabled={offset === 0}
          onClick={() => onChange(Math.max(0, offset - limit))}
          className="rounded border border-slate-300 px-2 py-1 disabled:opacity-40"
        >
          Previous
        </button>
        <button
          type="button"
          disabled={last >= total}
          onClick={() => onChange(offset + limit)}
          className="rounded border border-slate-300 px-2 py-1 disabled:opacity-40"
        >
          Next
        </button>
      </div>
    </div>
  );
}

export const inputClass = "rounded border border-slate-300 px-3 py-2 text-sm";
export const buttonClass =
  "rounded bg-slate-900 px-3 py-2 text-sm font-medium text-white disabled:opacity-60";
export const secondaryButtonClass =
  "rounded border border-slate-300 bg-white px-3 py-2 text-sm font-medium disabled:opacity-60";
