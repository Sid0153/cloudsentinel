import { Link, useSearchParams } from "react-router-dom";

import { formatDateTime, humanize } from "../components/format";
import { EmptyState, Loaded, PageHeader, Pagination, inputClass } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { AUDIT_ACTIONS, listAuditLogs } from "../services/audit";
import type { AuditLogEntry } from "../types/api";

const PAGE_SIZE = 50;

function Actor({ entry }: { entry: AuditLogEntry }) {
  if (entry.actor_email) return <span>{entry.actor_email}</span>;
  // No actor: either nobody was signed in (failed login) or CloudSentinel itself acted.
  const system = entry.action.startsWith("SCAN_");
  return <span className="text-slate-500">{system ? "System" : "Anonymous"}</span>;
}

/** Links to the thing the event was about, where the app has a page for it. */
function Target({ entry }: { entry: AuditLogEntry }) {
  if (!entry.target_type) return <span className="text-slate-400">—</span>;
  const label = humanize(entry.target_type);
  const paths: Record<string, string> = { FINDING: "/findings/", SCAN: "/scans/" };
  const base = paths[entry.target_type];
  if (base && entry.target_id) {
    return (
      <Link to={`${base}${entry.target_id}`} className="underline">
        {label}
      </Link>
    );
  }
  return <span title={entry.target_id ?? undefined}>{label}</span>;
}

function Details({ details }: { details: Record<string, unknown> }) {
  const entries = Object.entries(details);
  if (entries.length === 0) return <span className="text-slate-400">—</span>;
  return (
    <dl className="space-y-0.5">
      {entries.map(([key, value]) => (
        <div key={key} className="flex gap-1">
          <dt className="text-slate-500">{key}:</dt>
          <dd className="break-all font-mono">{typeof value === "string" ? value : JSON.stringify(value)}</dd>
        </div>
      ))}
    </dl>
  );
}

export default function AuditLogPage() {
  const [params, setParams] = useSearchParams();
  const action = params.get("action") ?? "";
  const outcome = params.get("outcome") ?? "";
  const offset = Number(params.get("offset") ?? 0) || 0;
  const { state, reload } = useApi(
    () =>
      listAuditLogs({
        action: action || undefined,
        outcome: outcome || undefined,
        limit: PAGE_SIZE,
        offset,
      }),
    params.toString(),
  );

  function update(key: string, value: string) {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    if (key !== "offset") next.delete("offset");
    setParams(next);
  }

  return (
    <section className="space-y-4">
      <PageHeader
        title="Audit log"
        description="Security-relevant actions, newest first. Records cannot be edited or deleted."
        actions={
          <button type="button" onClick={reload} className="rounded border border-slate-300 bg-white px-3 py-2 text-sm">
            Refresh
          </button>
        }
      />

      <div className="flex flex-wrap gap-3 rounded-lg border border-slate-200 bg-white p-4 text-sm">
        <label>
          <span className="mr-1 text-slate-600">Action</span>
          <select value={action} onChange={(e) => update("action", e.target.value)} className={inputClass}>
            <option value="">All</option>
            {AUDIT_ACTIONS.map((value) => (
              <option key={value} value={value}>
                {humanize(value)}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span className="mr-1 text-slate-600">Outcome</span>
          <select value={outcome} onChange={(e) => update("outcome", e.target.value)} className={inputClass}>
            <option value="">All</option>
            <option value="SUCCESS">Success</option>
            <option value="FAILURE">Failure</option>
          </select>
        </label>
      </div>

      <div className="overflow-x-auto rounded-lg border border-slate-200 bg-white">
        <Loaded state={state} what="audit log" onRetry={reload}>
          {(page) =>
            page.items.length === 0 ? (
              <EmptyState>No events match these filters.</EmptyState>
            ) : (
              <>
                <table className="w-full text-left text-sm">
                  <thead className="border-b border-slate-200 text-slate-600">
                    <tr>
                      <th className="px-4 py-2 font-medium">Time</th>
                      <th className="px-4 py-2 font-medium">Action</th>
                      <th className="px-4 py-2 font-medium">Outcome</th>
                      <th className="px-4 py-2 font-medium">Actor</th>
                      <th className="px-4 py-2 font-medium">Target</th>
                      <th className="px-4 py-2 font-medium">IP address</th>
                      <th className="px-4 py-2 font-medium">Details</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 align-top">
                    {page.items.map((entry) => (
                      <tr key={entry.id}>
                        <td className="whitespace-nowrap px-4 py-2" title={entry.request_id ?? undefined}>
                          {formatDateTime(entry.created_at, true)}
                        </td>
                        <td className="whitespace-nowrap px-4 py-2 font-medium">{humanize(entry.action)}</td>
                        <td className="px-4 py-2">
                          <span
                            className={`rounded px-2 py-0.5 text-xs font-semibold ${
                              entry.outcome === "SUCCESS"
                                ? "bg-emerald-50 text-emerald-900 ring-1 ring-inset ring-emerald-300"
                                : "bg-red-50 text-red-900 ring-1 ring-inset ring-red-300"
                            }`}
                          >
                            {humanize(entry.outcome)}
                          </span>
                        </td>
                        <td className="px-4 py-2">
                          <Actor entry={entry} />
                        </td>
                        <td className="px-4 py-2">
                          <Target entry={entry} />
                        </td>
                        <td className="whitespace-nowrap px-4 py-2 font-mono text-xs">{entry.ip_address ?? "—"}</td>
                        <td className="min-w-[14rem] px-4 py-2 text-xs">
                          <Details details={entry.details} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                <Pagination
                  total={page.total}
                  offset={offset}
                  limit={PAGE_SIZE}
                  onChange={(value) => update("offset", String(value))}
                />
              </>
            )
          }
        </Loaded>
      </div>
    </section>
  );
}
