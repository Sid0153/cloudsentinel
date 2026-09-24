import { useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router-dom";

import { FindingStatusBadge, RiskBadge, SeverityBadge } from "../components/Badges";
import { formatDateTime, humanize, shortResourceId, shortType } from "../components/format";
import {
  EmptyState,
  Loaded,
  PageHeader,
  Pagination,
  inputClass,
  secondaryButtonClass,
} from "../components/ui";
import { useApi } from "../hooks/useApi";
import { listFindings, type FindingQuery, type FindingSort } from "../services/findings";
import {
  CATEGORIES,
  FINDING_STATUSES,
  RESOURCE_TYPES,
  SEVERITIES,
  type Category,
  type FindingStatus,
  type Severity,
} from "../types/api";

const PAGE_SIZE = 25;
// Without an explicit status filter the page shows what still needs attention.
const DEFAULT_STATUSES: FindingStatus[] = ["OPEN", "ACKNOWLEDGED"];
const SORTS: { value: FindingSort; label: string }[] = [
  { value: "risk", label: "Risk" },
  { value: "severity", label: "Severity" },
  { value: "last_detected", label: "Last detected" },
  { value: "first_detected", label: "First detected" },
  { value: "rule_id", label: "Rule" },
];

function readQuery(params: URLSearchParams): FindingQuery {
  const statuses = params.getAll("status") as FindingStatus[];
  return {
    q: params.get("q") ?? undefined,
    severity: params.getAll("severity") as Severity[],
    status: params.has("status") ? statuses.filter(Boolean) : DEFAULT_STATUSES,
    category: (params.get("category") ?? "") as Category | "",
    resource_type: params.get("resource_type") ?? "",
    rule_id: params.get("rule_id") ?? undefined,
    sort: (params.get("sort") as FindingSort | null) ?? "risk",
    order: params.get("order") === "asc" ? "asc" : "desc",
    limit: PAGE_SIZE,
    offset: Number(params.get("offset") ?? 0) || 0,
  };
}

function CheckboxGroup<T extends string>({ legend, options, selected, onToggle }: {
  legend: string;
  options: T[];
  selected: T[];
  onToggle: (value: T) => void;
}) {
  return (
    <fieldset>
      <legend className="text-xs font-medium uppercase tracking-wide text-slate-500">{legend}</legend>
      <div className="mt-1 flex flex-wrap gap-x-3 gap-y-1">
        {options.map((option) => (
          <label key={option} className="flex items-center gap-1 text-sm">
            <input type="checkbox" checked={selected.includes(option)} onChange={() => onToggle(option)} />
            {humanize(option)}
          </label>
        ))}
      </div>
    </fieldset>
  );
}

export default function FindingsPage() {
  const [params, setParams] = useSearchParams();
  const query = readQuery(params);
  const [search, setSearch] = useState(query.q ?? "");
  const { state, reload } = useApi(() => listFindings(query), params.toString());

  /** Applies changes to the URL; any filter change goes back to the first page. */
  function update(changes: Record<string, string | string[] | null>, keepOffset = false) {
    const next = new URLSearchParams(params);
    for (const [key, value] of Object.entries(changes)) {
      next.delete(key);
      if (Array.isArray(value)) {
        value.forEach((item) => next.append(key, item));
        if (key === "status" && value.length === 0) next.append("status", "");
      } else if (value) {
        next.set(key, value);
      }
    }
    if (!keepOffset) next.delete("offset");
    setParams(next);
  }

  function toggle<T extends string>(key: "severity" | "status", current: T[], value: T) {
    const next = current.includes(value) ? current.filter((v) => v !== value) : [...current, value];
    update({ [key]: next });
  }

  function submitSearch(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    update({ q: search.trim() || null });
  }

  return (
    <section className="space-y-4">
      <PageHeader title="Findings" description="Security problems detected by scans, highest risk first." />

      <div className="space-y-3 rounded-lg border border-slate-200 bg-white p-4">
        {query.rule_id && (
          <p className="text-sm">
            Only rule <span className="font-medium">{query.rule_id}</span>{" "}
            <button type="button" onClick={() => update({ rule_id: null })} className="underline">
              Show all rules
            </button>
          </p>
        )}
        <form onSubmit={submitSearch} className="flex gap-2">
          <label htmlFor="finding-search" className="sr-only">
            Search findings
          </label>
          <input
            id="finding-search"
            type="search"
            value={search}
            maxLength={200}
            placeholder="Search title, rule or resource ID"
            onChange={(event) => setSearch(event.target.value)}
            className={`${inputClass} flex-1`}
          />
          <button type="submit" className={secondaryButtonClass}>
            Search
          </button>
        </form>
        <div className="grid gap-3 md:grid-cols-2">
          <CheckboxGroup
            legend="Severity"
            options={SEVERITIES}
            selected={query.severity ?? []}
            onToggle={(value) => toggle("severity", query.severity ?? [], value)}
          />
          <CheckboxGroup
            legend="Status"
            options={FINDING_STATUSES}
            selected={query.status ?? []}
            onToggle={(value) => toggle("status", query.status ?? [], value)}
          />
        </div>
        <div className="flex flex-wrap gap-3 text-sm">
          <label>
            <span className="mr-1 text-slate-600">Category</span>
            <select
              value={query.category}
              onChange={(e) => update({ category: e.target.value || null })}
              className={inputClass}
            >
              <option value="">All</option>
              {CATEGORIES.map((c) => (
                <option key={c} value={c}>
                  {humanize(c)}
                </option>
              ))}
            </select>
          </label>
          <label>
            <span className="mr-1 text-slate-600">Resource type</span>
            <select
              value={query.resource_type}
              onChange={(e) => update({ resource_type: e.target.value || null })}
              className={inputClass}
            >
              <option value="">All</option>
              {RESOURCE_TYPES.map((t) => (
                <option key={t} value={t}>
                  {shortType(t)}
                </option>
              ))}
            </select>
          </label>
          <label>
            <span className="mr-1 text-slate-600">Sort by</span>
            <select value={query.sort} onChange={(e) => update({ sort: e.target.value })} className={inputClass}>
              {SORTS.map((s) => (
                <option key={s.value} value={s.value}>
                  {s.label}
                </option>
              ))}
            </select>
          </label>
          <label>
            <span className="mr-1 text-slate-600">Order</span>
            <select value={query.order} onChange={(e) => update({ order: e.target.value })} className={inputClass}>
              <option value="desc">Descending</option>
              <option value="asc">Ascending</option>
            </select>
          </label>
        </div>
      </div>

      <div className="overflow-x-auto rounded-lg border border-slate-200 bg-white">
        <Loaded state={state} what="findings" onRetry={reload}>
          {(page) =>
            page.items.length === 0 ? (
              <EmptyState>No findings match these filters.</EmptyState>
            ) : (
              <>
                <table className="w-full text-left text-sm">
                  <thead className="border-b border-slate-200 text-slate-600">
                    <tr>
                      <th className="px-4 py-2 font-medium">Risk</th>
                      <th className="px-4 py-2 font-medium">Severity</th>
                      <th className="px-4 py-2 font-medium">Finding</th>
                      <th className="px-4 py-2 font-medium">Resource</th>
                      <th className="px-4 py-2 font-medium">Region</th>
                      <th className="px-4 py-2 font-medium">Status</th>
                      <th className="px-4 py-2 font-medium">Last detected</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {page.items.map((finding) => (
                      <tr key={finding.id}>
                        <td className="px-4 py-2">
                          <RiskBadge score={finding.risk_score} />
                        </td>
                        <td className="px-4 py-2">
                          <SeverityBadge severity={finding.severity} />
                        </td>
                        <td className="px-4 py-2">
                          <Link to={`/findings/${finding.id}`} className="font-medium underline">
                            {finding.title}
                          </Link>
                          <div className="text-xs text-slate-500">{finding.rule_id}</div>
                        </td>
                        <td className="px-4 py-2">
                          <span className="whitespace-nowrap font-mono text-xs" title={finding.resource_id}>
                            {shortResourceId(finding.resource_id)}
                          </span>
                          <div className="text-xs text-slate-500">{shortType(finding.resource_type)}</div>
                        </td>
                        <td className="whitespace-nowrap px-4 py-2">{finding.region}</td>
                        <td className="px-4 py-2">
                          <FindingStatusBadge status={finding.status} />
                        </td>
                        <td className="px-4 py-2 whitespace-nowrap">{formatDateTime(finding.last_detected)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                <Pagination
                  total={page.total}
                  offset={query.offset ?? 0}
                  limit={PAGE_SIZE}
                  onChange={(offset) => update({ offset: String(offset) }, true)}
                />
              </>
            )
          }
        </Loaded>
      </div>
    </section>
  );
}
