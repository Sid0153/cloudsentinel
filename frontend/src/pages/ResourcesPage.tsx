import { useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router-dom";

import { formatDateTime, shortResourceId, shortType } from "../components/format";
import {
  EmptyState,
  Loaded,
  PageHeader,
  Pagination,
  inputClass,
  secondaryButtonClass,
} from "../components/ui";
import { useApi } from "../hooks/useApi";
import { listResources } from "../services/resources";
import { RESOURCE_TYPES } from "../types/api";

const PAGE_SIZE = 50;

export default function ResourcesPage() {
  const [params, setParams] = useSearchParams();
  const resourceType = params.get("resource_type") ?? "";
  const region = params.get("region") ?? "";
  const offset = Number(params.get("offset") ?? 0) || 0;
  const [regionInput, setRegionInput] = useState(region);
  const { state, reload } = useApi(
    () =>
      listResources({
        resource_type: resourceType || undefined,
        region: region || undefined,
        limit: PAGE_SIZE,
        offset,
      }),
    params.toString(),
  );

  function update(changes: Record<string, string>) {
    const next = new URLSearchParams(params);
    for (const [key, value] of Object.entries(changes)) {
      if (value) next.set(key, value);
      else next.delete(key);
    }
    if (!("offset" in changes)) next.delete("offset");
    setParams(next);
  }

  function submitRegion(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    update({ region: regionInput.trim().toLowerCase() });
  }

  return (
    <section className="space-y-4">
      <PageHeader
        title="Resources"
        description="AWS resources found by scans. Resources deleted in AWS stay listed; Last seen shows when they were last found."
      />

      <div className="flex flex-wrap items-end gap-3 rounded-lg border border-slate-200 bg-white p-4 text-sm">
        <label>
          <span className="mr-1 text-slate-600">Type</span>
          <select value={resourceType} onChange={(e) => update({ resource_type: e.target.value })} className={inputClass}>
            <option value="">All</option>
            {RESOURCE_TYPES.map((type) => (
              <option key={type} value={type}>
                {shortType(type)}
              </option>
            ))}
          </select>
        </label>
        <form onSubmit={submitRegion} className="flex items-end gap-2">
          <label>
            <span className="mr-1 text-slate-600">Region</span>
            <input
              value={regionInput}
              maxLength={32}
              placeholder="e.g. us-east-1 or global"
              onChange={(e) => setRegionInput(e.target.value)}
              className={inputClass}
            />
          </label>
          <button type="submit" className={secondaryButtonClass}>
            Apply
          </button>
        </form>
      </div>

      <div className="overflow-x-auto rounded-lg border border-slate-200 bg-white">
        <Loaded state={state} what="resources" onRetry={reload}>
          {(page) =>
            page.items.length === 0 ? (
              <EmptyState>No resources found. Run a scan to discover resources.</EmptyState>
            ) : (
              <>
                <table className="w-full text-left text-sm">
                  <thead className="border-b border-slate-200 text-slate-600">
                    <tr>
                      <th className="px-4 py-2 font-medium">Resource</th>
                      <th className="px-4 py-2 font-medium">Type</th>
                      <th className="px-4 py-2 font-medium">Region</th>
                      <th className="px-4 py-2 font-medium">Last seen</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {page.items.map((resource) => (
                      <tr key={resource.id}>
                        <td className="px-4 py-2">
                          <Link to={`/resources/${resource.id}`} className="font-medium underline">
                            {resource.name ?? shortResourceId(resource.resource_id)}
                          </Link>
                          {resource.name !== null && resource.name !== shortResourceId(resource.resource_id) && (
                            <div className="font-mono text-xs text-slate-500" title={resource.resource_id}>
                              {shortResourceId(resource.resource_id)}
                            </div>
                          )}
                        </td>
                        <td className="px-4 py-2">{shortType(resource.resource_type)}</td>
                        <td className="px-4 py-2">{resource.region}</td>
                        <td className="px-4 py-2 whitespace-nowrap">{formatDateTime(resource.last_seen)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                <Pagination
                  total={page.total}
                  offset={offset}
                  limit={PAGE_SIZE}
                  onChange={(value) => update({ offset: String(value) })}
                />
              </>
            )
          }
        </Loaded>
      </div>
    </section>
  );
}
