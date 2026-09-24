import { Link, useParams } from "react-router-dom";

import { FindingStatusBadge, RiskBadge, SeverityBadge } from "../components/Badges";
import { formatDateTime, shortType } from "../components/format";
import { Card, EmptyState, JsonBlock, Loaded } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { listFindings } from "../services/findings";
import { getResource } from "../services/resources";

export default function ResourceDetailPage() {
  const { resourceId = "" } = useParams();
  const resource = useApi(() => getResource(resourceId), resourceId);
  // Every finding ever raised on this resource, including resolved ones.
  const findings = useApi(() => listFindings({ resource_uuid: resourceId, limit: 100 }), resourceId);

  return (
    <section>
      <Loaded state={resource.state} what="resource" onRetry={resource.reload}>
        {(data) => (
          <div className="space-y-6">
            <div>
              <p className="text-sm">
                <Link to="/resources" className="underline">
                  Resources
                </Link>
              </p>
              <h1 className="mt-1 break-all text-2xl font-semibold tracking-tight">
                {data.name ?? data.resource_id}
              </h1>
              <p className="mt-1 text-sm text-slate-600">
                {shortType(data.resource_type)} · {data.region}
              </p>
            </div>

            <Card title="Details">
              <dl className="grid grid-cols-[8rem_1fr] gap-y-1 text-sm">
                <dt className="text-slate-600">AWS ID</dt>
                <dd className="break-all font-mono text-xs">{data.resource_id}</dd>
                <dt className="text-slate-600">First seen</dt>
                <dd>{formatDateTime(data.first_seen)}</dd>
                <dt className="text-slate-600">Last seen</dt>
                <dd>
                  {data.last_scan_id ? (
                    <Link to={`/scans/${data.last_scan_id}`} className="underline">
                      {formatDateTime(data.last_seen)}
                    </Link>
                  ) : (
                    formatDateTime(data.last_seen)
                  )}
                </dd>
              </dl>
            </Card>

            <Card title="Findings on this resource">
              <Loaded state={findings.state} what="findings" onRetry={findings.reload}>
                {(page) =>
                  page.items.length === 0 ? (
                    <EmptyState>No findings on this resource.</EmptyState>
                  ) : (
                    <ul className="divide-y divide-slate-100">
                      {page.items.map((finding) => (
                        <li key={finding.id} className="flex flex-wrap items-center gap-2 py-2 text-sm">
                          <RiskBadge score={finding.risk_score} />
                          <SeverityBadge severity={finding.severity} />
                          <Link to={`/findings/${finding.id}`} className="font-medium underline">
                            {finding.title}
                          </Link>
                          <FindingStatusBadge status={finding.status} />
                        </li>
                      ))}
                    </ul>
                  )
                }
              </Loaded>
            </Card>

            <Card title="Configuration">
              <p className="mb-2 text-xs text-slate-500">
                As normalized by the last scan. A null value means it could not be read.
              </p>
              <JsonBlock value={data.config} />
            </Card>
          </div>
        )}
      </Loaded>
    </section>
  );
}
