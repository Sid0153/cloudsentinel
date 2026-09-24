import { useEffect } from "react";
import { Link, useParams } from "react-router-dom";

import { ScanStatusBadge } from "../components/Badges";
import { formatDateTime, humanize, shortType } from "../components/format";
import { Card, Loaded, ScrollX, StatTile } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { listRules } from "../services/rules";
import { ACTIVE_SCAN_STATUSES, getScan } from "../services/scans";
import { SEVERITIES, type Rule, type RuleResult, type Scan } from "../types/api";
import { POLL_MS } from "./ScansPage";

const RULE_STATUS_STYLES: Record<RuleResult["status"], string> = {
  FAILED: "text-red-800",
  PASSED: "text-emerald-800",
  INCOMPLETE: "text-amber-800",
  NOT_APPLICABLE: "text-slate-600",
  ERROR: "text-red-800",
};

function duration(scan: Scan): string {
  if (!scan.started_at || !scan.finished_at) return "—";
  const seconds = (Date.parse(scan.finished_at) - Date.parse(scan.started_at)) / 1000;
  return seconds < 1 ? "< 1 s" : `${Math.round(seconds)} s`;
}

function ScanDetail({ scan, rules }: { scan: Scan; rules: Rule[] }) {
  const titles = new Map(rules.map((rule) => [rule.id, rule.title]));
  const ruleIds = Object.keys(scan.rule_results).sort();
  const max = scan.risk_summary.max_score;

  return (
    <div className="space-y-6">
      <div>
        <p className="text-sm">
          <Link to="/scans" className="underline">
            Scans
          </Link>
        </p>
        <h1 className="mt-1 flex items-center gap-3 text-2xl font-semibold tracking-tight">
          Scan of {formatDateTime(scan.created_at, true)} <ScanStatusBadge status={scan.status} />
        </h1>
        {scan.error_summary && (
          <p role="alert" className="mt-2 text-sm text-red-700">
            {scan.error_summary}
          </p>
        )}
        {scan.status === "COMPLETED_WITH_ERRORS" && (
          <p className="mt-2 text-sm text-amber-800">
            Some data could not be read. Rules marked Incomplete below did not get a full
            answer, so a missing finding there does not mean the resource is secure.
          </p>
        )}
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatTile label="Resources" value={scan.resource_count} />
        <StatTile
          label="Findings detected"
          value={scan.finding_count}
          detail={SEVERITIES.filter((s) => scan.finding_counts[s])
            .map((s) => `${humanize(s)} ${scan.finding_counts[s]}`)
            .join(" · ")}
        />
        <StatTile label="Highest risk" value={max ?? "—"} detail="Among this scan's findings" />
        <StatTile
          label="Duration"
          value={duration(scan)}
          detail={scan.caller_arn ? <span className="break-all">As {scan.caller_arn}</span> : undefined}
        />
      </div>

      <Card title="Coverage by AWS service">
        {Object.keys(scan.coverage).length === 0 ? (
          <p className="text-sm text-slate-600">No coverage recorded yet.</p>
        ) : (
          <ScrollX>
          <table className="w-full text-left text-sm">
            <thead className="text-slate-600">
              <tr>
                <th className="py-1 pr-3 font-medium">Service</th>
                <th className="py-1 pr-3 font-medium">Status</th>
                <th className="py-1 pr-3 text-right font-medium">Items</th>
                <th className="py-1 font-medium">Errors</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {Object.entries(scan.coverage).map(([service, entry]) => (
                <tr key={service}>
                  <td className="py-1.5 pr-3 uppercase">{service}</td>
                  <td className="py-1.5 pr-3">{humanize(entry.status)}</td>
                  <td className="py-1.5 pr-3 text-right tabular-nums">{entry.items}</td>
                  <td className="py-1.5 font-mono text-xs text-slate-600">
                    {entry.errors.length === 0 ? "—" : entry.errors.join(", ")}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          </ScrollX>
        )}
      </Card>

      <Card title="Rule results">
        {ruleIds.length === 0 ? (
          <p className="text-sm text-slate-600">Rules have not run for this scan.</p>
        ) : (
          <ScrollX>
          <table className="w-full text-left text-sm">
            <thead className="text-slate-600">
              <tr>
                <th className="py-1 pr-3 font-medium">Rule</th>
                <th className="py-1 pr-3 font-medium">Result</th>
                <th className="py-1 pr-3 text-right font-medium">Checked</th>
                <th className="py-1 pr-3 text-right font-medium">Failed</th>
                <th className="py-1 text-right font-medium">Not evaluated</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {ruleIds.map((id) => {
                const result = scan.rule_results[id];
                return (
                  <tr key={id}>
                    <td className="py-1.5 pr-3">
                      <span className="font-medium">{id}</span>{" "}
                      <span className="text-slate-600">{titles.get(id) ?? ""}</span>
                    </td>
                    <td className={`py-1.5 pr-3 font-medium ${RULE_STATUS_STYLES[result.status]}`}>
                      {humanize(result.status)}
                    </td>
                    <td className="py-1.5 pr-3 text-right tabular-nums">{result.evaluated}</td>
                    <td className="py-1.5 pr-3 text-right tabular-nums">
                      {result.failed > 0 ? (
                        <Link to={`/findings?rule_id=${encodeURIComponent(id)}`} className="underline">
                          {result.failed}
                        </Link>
                      ) : (
                        0
                      )}
                    </td>
                    <td className="py-1.5 text-right tabular-nums">{result.unknown}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          </ScrollX>
        )}
      </Card>

      {Object.keys(scan.resource_counts).length > 0 && (
        <Card title="Resources found">
          <ul className="grid gap-x-10 gap-y-1 text-sm sm:grid-cols-2">
            {Object.entries(scan.resource_counts).map(([type, count]) => (
              <li key={type} className="flex justify-between border-b border-slate-100 py-1">
                <Link to={`/resources?resource_type=${encodeURIComponent(type)}`} className="underline">
                  {shortType(type)}
                </Link>
                <span className="tabular-nums">{count}</span>
              </li>
            ))}
          </ul>
        </Card>
      )}
    </div>
  );
}

export default function ScanDetailPage() {
  const { scanId = "" } = useParams();
  const scan = useApi(() => getScan(scanId), scanId);
  const rules = useApi(listRules, "rules");
  const { reload } = scan;

  const active = scan.state.kind === "loaded" && ACTIVE_SCAN_STATUSES.includes(scan.state.data.status);
  useEffect(() => {
    if (!active) return undefined;
    const timer = window.setTimeout(reload, POLL_MS);
    return () => window.clearTimeout(timer);
  }, [active, reload, scan.state]);

  return (
    <section>
      <Loaded state={scan.state} what="scan" onRetry={reload}>
        {(data) => <ScanDetail scan={data} rules={rules.state.kind === "loaded" ? rules.state.data : []} />}
      </Loaded>
    </section>
  );
}
