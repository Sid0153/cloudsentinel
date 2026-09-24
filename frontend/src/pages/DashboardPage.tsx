import { Link, useSearchParams } from "react-router-dom";

import { RiskBadge, ScanStatusBadge, SeverityBadge } from "../components/Badges";
import BarList from "../components/BarList";
import { formatDateTime, humanize, shortResourceId } from "../components/format";
import { Card, EmptyState, Loaded, PageHeader, ScrollX, StatTile, inputClass } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { listAwsAccounts } from "../services/awsAccounts";
import { getDashboard } from "../services/dashboard";
import { CATEGORIES, SEVERITIES, type DashboardSummary } from "../types/api";

function AccountPicker({ value, onChange }: { value: string; onChange: (id: string) => void }) {
  const { state } = useApi(listAwsAccounts, "accounts");
  if (state.kind !== "loaded" || state.data.length < 2) return null;
  return (
    <label className="text-sm">
      <span className="mr-2 text-slate-600">AWS account</span>
      <select value={value} onChange={(e) => onChange(e.target.value)} className={inputClass}>
        <option value="">All accounts</option>
        {state.data.map((account) => (
          <option key={account.id} value={account.id}>
            {account.name} ({account.account_id})
          </option>
        ))}
      </select>
    </label>
  );
}

function Summary({ data }: { data: DashboardSummary }) {
  if (data.latest_scan === null) {
    return (
      <Card>
        <EmptyState>
          <p className="font-medium text-slate-900">No scans yet</p>
          <p className="mt-1">
            Findings and risk appear here after the first scan.{" "}
            <Link to="/scans" className="underline">
              Go to Scans
            </Link>
          </p>
        </EmptyState>
      </Card>
    );
  }
  const scan = data.latest_scan;
  return (
    <div className="space-y-6">
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatTile
          label="Overall risk"
          value={data.overall_risk ? <RiskBadge score={data.overall_risk.score} /> : "None"}
          detail={
            data.overall_risk ? (
              <Link to={`/findings/${data.overall_risk.finding_id}`} className="underline">
                Highest open finding
              </Link>
            ) : (
              "No open findings"
            )
          }
        />
        <StatTile
          label="Open findings"
          value={data.open_finding_count}
          detail={`Critical ${data.findings_by_severity.CRITICAL} · High ${data.findings_by_severity.HIGH} · Medium ${data.findings_by_severity.MEDIUM} · Low ${data.findings_by_severity.LOW}`}
        />
        <StatTile
          label="Resources"
          value={data.resource_count}
          detail={`${data.aws_account_count} AWS account${data.aws_account_count === 1 ? "" : "s"}`}
        />
        <StatTile
          label="Latest scan"
          value={<ScanStatusBadge status={scan.status} />}
          detail={
            <Link to={`/scans/${scan.id}`} className="underline">
              {formatDateTime(scan.created_at, true)}
            </Link>
          }
        />
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <Card title="Open findings by severity">
          <BarList
            label="Open findings by severity"
            unit="open findings"
            items={SEVERITIES.map((s) => ({ key: s, label: humanize(s), value: data.findings_by_severity[s] }))}
          />
        </Card>
        <Card title="Open findings by category">
          <BarList
            label="Open findings by category"
            unit="open findings"
            items={CATEGORIES.map((c) => ({ key: c, label: humanize(c), value: data.findings_by_category[c] }))}
          />
        </Card>
      </div>

      <Card title="Top risks">
        {data.top_risks.length === 0 ? (
          <EmptyState>No open findings. Nothing to fix right now.</EmptyState>
        ) : (
          <ScrollX>
          <table className="w-full text-left text-sm">
            <thead className="text-slate-600">
              <tr>
                <th className="py-2 pr-3 font-medium">Risk</th>
                <th className="py-2 pr-3 font-medium">Finding</th>
                <th className="hidden py-2 pr-3 font-medium sm:table-cell">Resource</th>
                <th className="py-2 font-medium">Severity</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {data.top_risks.map((finding) => (
                <tr key={finding.id}>
                  <td className="py-2 pr-3">
                    <RiskBadge score={finding.risk_score} />
                  </td>
                  <td className="py-2 pr-3">
                    <Link to={`/findings/${finding.id}`} className="font-medium underline">
                      {finding.title}
                    </Link>
                  </td>
                  <td className="hidden whitespace-nowrap py-2 pr-3 font-mono text-xs sm:table-cell" title={finding.resource_id}>
                    {shortResourceId(finding.resource_id)}
                  </td>
                  <td className="py-2">
                    <SeverityBadge severity={finding.severity} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          </ScrollX>
        )}
        <p className="mt-3 text-sm">
          <Link to="/findings" className="underline">
            All findings
          </Link>
        </p>
      </Card>
    </div>
  );
}

export default function DashboardPage() {
  const [params, setParams] = useSearchParams();
  const accountId = params.get("account") ?? "";
  const { state, reload } = useApi(() => getDashboard(accountId || undefined), accountId);

  return (
    <section className="space-y-6">
      <PageHeader
        title="Dashboard"
        description="Open findings (open or acknowledged) and their risk, from the latest scans."
        actions={
          <AccountPicker
            value={accountId}
            onChange={(id) => setParams(id ? { account: id } : {})}
          />
        }
      />
      <Loaded state={state} what="dashboard" onRetry={reload}>
        {(data) => <Summary data={data} />}
      </Loaded>
    </section>
  );
}
