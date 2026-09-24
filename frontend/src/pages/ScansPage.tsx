import { useEffect, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";

import { useAuth } from "../auth/AuthContext";
import { ScanStatusBadge } from "../components/Badges";
import { formatDateTime } from "../components/format";
import {
  Card,
  EmptyState,
  Loaded,
  PageHeader,
  Pagination,
  buttonClass,
  inputClass,
} from "../components/ui";
import { useApi } from "../hooks/useApi";
import { ApiError } from "../services/api";
import { listAwsAccounts } from "../services/awsAccounts";
import { ACTIVE_SCAN_STATUSES, listScans, startScan } from "../services/scans";
import type { AwsAccount } from "../types/api";

const PAGE_SIZE = 20;
export const POLL_MS = 3000;

function describeStartError(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 409) return "A scan is already queued or running for this account.";
    if (error.status === 403) return "Your role cannot start scans.";
    if (error.status === 404) return "That AWS account no longer exists.";
  }
  return "Could not start the scan. Please try again.";
}

function StartScanForm({ accounts, onStarted }: { accounts: AwsAccount[]; onStarted: () => void }) {
  const [accountId, setAccountId] = useState(accounts[0]?.id ?? "");
  const [error, setError] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setStarting(true);
    setError(null);
    try {
      await startScan(accountId);
      onStarted();
    } catch (caught) {
      setError(describeStartError(caught));
    } finally {
      setStarting(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="flex flex-wrap items-end gap-3">
      <div>
        <label htmlFor="scan-account" className="block text-sm font-medium">
          AWS account
        </label>
        <select
          id="scan-account"
          value={accountId}
          onChange={(event) => setAccountId(event.target.value)}
          className={`${inputClass} mt-1`}
        >
          {accounts.map((account) => (
            <option key={account.id} value={account.id}>
              {account.name} ({account.account_id})
            </option>
          ))}
        </select>
      </div>
      <button type="submit" disabled={starting || !accountId} className={buttonClass}>
        Start scan
      </button>
      {error && (
        <p role="alert" className="w-full text-sm text-red-700">
          {error}
        </p>
      )}
      <p className="w-full text-xs text-slate-500">
        Scans are read-only: CloudSentinel never changes anything in AWS.
      </p>
    </form>
  );
}

export default function ScansPage() {
  const { state: auth } = useAuth();
  const canScan = auth.status === "authenticated" && auth.user.role !== "VIEWER";
  const [offset, setOffset] = useState(0);
  const accounts = useApi(listAwsAccounts, "accounts");
  const scans = useApi(() => listScans({ limit: PAGE_SIZE, offset }), String(offset));
  const { reload } = scans;

  // While a scan is queued or running, refresh the list every few seconds.
  const active =
    scans.state.kind === "loaded" &&
    scans.state.data.items.some((scan) => ACTIVE_SCAN_STATUSES.includes(scan.status));
  useEffect(() => {
    if (!active) return undefined;
    const timer = window.setTimeout(reload, POLL_MS);
    return () => window.clearTimeout(timer);
  }, [active, reload, scans.state]);

  const accountNames = new Map(
    accounts.state.kind === "loaded" ? accounts.state.data.map((a) => [a.id, a.name]) : [],
  );

  return (
    <section className="space-y-6">
      <PageHeader title="Scans" description="Read-only scans of your registered AWS accounts." />

      {canScan && (
        <Card title="New scan">
          <Loaded state={accounts.state} what="AWS accounts">
            {(list) =>
              list.length === 0 ? (
                <p className="text-sm text-slate-600">
                  No AWS account is registered yet.{" "}
                  {auth.status === "authenticated" && auth.user.role === "ADMIN" ? (
                    <Link to="/settings" className="underline">
                      Register one in Settings.
                    </Link>
                  ) : (
                    "Ask an admin to register one."
                  )}
                </p>
              ) : (
                <StartScanForm accounts={list} onStarted={reload} />
              )
            }
          </Loaded>
        </Card>
      )}

      <div className="overflow-x-auto rounded-lg border border-slate-200 bg-white">
        <Loaded state={scans.state} what="scans" onRetry={reload}>
          {(page) =>
            page.items.length === 0 ? (
              <EmptyState>No scans yet.</EmptyState>
            ) : (
              <>
                <table className="w-full text-left text-sm">
                  <thead className="border-b border-slate-200 text-slate-600">
                    <tr>
                      <th className="px-4 py-2 font-medium">Started</th>
                      <th className="px-4 py-2 font-medium">AWS account</th>
                      <th className="px-4 py-2 font-medium">Status</th>
                      <th className="px-4 py-2 text-right font-medium">Resources</th>
                      <th className="px-4 py-2 text-right font-medium">Findings</th>
                      <th className="px-4 py-2 font-medium">Finished</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {page.items.map((scan) => (
                      <tr key={scan.id}>
                        <td className="px-4 py-2">
                          <Link to={`/scans/${scan.id}`} className="underline">
                            {formatDateTime(scan.created_at, true)}
                          </Link>
                        </td>
                        <td className="px-4 py-2">{accountNames.get(scan.aws_account_id) ?? "—"}</td>
                        <td className="px-4 py-2">
                          <ScanStatusBadge status={scan.status} />
                        </td>
                        <td className="px-4 py-2 text-right tabular-nums">{scan.resource_count}</td>
                        <td className="px-4 py-2 text-right tabular-nums">{scan.finding_count}</td>
                        <td className="whitespace-nowrap px-4 py-2">{formatDateTime(scan.finished_at, true)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                <Pagination total={page.total} offset={offset} limit={PAGE_SIZE} onChange={setOffset} />
              </>
            )
          }
        </Loaded>
      </div>
    </section>
  );
}
