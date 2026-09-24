import { useState, type FormEvent } from "react";

import { useAuth } from "../auth/AuthContext";
import { SeverityBadge } from "../components/Badges";
import SystemStatus from "../components/SystemStatus";
import { formatDateTime, humanize, shortType } from "../components/format";
import {
  Card,
  EmptyState,
  Loaded,
  PageHeader,
  ScrollX,
  buttonClass,
  inputClass,
  secondaryButtonClass,
} from "../components/ui";
import { useApi } from "../hooks/useApi";
import { changePassword } from "../services/account";
import { ApiError } from "../services/api";
import { createAwsAccount, listAwsAccounts, verifyAwsAccount } from "../services/awsAccounts";
import { listRules } from "../services/rules";
import type { AwsAccount, AwsAccountVerification } from "../types/api";

function PasswordForm() {
  const { signOut } = useAuth();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSaving(true);
    setError(null);
    try {
      await changePassword(current, next);
      // The server has ended every session, including this one.
      await signOut();
    } catch (caught) {
      if (caught instanceof ApiError && caught.status === 400) setError("The current password is incorrect.");
      else if (caught instanceof ApiError && caught.status === 422)
        setError("The new password must be 12 to 128 characters.");
      else setError("Could not change the password. Please try again.");
      setSaving(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="mt-4 grid gap-3 sm:grid-cols-[1fr_1fr_auto] sm:items-end">
      <div>
        <label htmlFor="current-password" className="block text-sm font-medium">
          Current password
        </label>
        <input
          id="current-password"
          type="password"
          autoComplete="current-password"
          required
          value={current}
          onChange={(e) => setCurrent(e.target.value)}
          className={`${inputClass} mt-1 w-full`}
        />
      </div>
      <div>
        <label htmlFor="new-password" className="block text-sm font-medium">
          New password
        </label>
        <input
          id="new-password"
          type="password"
          autoComplete="new-password"
          required
          minLength={12}
          maxLength={128}
          value={next}
          onChange={(e) => setNext(e.target.value)}
          className={`${inputClass} mt-1 w-full`}
        />
      </div>
      <button type="submit" disabled={saving} className={buttonClass}>
        Change password
      </button>
      {error && (
        <p role="alert" className="text-sm text-red-700 sm:col-span-3">
          {error}
        </p>
      )}
      <p className="text-xs text-slate-500 sm:col-span-3">
        Changing the password signs you out everywhere, including here.
      </p>
    </form>
  );
}

function describeAccountError(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 409) return "This AWS account is already registered.";
    if (error.status === 422)
      return "Check the values: a 12-digit account ID, valid region names and, if given, an IAM role ARN.";
  }
  return "Could not register the account. Please try again.";
}

function RegisterAccountForm({ onCreated }: { onCreated: () => void }) {
  const [accountId, setAccountId] = useState("");
  const [name, setName] = useState("");
  const [regions, setRegions] = useState("us-east-1");
  const [roleArn, setRoleArn] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSaving(true);
    setError(null);
    try {
      await createAwsAccount({
        account_id: accountId.trim(),
        name: name.trim(),
        regions: regions.split(",").map((r) => r.trim()).filter(Boolean),
        role_arn: roleArn.trim() || null,
      });
      setAccountId("");
      setName("");
      setRoleArn("");
      onCreated();
    } catch (caught) {
      setError(describeAccountError(caught));
    } finally {
      setSaving(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="mt-4 space-y-3 border-t border-slate-100 pt-4">
      <h3 className="text-sm font-semibold">Register an AWS account</h3>
      <div className="grid gap-3 sm:grid-cols-2">
        <div>
          <label htmlFor="aws-account-id" className="block text-sm font-medium">
            Account ID
          </label>
          <input
            id="aws-account-id"
            required
            inputMode="numeric"
            pattern="\d{12}"
            title="12 digits"
            value={accountId}
            onChange={(e) => setAccountId(e.target.value)}
            className={`${inputClass} mt-1 w-full`}
          />
        </div>
        <div>
          <label htmlFor="aws-account-name" className="block text-sm font-medium">
            Name
          </label>
          <input
            id="aws-account-name"
            required
            maxLength={100}
            value={name}
            onChange={(e) => setName(e.target.value)}
            className={`${inputClass} mt-1 w-full`}
          />
        </div>
        <div>
          <label htmlFor="aws-regions" className="block text-sm font-medium">
            Regions (comma-separated)
          </label>
          <input
            id="aws-regions"
            required
            value={regions}
            onChange={(e) => setRegions(e.target.value)}
            className={`${inputClass} mt-1 w-full`}
          />
        </div>
        <div>
          <label htmlFor="aws-role-arn" className="block text-sm font-medium">
            Role ARN to assume (optional)
          </label>
          <input
            id="aws-role-arn"
            value={roleArn}
            placeholder="arn:aws:iam::123456789012:role/CloudSentinelReadOnly"
            onChange={(e) => setRoleArn(e.target.value)}
            className={`${inputClass} mt-1 w-full`}
          />
        </div>
      </div>
      {error && (
        <p role="alert" className="text-sm text-red-700">
          {error}
        </p>
      )}
      <button type="submit" disabled={saving} className={buttonClass}>
        Register account
      </button>
      <p className="text-xs text-slate-500">
        No credentials are entered here. The backend uses the standard AWS credential chain; see
        docs/aws-permissions.md for the read-only policy.
      </p>
    </form>
  );
}

function VerifyButton({ account }: { account: AwsAccount }) {
  const [result, setResult] = useState<AwsAccountVerification | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function verify() {
    setBusy(true);
    setError(null);
    try {
      setResult(await verifyAwsAccount(account.id));
    } catch (caught) {
      setResult(null);
      setError(caught instanceof ApiError && caught.status === 502 ? "AWS access failed." : "Could not verify.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="text-right">
      <button type="button" onClick={() => void verify()} disabled={busy} className={secondaryButtonClass}>
        Verify access
      </button>
      {result && (
        <p role="status" className={`mt-1 text-xs ${result.matches ? "text-emerald-700" : "text-red-700"}`}>
          {result.matches
            ? `OK: credentials resolve to account ${result.caller_account_id}`
            : `Mismatch: credentials belong to ${result.caller_account_id}`}
        </p>
      )}
      {error && (
        <p role="alert" className="mt-1 text-xs text-red-700">
          {error}
        </p>
      )}
    </div>
  );
}

function AwsAccounts({ isAdmin }: { isAdmin: boolean }) {
  const { state, reload } = useApi(listAwsAccounts, "accounts");
  return (
    <Card title="AWS accounts">
      <Loaded state={state} what="AWS accounts" onRetry={reload}>
        {(accounts) =>
          accounts.length === 0 ? (
            <EmptyState>No AWS account is registered yet.</EmptyState>
          ) : (
            <ul className="divide-y divide-slate-100">
              {accounts.map((account) => (
                <li key={account.id} className="flex flex-wrap items-start justify-between gap-3 py-3 text-sm">
                  <div>
                    <p className="font-medium">
                      {account.name} <span className="font-mono text-xs text-slate-600">{account.account_id}</span>
                    </p>
                    <p className="text-xs text-slate-600">
                      Regions: {account.regions.join(", ")}
                      {account.role_arn && <> · Assumes {account.role_arn}</>} · Added{" "}
                      {formatDateTime(account.created_at)}
                    </p>
                  </div>
                  {isAdmin && <VerifyButton account={account} />}
                </li>
              ))}
            </ul>
          )
        }
      </Loaded>
      {isAdmin && <RegisterAccountForm onCreated={reload} />}
    </Card>
  );
}

function RuleCatalog() {
  const { state, reload } = useApi(listRules, "rules");
  return (
    <Card title="Security rules">
      <p className="mb-3 text-sm text-slate-600">
        The checks every scan runs. Rules are read-only here; they are defined in security-rules/.
      </p>
      <Loaded state={state} what="rules" onRetry={reload}>
        {(rules) => (
          <ScrollX>
          <table className="w-full text-left text-sm">
            <thead className="text-slate-600">
              <tr>
                <th className="py-1 pr-3 font-medium">Rule</th>
                <th className="py-1 pr-3 font-medium">Category</th>
                <th className="py-1 pr-3 font-medium">Applies to</th>
                <th className="py-1 font-medium">Default severity</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {rules.map((rule) => (
                <tr key={rule.id}>
                  <td className="py-1.5 pr-3">
                    <span className="font-medium">{rule.id}</span> {rule.title}
                  </td>
                  <td className="py-1.5 pr-3">{humanize(rule.category)}</td>
                  <td className="py-1.5 pr-3">{rule.resource_types.map(shortType).join(", ")}</td>
                  <td className="py-1.5">
                    <SeverityBadge severity={rule.severity} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          </ScrollX>
        )}
      </Loaded>
    </Card>
  );
}

export default function SettingsPage() {
  const { state } = useAuth();
  if (state.status !== "authenticated") return null;
  const isAdmin = state.user.role === "ADMIN";

  return (
    <section className="space-y-6">
      <PageHeader title="Settings" />
      <Card title="Your account">
        <p className="text-sm">
          {state.user.email} · <span className="font-medium">{humanize(state.user.role)}</span>
        </p>
        <PasswordForm />
      </Card>
      <AwsAccounts isAdmin={isAdmin} />
      <RuleCatalog />
      <SystemStatus />
    </section>
  );
}
