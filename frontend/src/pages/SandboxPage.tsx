import { useState } from "react";
import { Link } from "react-router-dom";

import { useAbout } from "../about/AboutContext";
import { useAuth } from "../auth/AuthContext";
import { Card, EmptyState, Loaded, PageHeader, secondaryButtonClass } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { ApiError } from "../services/api";
import { getSandbox, resetSandbox, setSandboxControl } from "../services/sandbox";
import type { SandboxControl } from "../types/api";

function describeError(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 429) return "Too many changes from your connection. Wait a minute and try again.";
    if (error.status === 503)
      return "The simulated AWS is not reachable right now (it may be starting up). Try again in a minute.";
    if (error.status === 403) return "Your role can look at the sandbox but not change it.";
  }
  return "Could not change the sandbox. Please try again.";
}

function StateBadge({ insecure }: { insecure: boolean }) {
  return insecure ? (
    <span className="rounded bg-red-100 px-2 py-0.5 text-xs font-medium text-red-800">Insecure</span>
  ) : (
    <span className="rounded bg-emerald-100 px-2 py-0.5 text-xs font-medium text-emerald-800">Secure</span>
  );
}

function ControlRow({ control, canChange, disabled, saving, onToggle }: {
  control: SandboxControl;
  canChange: boolean;
  disabled: boolean;
  saving: boolean;
  onToggle: () => void;
}) {
  return (
    <li className="flex flex-wrap items-start justify-between gap-3 py-4">
      <div className="min-w-0 flex-1 basis-64">
        <div className="flex flex-wrap items-center gap-2">
          <h3 className="font-medium">{control.title}</h3>
          <StateBadge insecure={control.insecure} />
        </div>
        <p className="mt-1 text-sm text-slate-600">
          <span className="font-medium">When insecure:</span> {control.description}
        </p>
        <p className="mt-1 text-xs text-slate-500">
          Checked by rule{" "}
          <Link to={`/findings?rule_id=${control.rule_id}`} className="underline">
            {control.rule_id}
          </Link>
          {" · "}default: {control.insecure_by_default ? "insecure" : "secure"}
        </p>
      </div>
      {canChange && (
        <button type="button" disabled={disabled} onClick={onToggle} className={secondaryButtonClass}>
          {saving ? "Saving…" : control.insecure ? "Fix it" : "Make insecure"}
        </button>
      )}
    </li>
  );
}

export default function SandboxPage() {
  const about = useAbout();
  const { state: auth } = useAuth();
  const canChange = auth.status === "authenticated" && auth.user.role !== "VIEWER";
  const { state, reload, setState } = useApi(getSandbox, "sandbox");
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  if (about !== null && !about.sandbox_mode) {
    return (
      <div className="space-y-6">
        <PageHeader title="Sandbox" />
        <Card>
          <EmptyState>Sandbox mode is off on this server: scans use real AWS accounts.</EmptyState>
        </Card>
      </div>
    );
  }

  async function run(key: string, change: () => Promise<void>) {
    setBusy(key);
    setError(null);
    try {
      await change();
    } catch (caught) {
      setError(describeError(caught));
    } finally {
      setBusy(null);
    }
  }

  function toggle(control: SandboxControl) {
    void run(control.key, async () => {
      const updated = await setSandboxControl(control.key, !control.insecure);
      setState((current) =>
        current.kind === "loaded"
          ? {
              kind: "loaded",
              data: {
                ...current.data,
                controls: current.data.controls.map((c) => (c.key === updated.key ? updated : c)),
              },
            }
          : current,
      );
    });
  }

  function reset() {
    void run("reset", async () => {
      setState({ kind: "loaded", data: await resetSandbox() });
    });
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Sandbox"
        description="A simulated AWS account that this demo scans instead of a real one."
        actions={
          canChange && (
            <button
              type="button"
              disabled={busy !== null}
              onClick={reset}
              className={secondaryButtonClass}
            >
              {busy === "reset" ? "Resetting…" : "Reset to defaults"}
            </button>
          )
        }
      />

      <Card>
        <p className="text-sm text-slate-700">
          Each switch changes one setting in the simulated account. Make something insecure (or
          fix it), then <Link to="/scans" className="font-medium underline">start a scan</Link>:
          the matching finding opens, or closes once the scan confirms the fix.
        </p>
        {!canChange && (
          <p className="mt-2 text-sm text-slate-600">Your role can look at the switches but not change them.</p>
        )}
      </Card>

      {error && (
        <p role="alert" className="text-sm text-red-700">
          {error}
        </p>
      )}

      <Card>
        <Loaded state={state} what="the sandbox" onRetry={reload}>
          {(data) => (
            <>
              <p className="text-xs text-slate-500">
                Simulated account {data.account_id} · {data.region}
              </p>
              <ul className="divide-y divide-slate-100">
                {data.controls.map((control) => (
                  <ControlRow
                    key={control.key}
                    control={control}
                    canChange={canChange}
                    disabled={busy !== null}
                    saving={busy === control.key}
                    onToggle={() => toggle(control)}
                  />
                ))}
              </ul>
            </>
          )}
        </Loaded>
      </Card>
    </div>
  );
}
