import StatusRow from "../components/StatusRow";
import { useReadiness } from "../hooks/useReadiness";

export default function StatusPage() {
  const state = useReadiness();

  return (
    <section>
      <h1 className="text-2xl font-semibold tracking-tight">System status</h1>
      <p className="mt-1 text-sm text-slate-600">
        Live readiness check from the backend. Scanning features arrive in later phases.
      </p>

      <div className="mt-6 rounded-lg border border-slate-200 bg-white px-5">
        {state.kind === "loading" && (
          <p role="status" className="py-4 text-sm text-slate-600">
            Checking API status…
          </p>
        )}

        {state.kind === "error" && (
          <p role="alert" className="py-4 text-sm text-red-700">
            {state.message}
          </p>
        )}

        {state.kind === "loaded" && (
          <dl className="divide-y divide-slate-100">
            <StatusRow label="API" value="Online" healthy />
            <StatusRow
              label="Database"
              value={state.health.database === "up" ? "Connected" : "Unreachable"}
              healthy={state.health.database === "up"}
            />
          </dl>
        )}
      </div>
    </section>
  );
}
