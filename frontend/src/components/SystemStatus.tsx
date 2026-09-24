import StatusRow from "./StatusRow";
import { useReadiness } from "../hooks/useReadiness";

export default function SystemStatus() {
  const state = useReadiness();

  return (
    <section className="rounded-lg border border-slate-200 bg-white p-5">
      <h2 className="text-sm font-semibold text-slate-700">System status</h2>
      <p className="mt-1 text-sm text-slate-600">Live readiness check from the backend.</p>

      <div>
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
