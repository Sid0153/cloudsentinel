import { Link, NavLink, Outlet } from "react-router-dom";

import { useAbout } from "../about/AboutContext";
import { useAuth } from "../auth/AuthContext";

const NAV = [
  { to: "/", label: "Dashboard", end: true },
  { to: "/findings", label: "Findings", end: false },
  { to: "/resources", label: "Resources", end: false },
  { to: "/scans", label: "Scans", end: false },
  { to: "/settings", label: "Settings", end: false },
];

function navClass({ isActive }: { isActive: boolean }): string {
  return `rounded px-2 py-1 text-sm ${
    isActive ? "bg-slate-900 font-medium text-white" : "text-slate-700 hover:bg-slate-100"
  }`;
}

export default function AppLayout() {
  const { state, signOut } = useAuth();
  const about = useAbout();
  if (state.status !== "authenticated") {
    return null;
  }
  const { user } = state;

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900">
      <header className="border-b border-slate-200 bg-white">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-3 px-6 py-3">
          <div className="flex flex-wrap items-center gap-4">
            <Link to="/" className="text-lg font-semibold tracking-tight">
              CloudSentinel
            </Link>
            <nav aria-label="Main" className="flex flex-wrap gap-1">
              {NAV.map((item) => (
                <NavLink key={item.to} to={item.to} end={item.end} className={navClass}>
                  {item.label}
                </NavLink>
              ))}
              {about?.sandbox_mode && (
                <NavLink to="/sandbox" className={navClass}>
                  Sandbox
                </NavLink>
              )}
              {user.role === "ADMIN" && (
                <>
                  <NavLink to="/users" className={navClass}>
                    Users
                  </NavLink>
                  <NavLink to="/audit" className={navClass}>
                    Audit log
                  </NavLink>
                </>
              )}
            </nav>
          </div>
          <div className="flex items-center gap-3 text-sm">
            <span>{user.email}</span>
            <span className="rounded bg-slate-100 px-2 py-0.5 text-xs font-medium">{user.role}</span>
            <button
              type="button"
              onClick={() => void signOut()}
              className="rounded border border-slate-300 px-2 py-1"
            >
              Sign out
            </button>
          </div>
        </div>
      </header>
      {about?.sandbox_mode && (
        <div role="note" className="border-b border-amber-200 bg-amber-50">
          <p className="mx-auto max-w-6xl px-6 py-2 text-sm text-amber-900">
            Sandbox mode: scans run against a simulated AWS account, not a real one. Change its
            settings on the{" "}
            <Link to="/sandbox" className="font-medium underline">
              Sandbox
            </Link>{" "}
            page, then start a scan.
          </p>
        </div>
      )}
      <main className="mx-auto max-w-6xl px-6 py-8">
        <Outlet />
      </main>
    </div>
  );
}
