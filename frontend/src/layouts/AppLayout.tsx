import { Link, Outlet } from "react-router-dom";

import { useAuth } from "../auth/AuthContext";

export default function AppLayout() {
  const { state, signOut } = useAuth();
  if (state.status !== "authenticated") {
    return null;
  }
  const { user } = state;

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900">
      <header className="border-b border-slate-200 bg-white">
        <div className="mx-auto flex max-w-4xl items-center justify-between px-6 py-4">
          <div className="flex items-center gap-6">
            <Link to="/" className="text-lg font-semibold tracking-tight">
              CloudSentinel
            </Link>
            {user.role === "ADMIN" && (
              <Link to="/users" className="text-sm text-slate-700 underline">
                Users
              </Link>
            )}
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
      <main className="mx-auto max-w-4xl px-6 py-8">
        <Outlet />
      </main>
    </div>
  );
}
