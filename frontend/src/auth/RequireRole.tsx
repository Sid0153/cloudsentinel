import { Outlet } from "react-router-dom";

import type { Role } from "../types/auth";
import { useAuth } from "./AuthContext";

/** Hides pages the user's role cannot use. This is a courtesy: the API enforces the real rule. */
export default function RequireRole({ allowed }: { allowed: Role[] }) {
  const { state } = useAuth();
  if (state.status !== "authenticated" || !allowed.includes(state.user.role)) {
    return (
      <section>
        <h1 className="text-2xl font-semibold tracking-tight">Not authorized</h1>
        <p className="mt-1 text-sm text-slate-600">Your role does not have access to this page.</p>
      </section>
    );
  }
  return <Outlet />;
}
