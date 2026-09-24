import { Navigate, Outlet, useLocation } from "react-router-dom";

import { useAuth } from "./AuthContext";

/** Wraps routes that need a signed-in user. The server still enforces access on every API call. */
export default function ProtectedRoute() {
  const { state } = useAuth();
  const location = useLocation();

  if (state.status === "loading") {
    return (
      <p role="status" className="p-6 text-sm text-slate-600">
        Loading…
      </p>
    );
  }
  if (state.status === "unauthenticated") {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  }
  return <Outlet />;
}
