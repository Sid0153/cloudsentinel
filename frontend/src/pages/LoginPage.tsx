import { useState, type FormEvent } from "react";
import { Navigate, useLocation } from "react-router-dom";

import { useAbout } from "../about/AboutContext";
import { useAuth } from "../auth/AuthContext";
import { ApiError } from "../services/api";

function describeError(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 401) return "Incorrect email or password.";
    if (error.status === 429) return "Too many attempts. Wait a minute and try again.";
    if (error.status === 403 || error.status === 404) return "Guest access is not available right now.";
  }
  return "Could not sign in. Please try again.";
}

export default function LoginPage() {
  const { state, signIn, signInAsGuest } = useAuth();
  const about = useAbout();
  const location = useLocation();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  if (state.status === "authenticated") {
    const from = (location.state as { from?: string } | null)?.from ?? "/";
    return <Navigate to={from} replace />;
  }

  async function attempt(signInWith: () => Promise<void>) {
    setSubmitting(true);
    setError(null);
    try {
      await signInWith();
    } catch (caught) {
      setError(describeError(caught));
    } finally {
      setSubmitting(false);
    }
  }

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void attempt(() => signIn(email, password));
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-50 px-4">
      <form
        onSubmit={handleSubmit}
        className="w-full max-w-sm rounded-lg border border-slate-200 bg-white p-6"
      >
        <h1 className="text-2xl font-semibold tracking-tight">Sign in</h1>
        <p className="mt-1 text-sm text-slate-600">CloudSentinel</p>
        {about?.sandbox_mode && (
          <p className="mt-3 rounded bg-amber-50 px-3 py-2 text-sm text-amber-900">
            Demo server: scans run against a simulated AWS account, not a real one.
          </p>
        )}

        <label htmlFor="email" className="mt-5 block text-sm font-medium">
          Email
        </label>
        <input
          id="email"
          type="email"
          autoComplete="username"
          required
          value={email}
          onChange={(event) => setEmail(event.target.value)}
          className="mt-1 w-full rounded border border-slate-300 px-3 py-2 text-sm"
        />

        <label htmlFor="password" className="mt-4 block text-sm font-medium">
          Password
        </label>
        <input
          id="password"
          type="password"
          autoComplete="current-password"
          required
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          className="mt-1 w-full rounded border border-slate-300 px-3 py-2 text-sm"
        />

        {error && (
          <p role="alert" className="mt-4 text-sm text-red-700">
            {error}
          </p>
        )}

        <button
          type="submit"
          disabled={submitting}
          className="mt-5 w-full rounded bg-slate-900 px-3 py-2 text-sm font-medium text-white disabled:opacity-60"
        >
          {submitting ? "Signing in…" : "Sign in"}
        </button>

        {about?.guest_access && (
          <div className="mt-5 border-t border-slate-200 pt-5">
            <button
              type="button"
              disabled={submitting}
              onClick={() => void attempt(signInAsGuest)}
              className="w-full rounded border border-slate-300 px-3 py-2 text-sm font-medium disabled:opacity-60"
            >
              Explore as guest
            </button>
            <p className="mt-2 text-xs text-slate-600">
              No account needed. The guest is a shared ANALYST account: look around, start scans and
              change the sandbox. It cannot manage users or read the audit log.
            </p>
          </div>
        )}
      </form>
    </div>
  );
}
