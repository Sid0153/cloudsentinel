import { useEffect, useState, type FormEvent } from "react";

import { useAuth } from "../auth/AuthContext";
import { ApiError } from "../services/api";
import { createUser, listUsers, updateUser } from "../services/users";
import type { Role, User } from "../types/auth";

const ROLES: Role[] = ["VIEWER", "ANALYST", "ADMIN"];

function describeCreateError(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 409) return "A user with this email already exists.";
    if (error.status === 422) return "Check the email address and use a password of 12 to 128 characters.";
  }
  return "Could not create the user. Please try again.";
}

function CreateUserForm({ onCreated }: { onCreated: () => void }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<Role>("VIEWER");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      await createUser({ email, password, role });
      setEmail("");
      setPassword("");
      setRole("VIEWER");
      onCreated();
    } catch (caught) {
      setError(describeCreateError(caught));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="mt-6 rounded-lg border border-slate-200 bg-white p-5">
      <h2 className="text-lg font-semibold">Create user</h2>
      <div className="mt-3 grid gap-3 sm:grid-cols-3">
        <div>
          <label htmlFor="new-email" className="block text-sm font-medium">
            New user email
          </label>
          <input
            id="new-email"
            type="email"
            required
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            className="mt-1 w-full rounded border border-slate-300 px-3 py-2 text-sm"
          />
        </div>
        <div>
          <label htmlFor="new-password" className="block text-sm font-medium">
            Initial password
          </label>
          <input
            id="new-password"
            type="password"
            autoComplete="new-password"
            required
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            className="mt-1 w-full rounded border border-slate-300 px-3 py-2 text-sm"
          />
        </div>
        <div>
          <label htmlFor="new-role" className="block text-sm font-medium">
            Role
          </label>
          <select
            id="new-role"
            value={role}
            onChange={(event) => setRole(event.target.value as Role)}
            className="mt-1 w-full rounded border border-slate-300 px-3 py-2 text-sm"
          >
            {ROLES.map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
        </div>
      </div>
      {error && (
        <p role="alert" className="mt-3 text-sm text-red-700">
          {error}
        </p>
      )}
      <button
        type="submit"
        disabled={submitting}
        className="mt-4 rounded bg-slate-900 px-3 py-2 text-sm font-medium text-white disabled:opacity-60"
      >
        Create user
      </button>
    </form>
  );
}

/** Role and active flag for one user. Your own row is read-only (the API refuses it too). */
function UserRow({ user, isSelf, onChanged }: { user: User; isSelf: boolean; onChanged: () => void }) {
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function change(changes: { role?: Role; is_active?: boolean }) {
    setBusy(true);
    setError(null);
    try {
      await updateUser(user.id, changes);
      onChanged();
    } catch {
      setError("Could not update this user.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <tr>
      <td className="px-4 py-2">
        {user.email}
        {isSelf && <span className="ml-2 text-xs text-slate-500">(you)</span>}
        {error && (
          <p role="alert" className="text-xs text-red-700">
            {error}
          </p>
        )}
      </td>
      <td className="px-4 py-2">
        <label className="sr-only" htmlFor={`role-${user.id}`}>
          Role of {user.email}
        </label>
        <select
          id={`role-${user.id}`}
          value={user.role}
          disabled={isSelf || busy}
          onChange={(event) => void change({ role: event.target.value as Role })}
          className="rounded border border-slate-300 px-2 py-1 text-sm disabled:bg-slate-50"
        >
          {ROLES.map((value) => (
            <option key={value} value={value}>
              {value}
            </option>
          ))}
        </select>
      </td>
      <td className="px-4 py-2">
        {user.is_active ? "Yes" : "No"}
        {!isSelf && (
          <button
            type="button"
            disabled={busy}
            onClick={() => void change({ is_active: !user.is_active })}
            className="ml-3 rounded border border-slate-300 px-2 py-0.5 text-xs disabled:opacity-60"
          >
            {user.is_active ? "Deactivate" : "Activate"}
          </button>
        )}
      </td>
    </tr>
  );
}

export default function UsersPage() {
  const { state: auth } = useAuth();
  const selfId = auth.status === "authenticated" ? auth.user.id : null;
  const [users, setUsers] = useState<User[] | null>(null);
  const [loadFailed, setLoadFailed] = useState(false);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    let cancelled = false;
    listUsers()
      .then((data) => {
        if (cancelled) return;
        setUsers(data);
        setLoadFailed(false);
      })
      .catch(() => {
        if (!cancelled) setLoadFailed(true);
      });
    return () => {
      cancelled = true;
    };
  }, [reloadKey]);

  return (
    <section>
      <h1 className="text-2xl font-semibold tracking-tight">Users</h1>
      <p className="mt-1 text-sm text-slate-600">
        Accounts that can sign in to CloudSentinel. Deactivating a user ends their sessions at once.
      </p>

      <div className="mt-6 overflow-x-auto rounded-lg border border-slate-200 bg-white">
        {loadFailed && (
          <p role="alert" className="p-4 text-sm text-red-700">
            Could not load users.
          </p>
        )}
        {!loadFailed && users === null && (
          <p role="status" className="p-4 text-sm text-slate-600">
            Loading users…
          </p>
        )}
        {users !== null && (
          <table className="w-full text-left text-sm">
            <thead className="border-b border-slate-200 text-slate-600">
              <tr>
                <th className="px-4 py-2 font-medium">Email</th>
                <th className="px-4 py-2 font-medium">Role</th>
                <th className="px-4 py-2 font-medium">Active</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {users.map((user) => (
                <UserRow
                  key={user.id}
                  user={user}
                  isSelf={user.id === selfId}
                  onChanged={() => setReloadKey((key) => key + 1)}
                />
              ))}
            </tbody>
          </table>
        )}
      </div>

      <CreateUserForm onCreated={() => setReloadKey((key) => key + 1)} />
    </section>
  );
}
