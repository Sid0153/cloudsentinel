import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

import { onSessionExpired } from "../services/api";
import { guestLogin, login, logout, refreshSession } from "../services/auth";
import type { User } from "../types/auth";

type AuthState =
  | { status: "loading" }
  | { status: "unauthenticated" }
  | { status: "authenticated"; user: User };

interface AuthContextValue {
  state: AuthState;
  signIn: (email: string, password: string) => Promise<void>;
  signInAsGuest: () => Promise<void>;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>({ status: "loading" });

  useEffect(() => {
    let cancelled = false;
    // On page load the access token is gone; the refresh cookie may restore the session.
    refreshSession()
      .then((user) => {
        if (!cancelled) setState({ status: "authenticated", user });
      })
      .catch(() => {
        if (!cancelled) setState({ status: "unauthenticated" });
      });
    onSessionExpired(() => setState({ status: "unauthenticated" }));
    return () => {
      cancelled = true;
      onSessionExpired(null);
    };
  }, []);

  const signIn = useCallback(async (email: string, password: string) => {
    const user = await login(email, password);
    setState({ status: "authenticated", user });
  }, []);

  const signInAsGuest = useCallback(async () => {
    const user = await guestLogin();
    setState({ status: "authenticated", user });
  }, []);

  const signOut = useCallback(async () => {
    try {
      await logout();
    } catch {
      // Even if the server cannot be reached, this browser forgets the session.
    }
    setState({ status: "unauthenticated" });
  }, []);

  const value = useMemo(
    () => ({ state, signIn, signInAsGuest, signOut }),
    [state, signIn, signInAsGuest, signOut],
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (context === null) {
    throw new Error("useAuth must be used inside <AuthProvider>");
  }
  return context;
}
