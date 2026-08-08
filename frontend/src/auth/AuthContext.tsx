import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import {
  getCurrentUser,
  login as loginRequest,
  logout as logoutRequest,
} from "../api/auth";
import { ApiError, initializeCsrf, setCsrfToken } from "../api/client";
import type { AuthUser, UserRole } from "../api/types";

interface AuthContextValue {
  user: AuthUser | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  hasRole: (...roles: UserRole[]) => boolean;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);

  const clearSession = useCallback(() => {
    setUser(null);
    setCsrfToken(null);
  }, []);

  useEffect(() => {
    let active = true;
    Promise.all([initializeCsrf(), getCurrentUser()])
      .then(([, currentUser]) => {
        if (active) setUser(currentUser);
      })
      .catch((error: unknown) => {
        if (active && !(error instanceof ApiError && error.status >= 500)) {
          clearSession();
        }
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [clearSession]);

  useEffect(() => {
    const onSessionExpired = () => clearSession();
    window.addEventListener("msap:session-expired", onSessionExpired);
    return () =>
      window.removeEventListener("msap:session-expired", onSessionExpired);
  }, [clearSession]);

  const login = useCallback(async (username: string, password: string) => {
    const authenticatedUser = await loginRequest(username, password);
    try {
      const currentUser = await getCurrentUser();
      setUser({ ...authenticatedUser, ...currentUser });
    } catch (error) {
      clearSession();
      throw error;
    }
  }, [clearSession]);

  const logout = useCallback(async () => {
    try {
      await logoutRequest();
    } finally {
      clearSession();
    }
  }, [clearSession]);

  const value = useMemo<AuthContextValue>(
    () => ({
      user,
      loading,
      login,
      logout,
      hasRole: (...roles) => Boolean(user && roles.includes(user.role)),
    }),
    [user, loading, login, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used within AuthProvider.");
  return context;
}
