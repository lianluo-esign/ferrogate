import {
  loginAdminAccount,
  logoutAdminSession,
  refreshAdminSession,
  registerAdminAccount,
} from "@/lib/auth-client";
import {
  type StoredSession,
  applyRefreshResponse,
  clearStoredSession,
  loadStoredSession,
  saveStoredSession,
  sessionFromResponse,
} from "@/lib/session-storage";
import type { AdminLoginRequest, AdminRegisterRequest } from "@/types/auth";
import {
  type ReactNode,
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
} from "react";

const REFRESH_SAFETY_MARGIN_MS = 30_000;

interface AuthContextValue {
  session: StoredSession | null;
  isLoading: boolean;
  login: (payload: AdminLoginRequest) => Promise<void>;
  register: (payload: AdminRegisterRequest) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<StoredSession | null>(() => loadStoredSession());
  const [isLoading, setIsLoading] = useState(false);
  const refreshTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const scheduleRefresh = useCallback((current: StoredSession) => {
    if (refreshTimer.current) clearTimeout(refreshTimer.current);
    const delay = Math.max(current.expiresAt - Date.now() - REFRESH_SAFETY_MARGIN_MS, 0);
    refreshTimer.current = setTimeout(async () => {
      try {
        const response = await refreshAdminSession(current.refreshToken);
        const next = applyRefreshResponse(current, response);
        saveStoredSession(next);
        setSession(next);
        scheduleRefresh(next);
      } catch {
        clearStoredSession();
        setSession(null);
      }
    }, delay);
  }, []);

  // biome-ignore lint/correctness/useExhaustiveDependencies: mount-once effect — scheduleRefresh is stable (useCallback with []) and re-running on every session change would tear down and rebuild the refresh timer chain
  useEffect(() => {
    if (session) scheduleRefresh(session);
    return () => {
      if (refreshTimer.current) clearTimeout(refreshTimer.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const login = useCallback(
    async (payload: AdminLoginRequest) => {
      setIsLoading(true);
      try {
        const response = await loginAdminAccount(payload);
        const next = sessionFromResponse(response);
        saveStoredSession(next);
        setSession(next);
        scheduleRefresh(next);
      } finally {
        setIsLoading(false);
      }
    },
    [scheduleRefresh],
  );

  const register = useCallback(
    async (payload: AdminRegisterRequest) => {
      setIsLoading(true);
      try {
        const response = await registerAdminAccount(payload);
        const next = sessionFromResponse(response);
        saveStoredSession(next);
        setSession(next);
        scheduleRefresh(next);
      } finally {
        setIsLoading(false);
      }
    },
    [scheduleRefresh],
  );

  const logout = useCallback(async () => {
    if (refreshTimer.current) clearTimeout(refreshTimer.current);
    if (session) {
      try {
        await logoutAdminSession(session.refreshToken);
      } catch {
        // best-effort: still clear local session below
      }
    }
    clearStoredSession();
    setSession(null);
  }, [session]);

  return (
    <AuthContext.Provider value={{ session, isLoading, login, register, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used within an AuthProvider");
  return context;
}
