import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { getSystemStatus } from "../api/msap";
import type { SystemStatus } from "../api/types";

interface SystemStatusValue {
  status: SystemStatus | null;
  loading: boolean;
  refreshing: boolean;
  refresh: () => Promise<void>;
}

const StatusContext = createContext<SystemStatusValue | null>(null);
const POLL_INTERVAL_MS = 5_000;

export function SystemStatusProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const mounted = useRef(true);

  const load = useCallback(async (force = false) => {
    if (force) setRefreshing(true);
    try {
      const next = await getSystemStatus(force);
      if (mounted.current) setStatus(next);
    } catch {
      // Preserve the last known state. The API component becomes unavailable
      // in the view after a stale interval instead of exposing raw errors.
    } finally {
      if (mounted.current) {
        setLoading(false);
        setRefreshing(false);
      }
    }
  }, []);

  useEffect(() => {
    mounted.current = true;
    void load();
    let timer: number | undefined;
    const schedule = () => {
      if (timer) window.clearInterval(timer);
      timer = undefined;
      if (document.visibilityState === "visible") {
        timer = window.setInterval(() => void load(), POLL_INTERVAL_MS);
      }
    };
    const onVisibility = () => {
      schedule();
      if (document.visibilityState === "visible") void load();
    };
    document.addEventListener("visibilitychange", onVisibility);
    schedule();
    return () => {
      mounted.current = false;
      if (timer) window.clearInterval(timer);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [load]);

  const value = useMemo(
    () => ({
      status,
      loading,
      refreshing,
      refresh: () => load(true),
    }),
    [status, loading, refreshing, load],
  );

  return (
    <StatusContext.Provider value={value}>{children}</StatusContext.Provider>
  );
}

export function useSystemStatus() {
  const context = useContext(StatusContext);
  if (!context) {
    throw new Error(
      "useSystemStatus must be used within SystemStatusProvider.",
    );
  }
  return context;
}
