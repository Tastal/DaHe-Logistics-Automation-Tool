import {
  useCallback,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { createPortal } from "react-dom";
import { ToastContext, type ToastTone } from "./ToastContext";

interface ToastEntry {
  id: number;
  message: string;
  tone: ToastTone;
  closing: boolean;
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [entry, setEntry] = useState<ToastEntry | null>(null);
  const sequence = useRef(0);
  const timers = useRef<number[]>([]);
  const clearTimers = useCallback(() => {
    timers.current.forEach((timer) => window.clearTimeout(timer));
    timers.current = [];
  }, []);
  const showToast = useCallback((message: string, tone: ToastTone = "info") => {
    clearTimers();
    sequence.current += 1;
    const id = sequence.current;
    setEntry({ id, message, tone, closing: false });
    timers.current.push(window.setTimeout(() => {
      setEntry((current) => current?.id === id ? { ...current, closing: true } : current);
    }, 4_400));
    timers.current.push(window.setTimeout(() => {
      setEntry((current) => current?.id === id ? null : current);
    }, 5_000));
  }, [clearTimers]);
  const value = useMemo(() => ({ showToast }), [showToast]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      {entry ? createPortal(
        <div className="toast-viewport" aria-live="polite" aria-atomic="true">
          <div
            className={`centered-toast is-${entry.tone}${entry.closing ? " is-closing" : ""}`}
            role={entry.tone === "error" ? "alert" : "status"}
          >
            {entry.message}
          </div>
        </div>,
        document.body,
      ) : null}
    </ToastContext.Provider>
  );
}
