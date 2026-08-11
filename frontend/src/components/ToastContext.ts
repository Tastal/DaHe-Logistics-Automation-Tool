import { createContext, useContext } from "react";

export type ToastTone = "success" | "warning" | "error" | "info";

export interface ToastContextValue {
  showToast: (message: string, tone?: ToastTone) => void;
}

const DEFAULT_TOAST_CONTEXT: ToastContextValue = {
  showToast: () => undefined,
};

export const ToastContext = createContext<ToastContextValue>(DEFAULT_TOAST_CONTEXT);

export function useToast(): ToastContextValue {
  return useContext(ToastContext);
}
