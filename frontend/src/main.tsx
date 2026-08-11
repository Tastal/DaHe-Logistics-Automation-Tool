import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { browserAppServices } from "./api/client";
import { App } from "./app/App";
import { ToastProvider } from "./components/Toast";
import "./styles/tokens.css";
import "./styles/app.css";

const root = document.getElementById("root");

if (!root) {
  throw new Error("The operator console root element is missing.");
}

createRoot(root).render(
  <StrictMode>
    <ToastProvider>
      <App services={browserAppServices} />
    </ToastProvider>
  </StrictMode>,
);
