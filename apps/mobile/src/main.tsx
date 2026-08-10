import React from "react";
import ReactDOM from "react-dom/client";
import { App } from "../../../packages/frontend/App";
import "../../../packages/frontend/styles.css";

(window as typeof window & { __CLEANWEB_TARGET__?: string }).__CLEANWEB_TARGET__ = "mobile";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
