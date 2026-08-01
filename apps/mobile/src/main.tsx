import React from "react";
import ReactDOM from "react-dom/client";
import { App } from "../../../shared/frontend/App";
import "../../../shared/frontend/styles.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
