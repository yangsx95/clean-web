import React from "react";
import ReactDOM from "react-dom/client";
import { App } from "../../desktop/src/App";
import "../../desktop/src/styles.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
