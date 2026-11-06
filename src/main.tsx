import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { ThemeProvider, applyStoredTheme } from "./lib/ThemeContext";
import "./styles/global.css";

// Set the palette before the first React render so the stored theme wins
// immediately instead of flashing the default.
applyStoredTheme();

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ThemeProvider>
      <App />
    </ThemeProvider>
  </React.StrictMode>
);
