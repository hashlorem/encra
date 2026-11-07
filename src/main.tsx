import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { ThemeProvider, applyStoredTheme } from "./lib/ThemeContext";
// Self-hosted, Latin subset only: the CSP allows fonts from 'self' and nothing else.
import "@fontsource/public-sans/latin-400.css";
import "@fontsource/public-sans/latin-500.css";
import "@fontsource/public-sans/latin-600.css";
import "@fontsource/newsreader/latin-400.css";
import "@fontsource/newsreader/latin-400-italic.css";
import "@fontsource/newsreader/latin-500.css";
import "@fontsource/ibm-plex-mono/latin-400.css";
import "@fontsource/ibm-plex-mono/latin-500.css";
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
