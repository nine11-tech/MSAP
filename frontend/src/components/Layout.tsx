import type { ReactNode } from "react";
import { NavLink } from "react-router-dom";
import { API_DOCS_URL } from "../api/client";

export function Layout({ children }: { children: ReactNode }) {
  return (
    <div className="app-shell">
      <header className="topbar">
        <NavLink to="/" className="brand" aria-label="MSAP dashboard">
          <span className="brand-mark">M</span>
          <span>
            <strong>MSAP</strong>
            <small>Security assessment &amp; triage</small>
          </span>
        </NavLink>
        <nav className="nav-links" aria-label="Primary navigation">
          <NavLink
            to="/"
            end
            className={({ isActive }) => (isActive ? "active" : undefined)}
          >
            Dashboard
          </NavLink>
          <NavLink
            to="/projects"
            className={({ isActive }) => (isActive ? "active" : undefined)}
          >
            Projects
          </NavLink>
          <a href={API_DOCS_URL} target="_blank" rel="noreferrer">
            API Docs ↗
          </a>
        </nav>
      </header>
      <main className="page-container">{children}</main>
      <footer className="footer">
        Static Android assessment • ATT&amp;CK signals are not malware verdicts
      </footer>
    </div>
  );
}
