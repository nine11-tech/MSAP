import { useState, type ReactNode } from "react";
import { NavLink, useLocation } from "react-router-dom";
import { API_DOCS_URL } from "../api/client";
import { useAuth } from "../auth/AuthContext";
import { ArchitectureStatusBar } from "./ArchitectureStatusBar";
import { SystemStatusProvider } from "../status/SystemStatusContext";

export function Layout({ children }: { children: ReactNode }) {
  const { user, logout } = useAuth();
  const [collapsed, setCollapsed] = useState(false);
  const location = useLocation();
  const pageTitle =
    [
      ["/projects", "Projects"],
      ["/audits", "Audits"],
      ["/findings", "Findings"],
      ["/attack-triage", "ATT&CK Triage"],
      ["/reports", "Reports"],
      ["/dynamic", "Dynamic Lab"],
      ["/system-status", "System Status"],
      ["/administration", "Administration"],
      ["/profile", "Profile & Security"],
    ].find(([path]) => location.pathname.startsWith(path))?.[1] || "Overview";

  const navItems = [
    { to: "/", label: "Overview", icon: "OV", end: true },
    { to: "/projects", label: "Projects", icon: "PR" },
    { to: "/audits", label: "Audits", icon: "AU" },
    { to: "/findings", label: "Findings", icon: "FI" },
    { to: "/attack-triage", label: "ATT&CK Triage", icon: "AT" },
    { to: "/reports", label: "Reports", icon: "RP" },
    { to: "/dynamic", label: "Dynamic Lab", icon: "DL" },
    { to: "/system-status", label: "System Status", icon: "SY" },
  ];

  return (
    <SystemStatusProvider>
      <div className={`app-shell ${collapsed ? "sidebar-collapsed" : ""}`}>
        <aside className="sidebar">
          <NavLink to="/" className="brand" aria-label="MSAP overview">
            <span className="brand-mark">M</span>
            <span className="brand-copy">
              <strong>MSAP</strong>
              <small>Security Assessment</small>
            </span>
          </NavLink>
          <button
            className="sidebar-toggle"
            onClick={() => setCollapsed((value) => !value)}
            aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
            aria-expanded={!collapsed}
          >
            {collapsed ? "›" : "‹"}
          </button>
          <nav className="sidebar-nav" aria-label="Primary navigation">
            <span className="nav-section-label">Assessment</span>
            {navItems.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                title={item.label}
                className={({ isActive }) => (isActive ? "active" : undefined)}
              >
                <span className="nav-icon" aria-hidden="true">{item.icon}</span>
                <span className="nav-label">{item.label}</span>
              </NavLink>
            ))}
            {user?.role === "ADMIN" ? (
              <>
                <span className="nav-section-label">Platform</span>
                <NavLink to="/administration" title="Administration">
                  <span className="nav-icon" aria-hidden="true">AD</span>
                  <span className="nav-label">Administration</span>
                </NavLink>
              </>
            ) : null}
          </nav>
          <p className="sidebar-scope">
            <span className="status-dot status-operational" />
            <span className="nav-label">Static + dynamic MVP</span>
          </p>
        </aside>
        <div className="app-main">
          <header className="topbar">
            <div>
              <p className="topbar-context">Mobile application security</p>
              <strong>{pageTitle}</strong>
            </div>
            <div className="topbar-actions">
              {user?.role === "ADMIN" ? (
                <a
                  className="header-link"
                  href={API_DOCS_URL}
                  target="_blank"
                  rel="noreferrer"
                >
                  API
                </a>
              ) : null}
              <details className="profile-menu">
                <summary aria-label="Open user profile menu">
                  <span className="avatar">
                    {(user?.first_name || user?.username || "U")
                      .slice(0, 1)
                      .toUpperCase()}
                  </span>
                  <span className="profile-copy">
                    {user?.first_name || user?.username}
                    <small>{user?.role}</small>
                  </span>
                </summary>
                <div className="profile-popover">
                  <NavLink to="/profile">Profile &amp; password</NavLink>
                  <button onClick={() => void logout()}>Sign out</button>
                </div>
              </details>
            </div>
          </header>
          <ArchitectureStatusBar />
          <main className="page-container">{children}</main>
          <footer className="footer">
            Deterministic Android assessment MVP • Triage signals are not
            malware verdicts
          </footer>
        </div>
      </div>
    </SystemStatusProvider>
  );
}
