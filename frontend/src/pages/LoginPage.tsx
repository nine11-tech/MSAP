import { useState, type FormEvent } from "react";
import { Navigate, useLocation, useNavigate } from "react-router-dom";
import { ApiError } from "../api/client";
import { useAuth } from "../auth/AuthContext";

export function LoginPage() {
  const { user, login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");

  if (user) return <Navigate to="/" replace />;

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    setSubmitting(true);
    setError("");
    try {
      await login(username, password);
      const from =
        (location.state as { from?: { pathname?: string } } | null)?.from
          ?.pathname || "/";
      navigate(from, { replace: true });
    } catch (loginError) {
      if (loginError instanceof ApiError && loginError.status === 429) {
        setError(
          "Too many login attempts. Wait 15 minutes before trying again.",
        );
      } else {
        setError("Invalid username or password.");
      }
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <main className="login-page">
      <section className="login-panel" aria-labelledby="login-title">
        <div className="login-brand" aria-label="MSAP">
          <span className="brand-mark">M</span>
          <strong>MSAP</strong>
        </div>
        <p className="eyebrow">Restricted internal platform</p>
        <h1 id="login-title">Secure assessment workspace</h1>
        <p className="login-subtitle">
          Mobile Security Assessment &amp; Triage Platform
        </p>
        <form onSubmit={handleSubmit} className="login-form">
          <label htmlFor="username">Username</label>
          <input
            id="username"
            name="username"
            autoComplete="username"
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            disabled={submitting}
            required
            autoFocus
          />
          <label htmlFor="password">Password</label>
          <div className="password-field">
            <input
              id="password"
              name="password"
              type={showPassword ? "text" : "password"}
              autoComplete="current-password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              disabled={submitting}
              required
            />
            <button
              type="button"
              className="text-button"
              onClick={() => setShowPassword((visible) => !visible)}
              aria-label={showPassword ? "Hide password" : "Show password"}
            >
              {showPassword ? "Hide" : "Show"}
            </button>
          </div>
          {error ? (
            <div className="alert alert-error" role="alert">
              {error}
            </div>
          ) : null}
          <button className="button button-primary" disabled={submitting}>
            {submitting ? "Authenticating…" : "Sign in securely"}
          </button>
        </form>
        <p className="login-footnote">
          Session protected by server-side authentication and CSRF controls.
        </p>
      </section>
    </main>
  );
}
