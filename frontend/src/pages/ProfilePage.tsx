import { useState, type FormEvent } from "react";
import { changePassword } from "../api/auth";
import { useAuth } from "../auth/AuthContext";
import {
  Card,
  ErrorMessage,
  PageHeader,
  errorMessage,
} from "../components/Common";

export function ProfilePage() {
  const { user } = useAuth();
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [working, setWorking] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError("");
    setNotice("");
    if (newPassword !== confirmation) {
      setError("New password confirmation does not match.");
      return;
    }
    setWorking(true);
    try {
      await changePassword(currentPassword, newPassword);
      setCurrentPassword("");
      setNewPassword("");
      setConfirmation("");
      setNotice("Password changed. Your current session remains active.");
    } catch (requestError) {
      setError(errorMessage(requestError));
    } finally {
      setWorking(false);
    }
  }

  return (
    <>
      <PageHeader eyebrow="Account security" title="Profile & password" description="Review your internal MSAP identity and maintain your server-side session credentials." />
      {error ? <ErrorMessage message={error} /> : null}
      {notice ? <div className="alert alert-success" role="status">{notice}</div> : null}
      <div className="content-grid two-column">
        <Card title="Account">
          <dl className="details-list">
            <div><dt>Username</dt><dd>{user?.username}</dd></div>
            <div><dt>Name</dt><dd>{[user?.first_name, user?.last_name].filter(Boolean).join(" ") || "—"}</dd></div>
            <div><dt>Email</dt><dd>{user?.email || "—"}</dd></div>
            <div><dt>Role</dt><dd>{user?.role}</dd></div>
          </dl>
        </Card>
        <Card title="Change password">
          <form className="form-stack" onSubmit={submit}>
            <label>Current password<input type="password" autoComplete="current-password" value={currentPassword} onChange={(event) => setCurrentPassword(event.target.value)} required /></label>
            <label>New password<input type="password" autoComplete="new-password" value={newPassword} onChange={(event) => setNewPassword(event.target.value)} minLength={12} required /></label>
            <label>Confirm new password<input type="password" autoComplete="new-password" value={confirmation} onChange={(event) => setConfirmation(event.target.value)} minLength={12} required /></label>
            <button className="button button-primary" disabled={working}>{working ? "Updating…" : "Change password"}</button>
          </form>
        </Card>
      </div>
    </>
  );
}
