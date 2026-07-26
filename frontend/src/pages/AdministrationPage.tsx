import { API_BASE_URL, API_DOCS_URL } from "../api/client";
import { Card, PageHeader } from "../components/Common";

export function AdministrationPage() {
  const adminUrl = `${API_BASE_URL.replace(/\/api$/, "")}/admin/`;
  return (
    <>
      <PageHeader
        eyebrow="Administrator access"
        title="Platform administration"
        description="Manage internal users, group membership, and platform permissions through Django's protected administration interface."
      />
      <div className="content-grid two-column">
        <Card title="Identity and access">
          <p>
            User creation is administrator-controlled. MSAP does not expose
            public registration or client-side authentication tokens.
          </p>
          <a className="button button-primary" href={adminUrl} target="_blank" rel="noreferrer">
            Open Django administration ↗
          </a>
        </Card>
        <Card title="API governance">
          <p>
            Inspect the authenticated API schema. Production documentation is
            restricted to MSAP administrators.
          </p>
          <a className="button button-secondary" href={API_DOCS_URL} target="_blank" rel="noreferrer">
            Open API documentation ↗
          </a>
        </Card>
      </div>
      <Card title="Role permission matrix">
        <div className="table-wrap">
          <table>
            <thead><tr><th>Capability</th><th>Administrator</th><th>Analyst</th><th>Viewer</th></tr></thead>
            <tbody>
              <tr><td>Read assessments and reports</td><td>Allowed</td><td>Allowed</td><td>Allowed</td></tr>
              <tr><td>Create/update projects and audits</td><td>Allowed</td><td>Allowed</td><td>Denied</td></tr>
              <tr><td>Upload and initiate analysis</td><td>Allowed</td><td>Allowed</td><td>Denied</td></tr>
              <tr><td>Delete assessment records</td><td>Allowed</td><td>Denied</td><td>Denied</td></tr>
              <tr><td>Manage users and roles</td><td>Allowed</td><td>Denied</td><td>Denied</td></tr>
            </tbody>
          </table>
        </div>
      </Card>
    </>
  );
}
