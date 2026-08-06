import { Navigate, Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import { AuditDetailPage } from "./pages/AuditDetailPage";
import { DashboardPage } from "./pages/DashboardPage";
import { ProjectDetailPage } from "./pages/ProjectDetailPage";
import { ProjectsPage } from "./pages/ProjectsPage";
import { ReportPage } from "./pages/ReportPage";
import { LoginPage } from "./pages/LoginPage";
import { ProtectedRoute } from "./auth/ProtectedRoute";
import { AuditsPage } from "./pages/AuditsPage";
import { FindingsPage } from "./pages/FindingsPage";
import { AttackTriagePage } from "./pages/AttackTriagePage";
import { ReportsPage } from "./pages/ReportsPage";
import { SystemStatusPage } from "./pages/SystemStatusPage";
import { AdministrationPage } from "./pages/AdministrationPage";
import { ProfilePage } from "./pages/ProfilePage";
import { DynamicLabPage } from "./pages/DynamicLabPage";
import { DynamicSessionDetailPage } from "./pages/DynamicSessionDetailPage";

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        path="/*"
        element={
          <ProtectedRoute>
            <Layout>
              <Routes>
                <Route path="/" element={<DashboardPage />} />
                <Route path="/projects" element={<ProjectsPage />} />
                <Route path="/audits" element={<AuditsPage />} />
                <Route path="/findings" element={<FindingsPage />} />
                <Route path="/attack-triage" element={<AttackTriagePage />} />
                <Route path="/reports" element={<ReportsPage />} />
                <Route path="/dynamic" element={<DynamicLabPage />} />
                <Route
                  path="/dynamic/sessions/:sessionId"
                  element={<DynamicSessionDetailPage />}
                />
                <Route path="/system-status" element={<SystemStatusPage />} />
                <Route path="/profile" element={<ProfilePage />} />
                <Route
                  path="/administration"
                  element={
                    <ProtectedRoute roles={["ADMIN"]}>
                      <AdministrationPage />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/projects/:projectId"
                  element={<ProjectDetailPage />}
                />
                <Route path="/audits/:auditId" element={<AuditDetailPage />} />
                <Route
                  path="/audits/:auditId/report"
                  element={<ReportPage />}
                />
                <Route path="*" element={<Navigate to="/" replace />} />
              </Routes>
            </Layout>
          </ProtectedRoute>
        }
      />
    </Routes>
  );
}
