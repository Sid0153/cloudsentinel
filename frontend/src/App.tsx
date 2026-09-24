import { Route, Routes } from "react-router-dom";

import ProtectedRoute from "./auth/ProtectedRoute";
import RequireRole from "./auth/RequireRole";
import AppLayout from "./layouts/AppLayout";
import DashboardPage from "./pages/DashboardPage";
import FindingDetailPage from "./pages/FindingDetailPage";
import FindingsPage from "./pages/FindingsPage";
import LoginPage from "./pages/LoginPage";
import NotFoundPage from "./pages/NotFoundPage";
import ResourceDetailPage from "./pages/ResourceDetailPage";
import ResourcesPage from "./pages/ResourcesPage";
import ScanDetailPage from "./pages/ScanDetailPage";
import ScansPage from "./pages/ScansPage";
import SettingsPage from "./pages/SettingsPage";
import UsersPage from "./pages/UsersPage";

// The router and AuthProvider live in main.tsx so tests can wrap <App /> themselves.
export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route element={<ProtectedRoute />}>
        <Route element={<AppLayout />}>
          <Route index element={<DashboardPage />} />
          <Route path="findings" element={<FindingsPage />} />
          <Route path="findings/:findingId" element={<FindingDetailPage />} />
          <Route path="resources" element={<ResourcesPage />} />
          <Route path="resources/:resourceId" element={<ResourceDetailPage />} />
          <Route path="scans" element={<ScansPage />} />
          <Route path="scans/:scanId" element={<ScanDetailPage />} />
          <Route path="settings" element={<SettingsPage />} />
          <Route element={<RequireRole allowed={["ADMIN"]} />}>
            <Route path="users" element={<UsersPage />} />
          </Route>
          <Route path="*" element={<NotFoundPage />} />
        </Route>
      </Route>
    </Routes>
  );
}
