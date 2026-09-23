import { Route, Routes } from "react-router-dom";

import AppLayout from "./layouts/AppLayout";
import NotFoundPage from "./pages/NotFoundPage";
import StatusPage from "./pages/StatusPage";

// The router itself lives in main.tsx so tests can wrap <App /> in a MemoryRouter.
export default function App() {
  return (
    <Routes>
      <Route element={<AppLayout />}>
        <Route index element={<StatusPage />} />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  );
}
