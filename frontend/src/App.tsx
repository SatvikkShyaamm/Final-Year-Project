import { Navigate, Route, Routes } from 'react-router-dom'
import { AdminLayout } from './components/layout/AdminLayout'
import { Login } from './pages/Login'
import { UserPortal } from './pages/UserPortal'
import { DashboardHome } from './pages/admin/DashboardHome'
import { LiveSessions } from './pages/admin/LiveSessions'
import { TrustScorePage } from './pages/admin/TrustScorePage'
import { SecurityAlerts } from './pages/admin/SecurityAlerts'
import { ACLMonitor } from './pages/admin/ACLMonitor'
import { Analytics } from './pages/admin/Analytics'
import { AttackSimulation } from './pages/admin/AttackSimulation'
import { SystemStatus } from './pages/admin/SystemStatus'

function App() {
  return (
    <Routes>
      <Route path="/" element={<Navigate to="/admin" replace />} />
      <Route path="/login" element={<Login />} />
      <Route path="/portal" element={<UserPortal />} />

      <Route path="/admin" element={<AdminLayout />}>
        <Route index element={<DashboardHome />} />
        <Route path="sessions" element={<LiveSessions />} />
        <Route path="trust-score" element={<TrustScorePage />} />
        <Route path="alerts" element={<SecurityAlerts />} />
        <Route path="acl" element={<ACLMonitor />} />
        <Route path="analytics" element={<Analytics />} />
        <Route path="simulation" element={<AttackSimulation />} />
        <Route path="status" element={<SystemStatus />} />
      </Route>

      <Route path="*" element={<Navigate to="/admin" replace />} />
    </Routes>
  )
}

export default App
