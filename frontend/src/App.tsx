import { Navigate, Route, Routes } from 'react-router-dom'
import AuthPage from './pages/AuthPage'
import DashboardPage from './pages/DashboardPage'
import HistoryPage from './pages/HistoryPage'
import AnalysisPage from './pages/AnalysisPage'
import NotFoundPage from './pages/NotFoundPage'

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Navigate to="/login" replace />} />
      <Route path="/login" element={<AuthPage mode="login" />} />
      <Route path="/registro" element={<AuthPage mode="register" />} />
      <Route path="/dashboard" element={<DashboardPage />} />
      <Route path="/historial" element={<HistoryPage />} />
      <Route path="/analisis/nuevo" element={<AnalysisPage mode="new" />} />
      <Route path="/analisis/resultado" element={<AnalysisPage mode="result" />} />
      <Route path="/analisis/:id" element={<AnalysisPage mode="detail" />} />
      <Route path="*" element={<NotFoundPage />} />
    </Routes>
  )
}
