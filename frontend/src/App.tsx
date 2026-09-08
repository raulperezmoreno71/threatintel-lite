import { Route, Routes } from 'react-router-dom'
import LandingPage from './pages/LandingPage'
import LoginPage from './pages/LoginPage'
import RegisterPage from './pages/RegisterPage'
import DashboardPage from './pages/DashboardPage'
import SavedAnalysesPage from './pages/SavedAnalysesPage'
import AnalysisDetailPage from './pages/AnalysisDetailPage'
import ChangePasswordPage from './pages/ChangePasswordPage'

function App() {
  return (
    <Routes>
      <Route path='/' element={<LandingPage />} />
      <Route path='/login' element={<LoginPage />} />
      <Route path='/register' element={<RegisterPage />} />
      <Route path='/dashboard' element={<DashboardPage />} />
      <Route path='/analyses' element={<SavedAnalysesPage />} />
      <Route path='/analyses/:analysisId' element={<AnalysisDetailPage />} />
      <Route path='/change-password' element={<ChangePasswordPage />} />
    </Routes>
  )
}

export default App
