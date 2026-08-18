import React from 'react'
import { NavLink, Routes, Route, useLocation, useNavigate } from 'react-router-dom'
import {
  Activity,
  Download,
  FileStack,
  Gauge,
  LogIn,
  LogOut,
  ShieldCheck,
  Upload,
  UserPlus
} from 'lucide-react'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Files from './pages/Files'
import UploadPage from './pages/Upload'
import Share from './pages/Share'
import Audit from './pages/Audit'
import DownloadPage from './pages/Download'
import Register from './pages/Register'

const navItems = [
  { to: '/', label: 'Dashboard', icon: Gauge },
  { to: '/files', label: 'My Files', icon: FileStack },
  { to: '/upload', label: 'Upload', icon: Upload },
  { to: '/download', label: 'Download', icon: Download },
  { to: '/audit', label: 'Audit', icon: Activity },
  { to: '/login', label: 'Login', icon: LogIn },
  { to: '/register', label: 'Register', icon: UserPlus }
]

const routeTitles = {
  '/': ['Secure Storage', 'Client-side encrypted file workspace'],
  '/files': ['My Files', 'Access-controlled encrypted objects'],
  '/upload': ['Upload', 'Encrypt, wrap keys, and store ciphertext'],
  '/download': ['Download', 'Decrypt files by ID with session credentials'],
  '/audit': ['Audit', 'Trace file activity and access decisions'],
  '/share': ['Share', 'Manage access envelopes'],
  '/login': ['Login', 'Request Kerberos tickets for file access'],
  '/register': ['Register', 'Create an account with an encrypted private key']
}

export default function App() {
  const location = useLocation()
  const navigate = useNavigate()
  const username = sessionStorage.getItem('username') || 'Guest'
  const isSignedIn = Boolean(sessionStorage.getItem('st'))
  const [title, subtitle] = routeTitles[location.pathname] || routeTitles['/']

  function logout() {
    sessionStorage.clear()
    navigate('/login')
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark" aria-hidden="true">
            <ShieldCheck size={22} />
          </div>
          <div>
            <p className="brand-title">Secure Storage</p>
            <p className="brand-subtitle">E2EE Console</p>
          </div>
        </div>

        <nav className="nav-group" aria-label="Primary">
          {navItems.map((item) => {
            const Icon = item.icon
            return (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.to === '/'}
                className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}
              >
                <Icon size={17} />
                <span>{item.label}</span>
              </NavLink>
            )
          })}
        </nav>

        <div className="sidebar-footer">
          <div className="session-label">Current session</div>
          <div className="session-user">{username}</div>
          <div className={`status ${isSignedIn ? 'success' : 'warn'} mt-10`}>
            {isSignedIn ? 'Authenticated' : 'Not signed in'}
          </div>
        </div>
      </aside>

      <main className="app-main">
        <div className="topbar">
          <div>
            <h1 className="topbar-title">{title}</h1>
            <p className="topbar-meta">{subtitle}</p>
          </div>
          {isSignedIn && (
            <button className="btn secondary" type="button" onClick={logout}>
              <LogOut size={16} />
              Logout
            </button>
          )}
        </div>

        <div className="content">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/register" element={<Register />} />
            <Route path="/login" element={<Login />} />
            <Route path="/files" element={<Files />} />
            <Route path="/upload" element={<UploadPage />} />
            <Route path="/share" element={<Share />} />
            <Route path="/audit" element={<Audit />} />
            <Route path="/download" element={<DownloadPage />} />
          </Routes>
        </div>
      </main>
    </div>
  )
}