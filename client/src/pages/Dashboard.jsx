import React from 'react'
import { Clock3, FileKey, KeyRound, ShieldCheck } from 'lucide-react'

function formatDate(value) {
  if (!value || value === 'none') return 'No active ticket'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toLocaleString('vi-VN')
}

export default function Dashboard() {
  const username = sessionStorage.getItem('username') || 'Guest'
  const clientId = sessionStorage.getItem('client_id') || 'Not issued'
  const tgtExpires = sessionStorage.getItem('tgt_expires_at') || 'none'
  const stExpires = sessionStorage.getItem('st_expires_at') || 'none'
  const roles = JSON.parse(sessionStorage.getItem('roles') || '[]')
  const isSignedIn = Boolean(sessionStorage.getItem('st'))

  return (
    <section className="page">
      <div className="page-header">
        <div>
          <p className="eyebrow">Workspace</p>
          <h2 className="page-title">Security session overview</h2>
          <p className="page-description">
            Track the active Kerberos session, ticket expiry, and the local key material loaded for encrypted file access.
          </p>
        </div>
        <span className={`status ${isSignedIn ? 'success' : 'warn'}`}>
          {isSignedIn ? 'Session ready' : 'Login required'}
        </span>
      </div>

      <div className="grid three">
        <div className="stat-card">
          <div className="stat-icon"><ShieldCheck size={19} /></div>
          <div>
            <div className="stat-value">{username}</div>
            <p className="stat-label">Signed-in identity</p>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-icon"><KeyRound size={19} /></div>
          <div>
            <div className="stat-value">{roles.length || 0}</div>
            <p className="stat-label">Assigned roles</p>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-icon"><FileKey size={19} /></div>
          <div>
            <div className="stat-value">{isSignedIn ? 'Loaded' : 'Missing'}</div>
            <p className="stat-label">Service ticket</p>
          </div>
        </div>
      </div>

      <div className="grid two">
        <div className="panel">
          <div className="panel-header">
            <div>
              <h3 className="panel-title">Ticket lifecycle</h3>
              <p className="panel-subtitle">Timestamps are shown in your local timezone.</p>
            </div>
            <Clock3 size={20} color="#0a6f73" />
          </div>
          <div className="grid">
            <div className="recipient-row">
              <span>TGT expires</span>
              <span className="mono">{formatDate(tgtExpires)}</span>
            </div>
            <div className="recipient-row">
              <span>ST expires</span>
              <span className="mono">{formatDate(stExpires)}</span>
            </div>
          </div>
        </div>

        <div className="panel">
          <div className="panel-header">
            <div>
              <h3 className="panel-title">Client identity</h3>
              <p className="panel-subtitle">Used by the file-service authorization checks.</p>
            </div>
          </div>
          <div className="message">
            <div className="session-label">Client ID</div>
            <div className="mono mt-6">{clientId}</div>
          </div>
        </div>
      </div>
    </section>
  )
}
