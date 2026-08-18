import React from 'react'
import { Activity, Database, ShieldAlert } from 'lucide-react'

export default function Audit() {
  return (
    <section className="page">
      <div className="page-header">
        <div>
          <p className="eyebrow">Traceability</p>
          <h2 className="page-title">Audit log</h2>
          <p className="page-description">Audit records are written by file-service for upload, download, share, revoke, and failed authentication events.</p>
        </div>
        <span className="status warn">Prototype view</span>
      </div>

      <div className="grid three">
        <div className="stat-card">
          <div className="stat-icon"><Activity size={19} /></div>
          <div>
            <div className="stat-value">Events</div>
            <p className="stat-label">UPLOAD, DOWNLOAD, SHARE, REVOKE</p>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-icon"><ShieldAlert size={19} /></div>
          <div>
            <div className="stat-value">Auth</div>
            <p className="stat-label">Failed auth and replay attempts</p>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-icon"><Database size={19} /></div>
          <div>
            <div className="stat-value">DB</div>
            <p className="stat-label">Stored in file-service audit_log</p>
          </div>
        </div>
      </div>

      <div className="panel">
        <div className="empty-state">
          <Activity size={34} />
          <div>Audit viewer UI is ready for the next API integration step.</div>
        </div>
      </div>
    </section>
  )
}
