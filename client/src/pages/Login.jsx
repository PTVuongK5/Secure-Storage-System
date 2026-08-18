import React, { useState } from 'react'
import { LockKeyhole, LogIn } from 'lucide-react'
import {
  decryptKdcPayload,
  encryptKdcPayload,
  unwrapPrivateKeyWithPassword,
  base64ToBytes
} from '../services/crypto'

export default function Login() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [msg, setMsg] = useState('')
  const [loading, setLoading] = useState(false)

  async function onSubmit(e) {
    e.preventDefault()
    setMsg('Authenticating with KDC...')
    setLoading(true)

    try {
      const base = import.meta.env.VITE_KDC_URL || 'http://localhost:4000'

      const chReqId = crypto.randomUUID()
      const chRes = await fetch(`${base}/api/v1/auth/challenge?username=${encodeURIComponent(username)}`, {
        method: 'GET',
        headers: { 'X-Request-Id': chReqId, 'X-Client-Time': new Date().toISOString() }
      })
      if (!chRes.ok) {
        const t = await chRes.text()
        throw new Error(t || chRes.statusText || 'Challenge failed')
      }
      const ch = await chRes.json()
      const { iterations, salt } = ch.data || {}
      if (!iterations || !salt) throw new Error('Invalid challenge response')

      const enc = new TextEncoder()
      const passKey = await crypto.subtle.importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits'])
      const saltBuf = new TextEncoder().encode(salt)
      const derivedBits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', iterations, salt: saltBuf }, passKey, 256)
      const derivedArr = new Uint8Array(derivedBits)
      const derivedHex = Array.from(derivedArr).map((b) => b.toString(16).padStart(2, '0')).join('')

      const requestId = crypto.randomUUID()
      const res = await fetch(`${base}/api/v1/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Request-Id': requestId, 'X-Client-Time': new Date().toISOString() },
        body: JSON.stringify({ username, password: derivedHex })
      })

      const text = await res.text()
      let data = null
      try {
        data = text ? JSON.parse(text) : null
      } catch (err) {
        console.warn('Login: response not JSON', text)
      }

      if (!res.ok) throw new Error(data?.error?.message || text || res.statusText || 'Login failed')
      if (!data || !data.data) throw new Error('Invalid login response from server')

      setMsg('Loading encrypted private key...')
      const { public_key, encrypted_private_key } = data.data
      if (!public_key || !encrypted_private_key) {
        throw new Error('Account key material is missing. Register again to create a fresh E2EE key pair.')
      }

      const privateKeyPem = await unwrapPrivateKeyWithPassword(encrypted_private_key, password)

      sessionStorage.setItem('public_key_pem', public_key)
      sessionStorage.setItem('private_key_pem', privateKeyPem)
      sessionStorage.setItem('tgt', data.data.tgt)
      sessionStorage.setItem('client_id', data.data.client_id)
      sessionStorage.setItem('username', data.data.username)
      sessionStorage.setItem('roles', JSON.stringify(data.data.roles || []))
      sessionStorage.setItem('tgt_expires_at', data.data.expires_at)

      const envelopeData = await decryptKdcPayload(derivedArr, data.data.envelope)
      const kctgsBytes = base64ToBytes(envelopeData.k_c_tgs)

      setMsg('Requesting service ticket...')
      const authenticator = await encryptKdcPayload(kctgsBytes, {
        client_id: data.data.client_id,
        service_id: 'kdc-tgs',
        timestamp: new Date().toISOString()
      })

      const ticketReqId = crypto.randomUUID()
      const ticketRes = await fetch(`${base}/api/v1/auth/ticket`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Request-Id': ticketReqId,
          'X-Client-Time': new Date().toISOString()
        },
        body: JSON.stringify({
          tgt: data.data.tgt,
          authenticator,
          service_id: 'file-service'
        })
      })

      const ticketText = await ticketRes.text()
      let ticketData = null
      try {
        ticketData = JSON.parse(ticketText)
      } catch {
        throw new Error('Invalid ticket response')
      }
      if (!ticketRes.ok) throw new Error(ticketData?.error?.message || 'Ticket request failed')

      sessionStorage.setItem('st', ticketData.data.st)
      sessionStorage.setItem('st_expires_at', ticketData.data.expires_at)

      const decryptedSessionPayload = await decryptKdcPayload(kctgsBytes, ticketData.data.session)
      if (!decryptedSessionPayload.k_c_s) throw new Error('Service session key is missing from KDC response')
      sessionStorage.setItem('k_c_s', decryptedSessionPayload.k_c_s)

      setMsg('Login complete. Service ticket is ready.')
    } catch (err) {
      console.error(err)
      setMsg(err.message)
    } finally {
      setLoading(false)
    }
  }

  const isSuccess = msg.toLowerCase().includes('complete')

  return (
    <section className="auth-layout">
      <div className="auth-panel">
        <div className="panel-header">
          <div>
            <p className="eyebrow">Authentication</p>
            <h2 className="page-title">Login</h2>
            <p className="page-description">Request TGT/ST tickets and load your encrypted private key for this browser session.</p>
          </div>
          <LockKeyhole size={24} color="#0a6f73" />
        </div>

        <form className="form" onSubmit={onSubmit}>
          <div className="field">
            <label htmlFor="login-username">Username</label>
            <input id="login-username" value={username} onChange={(e) => setUsername(e.target.value)} disabled={loading} autoComplete="username" />
          </div>
          <div className="field">
            <label htmlFor="login-password">Password</label>
            <input id="login-password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} disabled={loading} autoComplete="current-password" />
          </div>
          <button className="btn primary" disabled={loading} type="submit">
            <LogIn size={16} />
            {loading ? 'Processing...' : 'Login'}
          </button>
        </form>

        {msg && <div className={`message mt-14 ${isSuccess ? 'success' : msg.toLowerCase().includes('fail') || msg.toLowerCase().includes('invalid') ? 'error' : ''}`}>{msg}</div>}
      </div>
    </section>
  )
}
