import React, { useState } from 'react'
import { KeyRound, UserPlus } from 'lucide-react'
import {
  generateRsaKeyPair,
  exportPrivateKeyToPem,
  wrapPrivateKeyWithPassword,
  createCsrAndGetCert
} from '../services/crypto'

export default function Register() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [msg, setMsg] = useState('')
  const [loading, setLoading] = useState(false)

  async function onRegister(e) {
    e.preventDefault()
    setMsg('')

    if (!username || !password) return setMsg('Username and password are required.')
    if (password !== confirmPassword) return setMsg('Password confirmation does not match.')

    try {
      setLoading(true)
      setMsg('Generating RSA key pair...')

      const keyPair = await generateRsaKeyPair()
      const rawPrivateKeyPem = await exportPrivateKeyToPem(keyPair.privateKey)

      setMsg('Encrypting private key...')
      const encryptedPrivateKey = await wrapPrivateKeyWithPassword(rawPrivateKeyPem, password)

      setMsg('Requesting certificate from CA...')
      const certPem = await createCsrAndGetCert(keyPair, username)

      setMsg('Creating account...')
      const userServiceUrl = import.meta.env.VITE_USER_SERVICE_URL || 'http://localhost:4002'
      const res = await fetch(`${userServiceUrl}/api/v1/users/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username,
          password,
          public_key: certPem,
          encrypted_private_key: encryptedPrivateKey
        })
      })

      const data = await res.json()
      if (!res.ok) throw new Error(data.error || 'Registration failed')

      setMsg('Account created. You can login now.')
      setUsername('')
      setPassword('')
      setConfirmPassword('')
    } catch (err) {
      console.error(err)
      setMsg('Error: ' + err.message)
    } finally {
      setLoading(false)
    }
  }

  const isSuccess = msg.toLowerCase().includes('created')
  const isError = msg.toLowerCase().startsWith('error') || msg.toLowerCase().includes('required') || msg.toLowerCase().includes('match')

  return (
    <section className="auth-layout">
      <div className="auth-panel">
        <div className="panel-header">
          <div>
            <p className="eyebrow">Identity</p>
            <h2 className="page-title">Register</h2>
            <p className="page-description">Create a user and store only the wrapped private key on the server.</p>
          </div>
          <KeyRound size={24} color="#0a6f73" />
        </div>

        <form className="form" onSubmit={onRegister}>
          <div className="field">
            <label htmlFor="register-username">Username</label>
            <input id="register-username" type="text" value={username} onChange={(e) => setUsername(e.target.value)} disabled={loading} required />
          </div>

          <div className="field">
            <label htmlFor="register-password">Password</label>
            <input id="register-password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} disabled={loading} required />
          </div>

          <div className="field">
            <label htmlFor="register-confirm">Confirm password</label>
            <input id="register-confirm" type="password" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} disabled={loading} required />
          </div>

          <button className="btn primary" type="submit" disabled={loading}>
            <UserPlus size={16} />
            {loading ? 'Creating...' : 'Create account'}
          </button>
        </form>

        {msg && <div className={`message mt-14 ${isSuccess ? 'success' : isError ? 'error' : ''}`}>{msg}</div>}
      </div>
    </section>
  )
}