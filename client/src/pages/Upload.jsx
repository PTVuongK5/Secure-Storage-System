import React, { useState } from 'react'
import { FileUp, ShieldCheck, UploadCloud, Users } from 'lucide-react'
import {
  sha256,
  generateAesKey,
  exportRawKey,
  encryptAesGcm,
  encryptKdcPayload,
  bytesToBase64,
  base64ToBytes,
  importPublicKeyFromPem,
  encryptRsa,
  verifyAndExtractPublicKey
} from '../services/crypto'

function formatSize(size) {
  if (!size) return 'No file selected'
  if (size < 1024) return `${size} B`
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`
  return `${(size / 1024 / 1024).toFixed(2)} MB`
}

async function getImportablePublicKeyPem(pem) {
  if (pem.includes('BEGIN CERTIFICATE')) {
    return (await verifyAndExtractPublicKey(pem)).publicKeyPem
  }
  return pem
}

export default function Upload() {
  const [file, setFile] = useState(null)
  const [recipients, setRecipients] = useState('')
  const [msg, setMsg] = useState('')
  const [loading, setLoading] = useState(false)

  async function onUpload(e) {
    e.preventDefault()
    setMsg('')
    if (!file) {
      setMsg('Choose a file before uploading.')
      return
    }

    try {
      setLoading(true)
      setMsg('Encrypting file with AES-GCM...')

      const currentUserId = sessionStorage.getItem('client_id')
      const currentUserPublicKey = sessionStorage.getItem('public_key_pem')
      const currentUsername = sessionStorage.getItem('username')

      if (!currentUserId || !currentUserPublicKey) {
        throw new Error('Missing local key material. Login again.')
      }

      const kf = await generateAesKey()
      const kfRaw = await exportRawKey(kf)
      const fileBuf = await file.arrayBuffer()
      const fileHash = await sha256(fileBuf)

      const iv = crypto.getRandomValues(new Uint8Array(12))
      const enc = await encryptAesGcm(kf, fileBuf, iv)
      const cipherBlob = new Blob([base64ToBytes(enc.ciphertext_b64)], { type: 'application/octet-stream' })

      setMsg('Resolving recipient public keys...')
      const recipientsList = recipients
        .split(',')
        .map((s) => s.trim())
        .filter((s) => s && s !== currentUsername)

      const userServiceUrl = import.meta.env.VITE_USER_SERVICE_URL || 'http://localhost:4002'

      let recipientsKeysData = []
      if (recipientsList.length > 0) {
        const keyRes = await fetch(`${userServiceUrl}/api/v1/users/public-keys`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ usernames: recipientsList })
        })
        const keyData = await keyRes.json()
        if (!keyRes.ok) throw new Error(keyData.error || 'Unable to fetch recipient public keys')

        recipientsKeysData = keyData.keys || []
        if (recipientsKeysData.length !== recipientsList.length) {
          throw new Error(`Some recipients were not found: ${recipientsList.join(', ')}`)
        }
      }

      recipientsKeysData.push({
        user_id: currentUserId,
        public_key: currentUserPublicKey
      })

      setMsg('Wrapping file key for recipients...')
      const envelope_keys = await Promise.all(
        recipientsKeysData.map(async (user) => {
          const actualPem = await getImportablePublicKeyPem(user.public_key)
          const pubKey = await importPublicKeyFromPem(actualPem)
          const encryptedEkBase64 = await encryptRsa(pubKey, kfRaw)

          return {
            recipient_id: user.user_id,
            ek: encryptedEkBase64,
            algo: 'RSA-OAEP',
            role: 'Owner'
          }
        })
      )

      const fileMetadata = {
        nonce: enc.iv_b64,
        gcm_tag: enc.tag_b64,
        plaintext_hash: fileHash,
        envelope_keys
      }

      const kcs_b64 = sessionStorage.getItem('k_c_s')
      if (!kcs_b64) throw new Error('Missing service session key. Login again.')

      const kcsRaw = base64ToBytes(kcs_b64)
      const kcsKey = await window.crypto.subtle.importKey('raw', kcsRaw, { name: 'AES-GCM' }, false, ['encrypt'])

      const metaIv = crypto.getRandomValues(new Uint8Array(12))
      const encodedMeta = new TextEncoder().encode(JSON.stringify(fileMetadata))
      const aad = new TextEncoder().encode('secure-storage-kdc-v1')

      const encryptedMetaBuffer = await window.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: metaIv, additionalData: aad },
        kcsKey,
        encodedMeta
      )

      const combinedMeta = new Uint8Array(12 + encryptedMetaBuffer.byteLength)
      combinedMeta.set(metaIv, 0)
      combinedMeta.set(new Uint8Array(encryptedMetaBuffer), 12)
      const encryptedMetadataBase64 = bytesToBase64(combinedMeta)

      setMsg('Uploading ciphertext to file-service...')
      const st = sessionStorage.getItem('st')
      if (!st) {
        alert("Phiên đăng nhập đã hết hạn, vui lòng đăng nhập lại!");
        return;
      }

      const requestId = crypto.randomUUID()
      const authenticatorPayload = {
        client_id: currentUserId,
        service_id: 'file-service',
        timestamp: new Date().toISOString()
      }
      const serviceAuthenticator = await encryptKdcPayload(kcsRaw, authenticatorPayload)

      const formData = new FormData()
      formData.append('originalName', file.name)
      formData.append('owner', currentUserId)
      formData.append('metadata', encryptedMetadataBase64)
      formData.append('authenticator', serviceAuthenticator)
      formData.append('ciphertext', cipherBlob, file.name + '.cipher')

      const baseFileUrl = import.meta.env.VITE_FILE_SERVICE_URL || 'http://localhost:4001'
      const res = await fetch(`${baseFileUrl}/api/v1/files/upload`, {
        method: 'POST',
        headers: {
          'X-Request-Id': requestId,
          'X-Client-Time': new Date().toISOString(),
          'Authorization': `Bearer ${st}`,
          'x-service-authenticator': serviceAuthenticator
        },
        body: formData
      })

      const data = await res.json()
      if (!res.ok) throw new Error(data.error || 'Upload failed')

      setMsg(`Upload complete. File ID: ${data.fileId || data.data?.file_id}`)
      setFile(null)
      setRecipients('')
    } catch (err) {
      console.error(err)
      setMsg('Upload error: ' + (err.message || err))
    } finally {
      setLoading(false)
    }
  }

  const isError = msg.toLowerCase().includes('error') || msg.toLowerCase().includes('missing') || msg.toLowerCase().includes('choose')
  const isSuccess = msg.toLowerCase().includes('complete')

  return (
    <section className="page">
      <div className="page-header">
        <div>
          <p className="eyebrow">Encrypted storage</p>
          <h2 className="page-title">Upload file</h2>
          <p className="page-description">The browser encrypts content, wraps the data key for each recipient, then sends ciphertext to file-service.</p>
        </div>
        <span className="status info">
          <ShieldCheck size={14} />
          Client-side crypto
        </span>
      </div>

      <div className="grid two">
        <div className="panel">
          <div className="panel-header">
            <div>
              <h3 className="panel-title">File package</h3>
              <p className="panel-subtitle">Ciphertext and encrypted metadata are uploaded together.</p>
            </div>
            <FileUp size={21} color="#0a6f73" />
          </div>

          <form className="form" onSubmit={onUpload}>
            <div className="field">
              <label htmlFor="upload-file">File</label>
              <input id="upload-file" type="file" onChange={(e) => setFile(e.target.files[0] || null)} disabled={loading} />
            </div>
            <div className="field">
              <label htmlFor="upload-recipients">Recipients</label>
              <input
                id="upload-recipients"
                type="text"
                value={recipients}
                onChange={(e) => setRecipients(e.target.value)}
                placeholder="alice, bob"
                disabled={loading}
              />
            </div>
            <button className="btn primary" disabled={loading} type="submit">
              <UploadCloud size={16} />
              {loading ? 'Working...' : 'Upload encrypted file'}
            </button>
          </form>

          {msg && <div className={`message mt-14 ${isSuccess ? 'success' : isError ? 'error' : ''}`}>{msg}</div>}
        </div>

        <div className="panel">
          <div className="panel-header">
            <div>
              <h3 className="panel-title">Current selection</h3>
              <p className="panel-subtitle">Recipient names are resolved before upload.</p>
            </div>
            <Users size={20} color="#4357ad" />
          </div>
          <div className="grid">
            <div className="recipient-row">
              <span>Filename</span>
              <span className="mono">{file?.name || 'None'}</span>
            </div>
            <div className="recipient-row">
              <span>Size</span>
              <span className="mono">{formatSize(file?.size)}</span>
            </div>
            <div className="recipient-row">
              <span>Recipients</span>
              <span className="mono">{recipients.trim() || 'Owner only'}</span>
            </div>
          </div>
        </div>
      </div>
    </section>
  )
}
