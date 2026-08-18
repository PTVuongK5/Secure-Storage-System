import React, { useState, useEffect } from 'react';
import { 
  encryptKdcPayload, 
  importPrivateKeyFromPem, 
  decryptRsa, 
  importPublicKeyFromPem, 
  encryptRsa,
  verifyAndExtractPublicKey
} from '../services/crypto';
import { 
  RefreshCw, 
  FolderOpen, 
  FileText, 
  DownloadCloud, 
  Share2, 
  X, 
  Users, 
  Trash2 
} from 'lucide-react';
function formatDate(value) {
  if (!value) return 'Unknown';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString('vi-VN');
}

function formatSize(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function shortId(id) {
  if (!id) return '';
  if (id.length <= 8) return id;
  return `${id.substring(0, 4)}...${id.substring(id.length - 4)}`;
}

export default function Files() {
  const [files, setFiles] = useState([]);
  const [msg, setMsg] = useState('');
  const [loading, setLoading] = useState(true);

  const [shareModal, setShareModal] = useState({ isOpen: false, file: null });
  const [shareUsernames, setShareUsernames] = useState('');
  const [shareLoading, setShareLoading] = useState(false);
  const [downloadingId, setDownloadingId] = useState(null); // Quản lý trạng thái nút đang tải

  const currentUser = sessionStorage.getItem('username') || 'unknown';
  const currentClientId = sessionStorage.getItem('client_id');

  useEffect(() => {
    fetchFilesList();
  }, []);

  async function fetchFilesList() {
    try {
      setLoading(true);
      const st = sessionStorage.getItem('st');
      const kcs_b64 = sessionStorage.getItem('k_c_s');
      const baseFileUrl = import.meta.env.VITE_FILE_SERVICE_URL || 'http://localhost:4001';

      if (!st || !kcs_b64) throw new Error('Thiếu phiên Kerberos. Vui lòng đăng nhập lại!');

      const kcsRaw = Uint8Array.from(atob(kcs_b64), c => c.charCodeAt(0));
      const serviceAuthenticator = await encryptKdcPayload(kcsRaw, {
        client_id: currentClientId || currentUser,
        service_id: 'file-service',
        timestamp: new Date().toISOString()
      });

      const res = await fetch(`${baseFileUrl}/api/v1/files`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${st}`,
          'X-Request-Id': crypto.randomUUID(),
          'X-Client-Time': new Date().toISOString(),
          'x-service-authenticator': serviceAuthenticator
        }
      });

      const responseData = await res.json();
      if (!res.ok) throw new Error(responseData.error || 'Không thể lấy danh sách file');
      if (!responseData.encryptedData) throw new Error('Dữ liệu trả về không hợp lệ');

      const kcsKey = await window.crypto.subtle.importKey('raw', kcsRaw, { name: 'AES-GCM' }, false, ['decrypt']);
      const combinedBuffer = Uint8Array.from(atob(responseData.encryptedData), c => c.charCodeAt(0));
      const iv = combinedBuffer.slice(0, 12);
      const dataToDecrypt = combinedBuffer.slice(12);
      const aad = new TextEncoder().encode('secure-storage-kdc-v1');

      const decryptedBuffer = await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad }, kcsKey, dataToDecrypt);
      const parsedData = JSON.parse(new TextDecoder().decode(decryptedBuffer));
      setFiles(parsedData.files || []);
      
    } catch (err) {
      console.error(err);
      setMsg('Lỗi: ' + err.message);
    } finally {
      setLoading(false);
    }
  }

  function checkPermission(file) {
    if (file.owner === currentClientId) {
      return { text: 'Owner (Chủ sở hữu)', color: '#2ecc71', canDownload: true, isOwner: true };
    }

    const myPrivilege = file.recipients.find(r => r.recipient_id === currentClientId);
    if (myPrivilege) {
      return { text: `Viewer (Được chia sẻ)`, color: '#3498db', canDownload: true, isOwner: false };
    }
    
    return { text: 'No Access (Không có quyền)', color: '#e74c3c', canDownload: false, isOwner: false };
  }

  async function handleDownload(fileId) {
    setDownloadingId(fileId);
    try {
      const st = sessionStorage.getItem('st'); 
      const privateKeyPem = sessionStorage.getItem('private_key_pem');
      const kcs_b64 = sessionStorage.getItem('k_c_s');
      if (!st || !privateKeyPem || !kcs_b64) throw new Error('Thiếu thông tin bảo mật để giải mã!');

      const kcsRaw = Uint8Array.from(atob(kcs_b64), c => c.charCodeAt(0));
      const baseFileUrl = import.meta.env.VITE_FILE_SERVICE_URL || 'http://localhost:4001';

      const serviceAuthenticator = await encryptKdcPayload(kcsRaw, { 
        client_id: currentClientId, service_id: 'file-service', timestamp: new Date().toISOString() 
      });

      const res = await fetch(`${baseFileUrl}/api/v1/download/${fileId}`, {
        headers: {
          'Authorization': `Bearer ${st}`,
          'X-Request-Id': crypto.randomUUID(),
          'X-Client-Time': new Date().toISOString(),
          'x-service-authenticator': serviceAuthenticator
        }
      });
      if (!res.ok) throw new Error('Không thể tải tệp tin từ Server');

      const encryptedMetaHeader = res.headers.get('X-File-Metadata');
      const originalName = res.headers.get('X-Original-Name');
      const kcsKey = await window.crypto.subtle.importKey('raw', kcsRaw, { name: 'AES-GCM' }, false, ['decrypt']);
      
      const combinedMeta = Uint8Array.from(atob(encryptedMetaHeader), c => c.charCodeAt(0));
      const decryptedMetaBuffer = await window.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: combinedMeta.slice(0, 12), additionalData: new TextEncoder().encode('secure-storage-kdc-v1') },
        kcsKey,
        combinedMeta.slice(12)
      );
      const metadata = JSON.parse(new TextDecoder().decode(decryptedMetaBuffer));

      const myEnvelope = metadata.envelope_keys.find(e => e.recipient_id === currentClientId);
      if (!myEnvelope) throw new Error('Bạn không có quyền mở file này!');
      
      const myPrivateKey = await importPrivateKeyFromPem(privateKeyPem);
      const kfRaw = await decryptRsa(myPrivateKey, myEnvelope.ek);
      const kf = await window.crypto.subtle.importKey('raw', kfRaw, { name: 'AES-GCM' }, false, ['decrypt']);

      const encryptedBuffer = await res.arrayBuffer();
      const nonce = Uint8Array.from(atob(metadata.nonce), c => c.charCodeAt(0));
      const tag = Uint8Array.from(atob(metadata.gcm_tag), c => c.charCodeAt(0));
      
      const ciphertext = new Uint8Array(encryptedBuffer);
      const dataToDecrypt = new Uint8Array(ciphertext.length + tag.length);
      dataToDecrypt.set(ciphertext); dataToDecrypt.set(tag, ciphertext.length);

      const decryptedFileBuffer = await window.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: nonce, additionalData: new TextEncoder().encode('secure-storage-client-v1') },
        kf, dataToDecrypt
      );

      const blob = new Blob([decryptedFileBuffer]);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a'); a.href = url;
      a.download = originalName ? decodeURIComponent(originalName) : 'downloaded_file';
      document.body.appendChild(a); a.click(); a.remove(); window.URL.revokeObjectURL(url); 

    } catch (err) {
      console.error(err);
      alert('Lỗi tải/giải mã: ' + err.message);
    } finally {
      setDownloadingId(null);
    }
  }

  async function submitShare() {
    if (!shareUsernames.trim()) return alert('Vui lòng nhập tên người dùng!');
    setShareLoading(true);
    try {
      const file = shareModal.file;
      const privateKeyPem = sessionStorage.getItem('private_key_pem');
      const kcs_b64 = sessionStorage.getItem('k_c_s');
      const st = sessionStorage.getItem('st');

      const myEnvelope = file.recipients.find(r => r.recipient_id === currentClientId);
      const myPrivateKey = await importPrivateKeyFromPem(privateKeyPem);
      const kfRaw = await decryptRsa(myPrivateKey, myEnvelope.ek);

      const recipientsList = shareUsernames.split(',').map(s => s.trim()).filter(Boolean);
      const userServiceUrl = import.meta.env.VITE_USER_SERVICE_URL || 'http://localhost:4002';
      
      const keyRes = await fetch(`${userServiceUrl}/api/v1/users/public-keys`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ usernames: recipientsList })
      });
      const keyData = await keyRes.json();
      const newUsersData = keyData.keys || [];
      if (newUsersData.length === 0) throw new Error('Không tìm thấy user nào hợp lệ.');

      const newEnvelopes = await Promise.all(
        newUsersData.map(async (user) => {
          const { publicKeyPem, certSerial } = await verifyAndExtractPublicKey(user.public_key);
          const pubKey = await importPublicKeyFromPem(publicKeyPem);
          const encryptedEkBase64 = await encryptRsa(pubKey, kfRaw);
          return { recipient_id: user.user_id, ek: encryptedEkBase64, algo: 'RSA-OAEP', cert_serial: certSerial };
        })
      );

      const kcsRaw = Uint8Array.from(atob(kcs_b64), c => c.charCodeAt(0));
      const serviceAuthenticator = await encryptKdcPayload(kcsRaw, { client_id: currentClientId, service_id: 'file-service', timestamp: new Date().toISOString() });
      const baseFileUrl = import.meta.env.VITE_FILE_SERVICE_URL || 'http://localhost:4001';

      const shareRes = await fetch(`${baseFileUrl}/api/v1/files/${file.id}/share`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json', 'Authorization': `Bearer ${st}`,
          'X-Request-Id': crypto.randomUUID(), 'X-Client-Time': new Date().toISOString(),
          'x-service-authenticator': serviceAuthenticator
        },
        body: JSON.stringify({ addEnvelopes: newEnvelopes, removeUserIds: [] })
      });

      if (!shareRes.ok) throw new Error('Server từ chối cập nhật quyền');
      alert(`Đã cấp quyền cho ${newUsersData.length} người!`);
      setShareModal({ isOpen: false, file: null }); setShareUsernames('');
      fetchFilesList();
    } catch (error) {
      alert('Lỗi: ' + error.message);
    } finally {
      setShareLoading(false);
    }
  }

  async function revokeShare(targetUserId) {
    if (!window.confirm('Bạn có chắc muốn xóa quyền truy cập của người này?')) return;
    
    try {
      const file = shareModal.file;
      const kcs_b64 = sessionStorage.getItem('k_c_s');
      const st = sessionStorage.getItem('st');
      const kcsRaw = Uint8Array.from(atob(kcs_b64), c => c.charCodeAt(0));

      const serviceAuthenticator = await encryptKdcPayload(kcsRaw, { client_id: currentClientId, service_id: 'file-service', timestamp: new Date().toISOString() });
      const baseFileUrl = import.meta.env.VITE_FILE_SERVICE_URL || 'http://localhost:4001';

      const res = await fetch(`${baseFileUrl}/api/v1/files/${file.id}/share`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json', 'Authorization': `Bearer ${st}`,
          'X-Request-Id': crypto.randomUUID(), 'X-Client-Time': new Date().toISOString(),
          'x-service-authenticator': serviceAuthenticator
        },
        body: JSON.stringify({ addEnvelopes: [], removeUserIds: [targetUserId] })
      });

      if (!res.ok) throw new Error('Thu hồi quyền thất bại');
      alert('Đã xóa quyền thành công!');
      
      setShareModal({ isOpen: false, file: null });
      fetchFilesList();
    } catch (error) {
      alert('Lỗi: ' + error.message);
    }
  }

  return (
    <section className="page">
      <div className="page-header">
        <div>
          <p className="eyebrow">Repository</p>
          <h2 className="page-title">My files</h2>
          <p className="page-description">Only files owned by you or shared with your active envelope key are returned.</p>
        </div>
        <button className="btn secondary" type="button" onClick={fetchFilesList} disabled={loading}>
          <RefreshCw size={16} />
          Refresh
        </button>
      </div>

      {msg && <div className="message error">{msg}</div>}

      <div className="panel">
        <div className="panel-header">
          <div>
            <h3 className="panel-title">Accessible objects</h3>
            <p className="panel-subtitle">Signed in as {currentUser}</p>
          </div>
          <span className="status info">{files.length} files</span>
        </div>

        {loading ? (
          <div className="empty-state">
            <RefreshCw size={28} />
            <div>Loading encrypted file list...</div>
          </div>
        ) : files.length === 0 ? (
          <div className="empty-state">
            <FolderOpen size={34} />
            <div>No accessible files yet.</div>
          </div>
        ) : (
          <div className="data-table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Created</th>
                  <th>Size</th>
                  <th>Access</th>
                  <th>Shared</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {files.map((file) => {
                  const perm = checkPermission(file)
                  return (
                    <tr key={file.id}>
                      <td>
                        <div className="file-name">
                          <span className="file-icon"><FileText size={17} /></span>
                          <span>{file.originalName}</span>
                        </div>
                      </td>
                      <td>{formatDate(file.createdAt)}</td>
                      <td>{formatSize(file.size)}</td>
                      <td><span className={`status ${perm.status}`}>{perm.text}</span></td>
                      <td>
                        <span className="status info">
                          {Math.max((file.recipients?.length || 0) - 1, 0)} users
                        </span>
                      </td>
                      <td>
                        <div className="button-row">
                          <button
                            className="btn secondary icon-only"
                            type="button"
                            title="Download"
                            aria-label="Download"
                            onClick={() => handleDownload(file.id)}
                            disabled={!perm.canDownload || downloadingId === file.id}
                          >
                            <DownloadCloud size={16} />
                          </button>
                          {perm.isOwner && (
                            <button
                              className="btn secondary"
                              type="button"
                              title="Manage access"
                              aria-label="Manage access"
                              onClick={() => setShareModal({ isOpen: true, file })}
                            >
                              <Share2 size={16} />
                              Quản lý quyền
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {shareModal.isOpen && (
        <div className="modal-backdrop">
          <div className="modal">
            <div className="modal-header">
              <div>
                <h3 className="modal-title">Quản lý quyền truy cập</h3>
                <p className="panel-subtitle">{shareModal.file.originalName}</p>
              </div>
              <button className="btn secondary icon-only" type="button" onClick={() => setShareModal({ isOpen: false, file: null })} aria-label="Close">
                <X size={16} />
              </button>
            </div>

            <div className="modal-body">
              <div>
                <div className="panel-header mb-8">
                  <div>
                    <h4 className="panel-title">Người đang được chia sẻ</h4>
                    <p className="panel-subtitle">Bấm Xóa quyền để thu hồi EK của người nhận.</p>
                  </div>
                  <Users size={18} color="#4357ad" />
                </div>
                <div className="recipient-list">
                  {shareModal.file.recipients.filter((recipient) => recipient.recipient_id !== currentClientId).length === 0 ? (
                    <div className="empty-inline">File này chưa được chia sẻ cho ai khác.</div>
                  ) : (
                    shareModal.file.recipients
                      .filter((recipient) => recipient.recipient_id !== currentClientId)
                      .map((recipient) => (
                        <div className="recipient-row" key={recipient.recipient_id}>
                          <div>
                            <div className="recipient-name">Shared user</div>
                            <div className="mono">{shortId(recipient.recipient_id)}</div>
                          </div>
                          <button className="btn danger" type="button" onClick={() => revokeShare(recipient.recipient_id)}>
                            <Trash2 size={15} />
                            Xóa quyền
                          </button>
                        </div>
                      ))
                  )}
                </div>
              </div>

              <div className="field">
                <label htmlFor="share-users">Thêm người được chia sẻ</label>
                <input
                  id="share-users"
                  type="text"
                  value={shareUsernames}
                  onChange={(e) => setShareUsernames(e.target.value)}
                  placeholder="alice, bob"
                  disabled={shareLoading}
                />
              </div>
            </div>

            <div className="modal-footer">
              <button className="btn secondary" type="button" onClick={() => { setShareModal({ isOpen: false, file: null }); setShareUsernames('') }}>
                Đóng
              </button>
              <button className="btn primary" type="button" onClick={submitShare} disabled={shareLoading}>
                <Share2 size={16} />
                {shareLoading ? 'Đang chia sẻ...' : 'Thêm quyền'}
              </button>
            </div>
          </div>
        </div>
      )}
    </section>
  )
}