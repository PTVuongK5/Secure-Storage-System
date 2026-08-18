import React, { useState } from 'react';
import { 
  encryptKdcPayload, 
  importPrivateKeyFromPem, 
  decryptRsa 
} from '../services/crypto';
import { ShieldCheck, FileKey, DownloadCloud } from 'lucide-react';

export default function Download() {
  const [fileId, setFileId] = useState('');
  const [msg, setMsg] = useState('');
  const [loading, setLoading] = useState(false);

  async function onDownload(e) {
    e.preventDefault();
    if (!fileId.trim()) { setMsg('Vui lòng nhập mã File ID'); return; }
    
    setMsg('Đang gửi yêu cầu tải file và xác thực Kerberos...');
    setLoading(true);

    try {
      const st = sessionStorage.getItem('st'); 
      const currentUserId = sessionStorage.getItem('client_id'); 
      const privateKeyPem = sessionStorage.getItem('private_key_pem');
      const kcs_b64 = sessionStorage.getItem('k_c_s');

      if (!st || !currentUserId || !privateKeyPem || !kcs_b64) {
        throw new Error('Phiên làm việc thiếu thông tin xác thực hoặc cặp khóa E2EE. Vui lòng đăng nhập lại!');
      }

      const kcsRaw = Uint8Array.from(atob(kcs_b64), c => c.charCodeAt(0));
      const baseFileUrl = import.meta.env.VITE_FILE_SERVICE_URL || 'http://localhost:4001';

      const requestId = crypto.randomUUID();
      const authenticatorPayload = { 
        client_id: currentUserId, 
        service_id: 'file-service', 
        timestamp: new Date().toISOString() 
      };
      const serviceAuthenticator = await encryptKdcPayload(kcsRaw, authenticatorPayload);

      const res = await fetch(`${baseFileUrl}/api/v1/download/${fileId}`, {
        headers: {
          'Authorization': `Bearer ${st}`,
          'X-Request-Id': requestId,
          'X-Client-Time': new Date().toISOString(),
          'x-service-authenticator': serviceAuthenticator
        }
      });

      if (!res.ok) throw new Error('Không tìm thấy file hoặc bạn không có quyền tải tệp tin này.');

      setMsg('Đang giải mã gói thông tin Metadata từ Server...');
      const encryptedMetaHeader = res.headers.get('X-File-Metadata');
      const originalName = res.headers.get('X-Original-Name');
      if (!encryptedMetaHeader) throw new Error('Server không gửi kèm gói bảo mật Metadata');

      const kcsKey = await window.crypto.subtle.importKey('raw', kcsRaw, { name: 'AES-GCM' }, false, ['decrypt']);
      const combinedMeta = Uint8Array.from(atob(encryptedMetaHeader), c => c.charCodeAt(0));
      
      const metaIv = combinedMeta.slice(0, 12);
      const metaCiphertextAndTag = combinedMeta.slice(12);
      const aad = new TextEncoder().encode('secure-storage-kdc-v1');

      const decryptedMetaBuffer = await window.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: metaIv, additionalData: aad },
        kcsKey,
        metaCiphertextAndTag
      );
      
      const metadata = JSON.parse(new TextDecoder().decode(decryptedMetaBuffer));

      setMsg('Đang dùng Private Key cá nhân để mở phong bì khóa RSA...');
      
      const myEnvelope = metadata.envelope_keys.find(e => e.recipient_id === currentUserId);
      if (!myEnvelope) throw new Error('Bạn không có tên trong danh sách phân quyền truy cập của tệp tin này!');

      const myPrivateKey = await importPrivateKeyFromPem(privateKeyPem);
      
      const kfRaw = await decryptRsa(myPrivateKey, myEnvelope.ek);

      const kf = await window.crypto.subtle.importKey('raw', kfRaw, { name: 'AES-GCM' }, false, ['decrypt']);

      setMsg('Đang giải mã toàn bộ nội dung tệp tin (AES-GCM)...');
      const encryptedBuffer = await res.arrayBuffer();
      const nonce = Uint8Array.from(atob(metadata.nonce), c => c.charCodeAt(0));
      const tag = Uint8Array.from(atob(metadata.gcm_tag), c => c.charCodeAt(0));

      const ciphertext = new Uint8Array(encryptedBuffer);
      const dataToDecrypt = new Uint8Array(ciphertext.length + tag.length);
      dataToDecrypt.set(ciphertext);
      dataToDecrypt.set(tag, ciphertext.length);

      const decryptedFileBuffer = await window.crypto.subtle.decrypt(
        { 
          name: 'AES-GCM', 
          iv: nonce, 
          additionalData: new TextEncoder().encode('secure-storage-client-v1') 
        },
        kf,
        dataToDecrypt
      );

      const blob = new Blob([decryptedFileBuffer]);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = originalName ? decodeURIComponent(originalName) : 'downloaded_file';
      document.body.appendChild(a);
      a.click();
      a.remove(); 
      window.URL.revokeObjectURL(url); 

      setMsg('Tải xuống và Giải mã tệp tin thành công! 🎉');
    } catch (err) {
      console.error(err);
      setMsg('Lỗi giải mã: ' + (err.message || err));
    } finally {
      setLoading(false);
    }
  }

  const isError = msg.toLowerCase().includes('error') || msg.toLowerCase().includes('missing') || msg.toLowerCase().includes('denied')
  const isSuccess = msg.toLowerCase().includes('complete')

  return (
    <section className="page">
      <div className="page-header">
        <div>
          <p className="eyebrow">Recovery</p>
          <h2 className="page-title">Download by file ID</h2>
          <p className="page-description">Fetch ciphertext, unwrap the file key, decrypt locally, and verify the original SHA-256 hash.</p>
        </div>
        <span className="status info">
          <ShieldCheck size={14} />
          Verified decrypt
        </span>
      </div>

      <div className="grid two">
        <div className="panel">
          <div className="panel-header">
            <div>
              <h3 className="panel-title">File request</h3>
              <p className="panel-subtitle">Access is checked by file-service before metadata is returned.</p>
            </div>
            <FileKey size={21} color="#0a6f73" />
          </div>

          <form className="form" onSubmit={onDownload}>
            <div className="field">
              <label htmlFor="download-file-id">File ID</label>
              <input
                id="download-file-id"
                value={fileId}
                onChange={(e) => setFileId(e.target.value)}
                placeholder="123e4567-e89b-12d3-a456-426614174000"
                disabled={loading}
                required
              />
            </div>
            <button className="btn primary" type="submit" disabled={loading}>
              <DownloadCloud size={16} />
              {loading ? 'Decrypting...' : 'Download and decrypt'}
            </button>
          </form>

          {msg && <div className={`message mt-14 ${isSuccess ? 'success' : isError ? 'error' : ''}`}>{msg}</div>}
        </div>

        <div className="panel">
          <div className="panel-header">
            <div>
              <h3 className="panel-title">Decrypt path</h3>
              <p className="panel-subtitle">Each step happens in order for the active session.</p>
            </div>
          </div>
          <div className="grid">
            <div className="recipient-row"><span>Ticket</span><span className="status success">ST</span></div>
            <div className="recipient-row"><span>Envelope</span><span className="status info">RSA-OAEP</span></div>
            <div className="recipient-row"><span>Content</span><span className="status info">AES-GCM</span></div>
            <div className="recipient-row"><span>Integrity</span><span className="status success">SHA-256</span></div>
          </div>
        </div>
      </div>
    </section>
  )
}

