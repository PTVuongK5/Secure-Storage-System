// Web Crypto helpers for AES-GCM and SHA-256
import forge from 'node-forge';

export async function generateAesKey() {
  return await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt'])
}

export async function exportRawKey(key) {
  return new Uint8Array(await crypto.subtle.exportKey('raw', key))
}

export async function importRawKey(raw) {
  return await crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt'])
}

export async function sha256(arrayBuffer) {
  const hash = await crypto.subtle.digest('SHA-256', arrayBuffer)
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('')
}

export async function encryptAesGcm(key, arrayBuffer, iv) {
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: new TextEncoder().encode('secure-storage-client-v1') }, key, arrayBuffer)
  const ctArr = new Uint8Array(ct)
  const tag = ctArr.slice(ctArr.length - 16)
  const ciphertext = ctArr.slice(0, ctArr.length - 16)
  return {
    // SỬA LỖI: Dùng hàm arrayBufferToBase64 an toàn để không bị tràn RAM (Call Stack)
    ciphertext_b64: arrayBufferToBase64(ciphertext),
    tag_b64: arrayBufferToBase64(tag),
    iv_b64: arrayBufferToBase64(iv)
  }
}

export async function decryptAesGcm(key, ciphertext_b64, iv_b64, tag_b64) {
  const ct = Uint8Array.from(atob(ciphertext_b64), c => c.charCodeAt(0))
  const tag = Uint8Array.from(atob(tag_b64), c => c.charCodeAt(0))
  const iv = Uint8Array.from(atob(iv_b64), c => c.charCodeAt(0))
  const merged = new Uint8Array(ct.length + tag.length)
  merged.set(ct, 0)
  merged.set(tag, ct.length)
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: new TextEncoder().encode('secure-storage-client-v1') }, key, merged.buffer)
  return plain
}

// KDC-specific helpers for encrypting/decrypting the envelope payloads using AES-GCM with a raw key derived from PBKDF2
export async function decryptKdcPayload(rawKeyBytes, payloadBase64) {
  const payload = Uint8Array.from(
    atob(payloadBase64),
    c => c.charCodeAt(0)
  )

  const iv = payload.slice(0, 12)
  const tag = payload.slice(payload.length - 16)
  const ciphertext = payload.slice(12, payload.length - 16)

  const merged = new Uint8Array(
    ciphertext.length + tag.length
  )

  merged.set(ciphertext)
  merged.set(tag, ciphertext.length)

  const key = await crypto.subtle.importKey(
    'raw',
    rawKeyBytes,
    'AES-GCM',
    false,
    ['decrypt']
  )

  const plain = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv,
      additionalData: new TextEncoder().encode(
        'secure-storage-kdc-v1'
      )
    },
    key,
    merged
  )

  return JSON.parse(
    new TextDecoder().decode(plain)
  )
}

export async function encryptKdcPayload(rawKeyBytes, obj) {
  const iv = crypto.getRandomValues(
    new Uint8Array(12)
  )

  const key = await crypto.subtle.importKey(
    'raw',
    rawKeyBytes,
    'AES-GCM',
    false,
    ['encrypt']
  )

  const encrypted = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv,
      additionalData: new TextEncoder().encode(
        'secure-storage-kdc-v1'
      )
    },
    key,
    new TextEncoder().encode(
      JSON.stringify(obj)
    )
  )

  const enc = new Uint8Array(encrypted)

  const result = new Uint8Array(
    iv.length + enc.length
  )

  result.set(iv)
  result.set(enc, iv.length)

  // SỬA LỖI: Dùng hàm an toàn tránh tràn RAM
  return arrayBufferToBase64(result)
}

// =====================================================================
// UTILS: CÁC HÀM HỖ TRỢ CHUYỂN ĐỔI BASE64 VÀ PEM
// =====================================================================

function arrayBufferToBase64(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  
  // KỸ THUẬT BĂM NHỎ (CHUNKING) ĐỂ KHÔNG BỊ CRASH VỚI FILE LỚN
  const chunkSize = 8192; 
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
  }
  return window.btoa(binary);
}

function base64ToArrayBuffer(base64) {
  const binary_string = window.atob(base64);
  const len = binary_string.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary_string.charCodeAt(i);
  }
  return bytes.buffer;
}

// Bọc chuỗi Base64 thành chuẩn PEM để lưu Database cho đẹp (Giống Seed Data)
function toPem(base64, type) {
  const formatted = base64.match(/.{1,64}/g).join('\n');
  return `-----BEGIN ${type}-----\n${formatted}\n-----END ${type}-----`;
}

// Lọc bỏ Header/Footer của PEM để lấy lại cục Base64
function stripPem(pem) {
  return pem
    .replace(/-----BEGIN (.*)-----/, '')
    .replace(/-----END (.*)-----/, '')
    .replace(/\s+/g, '');
}

// =====================================================================
// 1. HÀM TẠO CẶP KHÓA RSA (Dùng khi User đăng ký tài khoản)
// =====================================================================
export async function generateRsaKeyPair() {
  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048, // Độ dài 2048-bit là tiêu chuẩn an toàn hiện hành
      publicExponent: new Uint8Array([1, 0, 1]), // 65537
      hash: "SHA-256",
    },
    true, // Cho phép export khóa
    ["encrypt", "decrypt"]
  );
  return keyPair;
}

// =====================================================================
// 2. HÀM EXPORT KHÓA RA CHUỖI PEM (Để lưu lên Database)
// =====================================================================
export async function exportPublicKeyToPem(publicKey) {
  const exported = await window.crypto.subtle.exportKey("spki", publicKey);
  const base64 = arrayBufferToBase64(exported);
  return toPem(base64, "PUBLIC KEY");
}

export async function exportPrivateKeyToPem(privateKey) {
  const exported = await window.crypto.subtle.exportKey("pkcs8", privateKey);
  const base64 = arrayBufferToBase64(exported);
  return toPem(base64, "PRIVATE KEY"); // Lưu ý: Sau này hàm này sẽ bị bọc KEK trước khi đẩy lên DB
}

// =====================================================================
// 3. HÀM IMPORT KHÓA TỪ CHUỖI PEM VÀO RAM (Để sử dụng)
// =====================================================================
export async function importPublicKeyFromPem(pem) {
  const base64 = stripPem(pem);
  const binaryDer = base64ToArrayBuffer(base64);
  return await window.crypto.subtle.importKey(
    "spki",
    binaryDer,
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["encrypt"]
  );
}

export async function importPrivateKeyFromPem(pem) {
  const base64 = stripPem(pem);
  const binaryDer = base64ToArrayBuffer(base64);
  return await window.crypto.subtle.importKey(
    "pkcs8",
    binaryDer,
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["decrypt"]
  );
}

// =====================================================================
// 3.5 TÍCH HỢP CA/X.509
// =====================================================================

export async function createCsrAndGetCert(keyPair, username) {
  // Xuất khóa thô ra PEM
  const privateKeyPem = await exportPrivateKeyToPem(keyPair.privateKey);
  const publicKeyPem = await exportPublicKeyToPem(keyPair.publicKey);

  // Đưa vào thư viện node-forge
  const forgePrivateKey = forge.pki.privateKeyFromPem(privateKeyPem);
  const forgePublicKey = forge.pki.publicKeyFromPem(publicKeyPem);

  // Tạo CSR (Certificate Signing Request)
  const csr = forge.pki.createCertificationRequest();
  csr.publicKey = forgePublicKey;
  csr.setSubject([{
    name: 'commonName',
    value: username
  }]);
  csr.sign(forgePrivateKey, forge.md.sha256.create());
  const csrPem = forge.pki.certificationRequestToPem(csr);

  // Gọi CA Server để xin cấp chứng chỉ
  const caUrl = import.meta.env.VITE_CA_URL || 'http://localhost:7002';

  // NOTE: Trong môi trường thực tế, API KEY nên được lấy an toàn hoặc truyền thông qua Proxy
  // Để demo, chúng ta dùng chung 1 key hoặc bạn có thể thay đổi tùy ý.
  const CA_API_KEY = "2006fc97ac0b15866d0800854510a73f54f31ea5b91b7099f3d4dd7c4d9be700";

  const res = await fetch(`${caUrl}/api/v1/certs/issue`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': CA_API_KEY
    },
    body: JSON.stringify({
      commonName: username,
      type: 'client',
      csr: csrPem
    })
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error?.message || 'Không thể xin cấp chứng chỉ từ CA');
  }

  // CA trả về chứng chỉ dưới dạng PEM
  return data.certificate;
}

export async function verifyAndExtractPublicKey(certPem) {
  let rootCaPem = sessionStorage.getItem('root_ca_pem');
  
  // Hàm phụ trợ tải Root CA
  const fetchRootCa = async () => {
    const caUrl = import.meta.env.VITE_CA_URL || 'http://localhost:7002';
    const res = await fetch(`${caUrl}/api/v1/ca/cert`);
    if (!res.ok) throw new Error('Không thể tải Root CA Certificate');
    const pem = await res.text();
    sessionStorage.setItem('root_ca_pem', pem);
    return pem;
  };

  try {
    if (!rootCaPem) {
      rootCaPem = await fetchRootCa();
    }

    let rootCa = forge.pki.certificateFromPem(rootCaPem);
    let cert = forge.pki.certificateFromPem(certPem);

    // Xác minh lần 1
    let verified = rootCa.verify(cert);

    // Nếu Root CA trong cache có thể đã cũ (stale), tải lại và thử lần 2
    if (!verified) {
      console.warn('Chứng chỉ không khớp với Root CA hiện tại. Thử tải lại Root CA...');
      rootCaPem = await fetchRootCa();
      rootCa = forge.pki.certificateFromPem(rootCaPem);
      verified = rootCa.verify(cert);
      
      if (!verified) {
        throw new Error('Chứng chỉ không hợp lệ hoặc giả mạo (Chữ ký không khớp Root CA)!');
      }
    }

    // Kiểm tra thời hạn
    const now = new Date();
    if (now < cert.validity.notBefore || now > cert.validity.notAfter) {
      throw new Error('Chứng chỉ đã hết hạn hoặc chưa có hiệu lực!');
    }

    // Trích xuất Public Key dạng PEM
    const publicKeyPem = forge.pki.publicKeyToPem(cert.publicKey);

    // Trích xuất Serial Number (Hex string)
    const certSerial = cert.serialNumber;

    return {
      publicKeyPem,
      certSerial
    };
  } catch (error) {
    throw new Error(`Xác minh chứng chỉ thất bại: ${error.message}`);
  }
}

// =====================================================================
// 4. HÀM MÃ HÓA BẰNG PUBLIC KEY (Dùng khi Upload / Share file)
// =====================================================================
export async function encryptRsa(publicKey, dataBuffer) {
  const encryptedBuffer = await window.crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    publicKey,
    dataBuffer
  );
  return arrayBufferToBase64(encryptedBuffer);
}

// =====================================================================
// 5. HÀM GIẢI MÃ BẰNG PRIVATE KEY (Dùng khi Download file)
// =====================================================================
export async function decryptRsa(privateKey, encryptedBase64) {
  const encryptedBuffer = base64ToArrayBuffer(encryptedBase64);
  const decryptedBuffer = await window.crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    privateKey,
    encryptedBuffer
  );
  // Trả về khóa AES dạng thô (Raw ArrayBuffer)
  return decryptedBuffer;
}

// =====================================================================
// 6. HÀM BỌC PRIVATE KEY BẰNG MẬT KHẨU (Key Wrapping)
// =====================================================================
export async function wrapPrivateKeyWithPassword(privateKeyPem, password) {
  // 1. Tạo Salt (muối) và IV (vectơ khởi tạo) ngẫu nhiên
  const salt = window.crypto.getRandomValues(new Uint8Array(16));
  const iv = window.crypto.getRandomValues(new Uint8Array(12));

  // 2. Chuyển đổi mật khẩu thành định dạng khóa để dùng cho PBKDF2
  const encoder = new TextEncoder();
  const passwordKey = await window.crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );

  // 3. Dùng PBKDF2 băm mật khẩu thành khóa AES-GCM 256-bit (KEK)
  const kek = await window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 100000, // Lặp 100.000 lần để chống Brute-force
      hash: "SHA-256"
    },
    passwordKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"]
  );

  // 4. Dùng KEK mã hóa chuỗi Private Key PEM
  const encryptedBuffer = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    kek,
    encoder.encode(privateKeyPem)
  );

  // 5. Gộp Salt + IV + Ciphertext lại thành một mảng duy nhất để dễ lưu DB
  const combined = new Uint8Array(salt.length + iv.length + encryptedBuffer.byteLength);
  combined.set(salt, 0);
  combined.set(iv, salt.length);
  combined.set(new Uint8Array(encryptedBuffer), salt.length + iv.length);

  // 6. Trả về chuỗi Base64
  return arrayBufferToBase64(combined.buffer);
}


// =====================================================================
// 7. HÀM MỞ KHÓA PRIVATE KEY BẰNG MẬT KHẨU (Key Unwrapping)
// =====================================================================
export async function unwrapPrivateKeyWithPassword(encryptedBase64, password) {
  const combined = new Uint8Array(base64ToArrayBuffer(encryptedBase64));

  const salt = combined.slice(0, 16);
  const iv = combined.slice(16, 28);
  const ciphertext = combined.slice(28);

  const encoder = new TextEncoder();
  const passwordKey = await window.crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );

  const kek = await window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 100000, // Phải khớp với số vòng lặp lúc Register
      hash: "SHA-256"
    },
    passwordKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );

  const decryptedBuffer = await window.crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv },
    kek,
    ciphertext
  );

  return new TextDecoder().decode(decryptedBuffer);
}

// =====================================================================
// 8. HÀM CHUYỂN ĐỔI BASE64 VÀ BYTES (Dành cho các Component React import)
// =====================================================================
export function base64ToBytes(base64) {
  const binString = atob(base64);
  return Uint8Array.from(binString, (m) => m.codePointAt(0));
}

export function bytesToBase64(bytes) {
  // SỬA LỖI: Dùng lại logic băm nhỏ để tránh tràn RAM
  let binary = '';
  const chunkSize = 8192;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}