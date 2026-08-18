require('dotenv').config();
const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const morgan = require('morgan');
const helmet = require('helmet');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const { initDb, insertFileMetadata, getFileMetadata, insertFileRecipients, insertAudit, getAllFiles } = require('./fileService');

// -------------------------------------------------------------
// SETUP CRYPTO & KERBEROS LOCAL VERIFICATION
// -------------------------------------------------------------
const AAD = Buffer.from('secure-storage-kdc-v1');
const AUTH_WINDOW_MS = 5 * 60 * 1000;

function parseSecretKey(value, name) {
  if (!value) {
    console.error(`Missing required environment variable ${name}`);
    process.exit(1);
  }
  return /^[0-9a-fA-F]+$/.test(value) ? Buffer.from(value, 'hex') : Buffer.from(value, 'base64');
}

// Khóa K_SERVICE dùng chung với KDC
const K_SERVICE = parseSecretKey(process.env.KDC_SERVICE_KEY, 'KDC_SERVICE_KEY');

function encryptAesGcm(key, plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(AAD);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, ciphertext, tag]).toString('base64');
}

function decryptAesGcm(key, payloadBase64) {
  const payload = Buffer.from(payloadBase64, 'base64');
  const iv = payload.slice(0, 12);
  const tag = payload.slice(payload.length - 16);
  const ciphertext = payload.slice(12, payload.length - 16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAAD(AAD);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
}

// HÀM TỰ GIẢI MÃ ST TẠI LOCAL TRÊN SERVER
async function verifyServiceTicket(st, authenticator, requestId) {
  try {
    let stPayload = JSON.parse(decryptAesGcm(K_SERVICE, st));
    const now = Date.now();
    
    if (stPayload.expires_at < now) throw new Error('Service Ticket expired');
    if (stPayload.service_id !== 'file-service') throw new Error('Service mismatch in ST');

    const k_c_s = Buffer.from(stPayload.k_c_s, 'base64');
    let authPayload = JSON.parse(decryptAesGcm(k_c_s, authenticator));

    if (authPayload.client_id !== stPayload.client_id) throw new Error('Authenticator mismatch');
    const authTime = Date.parse(authPayload.timestamp);
    if (Number.isNaN(authTime) || Math.abs(now - authTime) > AUTH_WINDOW_MS) {
      throw new Error('Authenticator expired');
    }

    return { client_id: stPayload.client_id, k_c_s: k_c_s };
  } catch (e) {
    const err = new Error(e.message || 'Ticket verification failed');
    err.status = 401;
    throw err;
  }
}

// -------------------------------------------------------------
// SETUP EXPRESS APP
// -------------------------------------------------------------
const STORAGE_DIR = path.join(__dirname, '..', '..', '..', 'storage', 'files');
if (!fs.existsSync(STORAGE_DIR)) fs.mkdirSync(STORAGE_DIR, { recursive: true });

// 1. KHỞI TẠO EXPRESS APP
const app = express();

// 2. CẤU HÌNH MIDDLEWARE
app.use(helmet());
app.use(morgan('dev'));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Request-Id, X-Client-Time, x-service-authenticator');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// 3. CẤU HÌNH MULTER
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, STORAGE_DIR); 
  },
  filename: function (req, file, cb) {
    const uniqueId = crypto.randomUUID();
    cb(null, uniqueId + '.cipher');
  }
});

const upload = multer({ 
  storage: storage,
  limits: { fileSize: 500 * 1024 * 1024 }
});

// -------------------------------------------------------------
// UPLOAD ENDPOINT
// -------------------------------------------------------------
app.post('/api/v1/files/upload', upload.single('ciphertext'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'ciphertext file required' });

    // Lấy token không phân biệt hoa thường
    const authHeader = req.headers['authorization'] || '';
    const match = authHeader.match(/^Bearer\s+(.*)$/i);
    const st = match ? match[1].trim() : null;
    
    // Ưu tiên đọc header, nếu không có mới tìm trong body (hỗ trợ FormData stream)
    const serviceAuthenticator = req.headers['x-service-authenticator'] || req.body.authenticator;
    const requestId = req.headers['x-request-id'] || crypto.randomUUID();
    
    if (!st || !serviceAuthenticator) {
       console.log("=== [LỖI UPLOAD] MẤT DỮ LIỆU XÁC THỰC ===");
       console.log("- Token ST có không?:", st ? "Có" : "KHÔNG CÓ");
       console.log("- Authenticator có không?:", serviceAuthenticator ? "Có" : "KHÔNG CÓ");
       console.log("- Request Body:", req.body);
       console.log("===========================================");

       if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path); 
       return res.status(401).json({ error: 'Missing auth data' });
    }

    let session;
    try {
      session = await verifyServiceTicket(st, serviceAuthenticator, requestId);
    } catch (e) {
      if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
      return res.status(e.status || 401).json({ error: e.message });
    }

    const storagePath = req.file.path; 
    const filename = req.file.filename;
    const id = filename.replace('.cipher', '');

    let clientMetadata = {};
    try {
      if (req.body.metadata) {
        const decryptedMetaStr = decryptAesGcm(session.k_c_s, req.body.metadata);
        clientMetadata = JSON.parse(decryptedMetaStr);
      }
    } catch (parseErr) {
      console.warn('Lỗi giải mã metadata từ Client:', parseErr);
      return res.status(400).json({ error: 'Invalid encrypted metadata' });
    }

    const metadata = {
      id,
      originalName: req.body.originalName || req.file.originalname,
      owner: session.client_id,
      size: req.file.size,
      storagePath,
      metadata: clientMetadata,
      createdAt: new Date().toISOString(),
    };

    await insertFileMetadata(metadata);

    if (clientMetadata.envelope_keys && Array.isArray(clientMetadata.envelope_keys)) {
      await insertFileRecipients(id, clientMetadata.envelope_keys);
    }

    try { await insertAudit(metadata.owner, 'upload', id, JSON.stringify({ recipients: clientMetadata.envelope_keys || [] })); } catch (e) {}

    return res.status(201).json({ fileId: id, message: 'Upload success' });
  } catch (err) {
    console.error(err);
    if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    return res.status(500).json({ error: 'internal error' });
  }
});

// -------------------------------------------------------------
// DOWNLOAD ENDPOINT
// -------------------------------------------------------------
app.get('/api/v1/download/:id', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'] || '';
    const match = authHeader.match(/^Bearer\s+(.*)$/i);
    const st = match ? match[1].trim() : null;

    const serviceAuthenticator = req.headers['x-service-authenticator'] || req.query.authenticator;
    const requestId = req.headers['x-request-id'] || crypto.randomUUID();
    
    if (!st || !serviceAuthenticator) return res.status(401).json({ error: 'Missing auth data' });

    let session;
    try {
      session = await verifyServiceTicket(st, serviceAuthenticator, requestId);
    } catch (e) {
      return res.status(e.status || 401).json({ error: e.message });
    }

    const id = req.params.id;
    const meta = await getFileMetadata(id);
    if (!meta) return res.status(404).json({ error: 'not found' });

    const secureMetadataBase64 = encryptAesGcm(session.k_c_s, JSON.stringify(meta.metadata));

    res.set('Access-Control-Expose-Headers', 'X-File-Metadata, X-Original-Name');
    res.set('X-File-Metadata', secureMetadataBase64);
    res.set('X-Original-Name', encodeURIComponent(meta.originalName || id));

    try { await insertAudit(session.client_id, 'download', id, JSON.stringify({ requester: session.client_id })); } catch (e) {}
    
    return res.download(meta.storagePath, meta.originalName || (id + '.cipher'));
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'internal error' });
  }
});

// -------------------------------------------------------------
// GET FILES LIST ENDPOINT
// -------------------------------------------------------------
app.get('/api/v1/files', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'] || '';
    const match = authHeader.match(/^Bearer\s+(.*)$/i);
    const st = match ? match[1].trim() : null;

    const serviceAuthenticator = req.headers['x-service-authenticator'];
    const requestId = req.headers['x-request-id'] || crypto.randomUUID();

    if (!st || !serviceAuthenticator) {
      return res.status(401).json({ error: 'Missing Service Ticket or service authenticator' });
    }

    let session;
    try {
      session = await verifyServiceTicket(st, serviceAuthenticator, requestId);
    } catch (e) {
      return res.status(e.status || 401).json({ error: e.message || 'Invalid or expired Service Ticket' });
    }

    const dbRows = await getAllFiles(); 

    const formattedFiles = dbRows.map(row => {
      const metaObj = row.metadata || {};
      return {
        id: row.id,
        originalName: row.original_name,
        owner: row.owner,
        size: row.size,
        createdAt: row.created_at,
        recipients: metaObj.envelope_keys && Array.isArray(metaObj.envelope_keys) ? metaObj.envelope_keys : []
      };
    });    
    
    const payloadString = JSON.stringify({ files: formattedFiles });
    const encryptedPayload = encryptAesGcm(session.k_c_s, payloadString);

    return res.status(200).json({ encryptedData: encryptedPayload });
    
  } catch (err) {
    console.error('Lỗi nghiêm trọng tại API /api/v1/files:', err);
    return res.status(500).json({ error: 'internal error' });
  }
});

// -------------------------------------------------------------
// SHARE FILE ENDPOINT
// -------------------------------------------------------------
app.post('/api/v1/files/:id/share', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'] || '';
    const match = authHeader.match(/^Bearer\s+(.*)$/i);
    const st = match ? match[1].trim() : null;

    const serviceAuthenticator = req.headers['x-service-authenticator'];
    const requestId = req.headers['x-request-id'] || crypto.randomUUID();

    if (!st || !serviceAuthenticator) return res.status(401).json({ error: 'Missing auth data' });

    let session;
    try {
      session = await verifyServiceTicket(st, serviceAuthenticator, requestId);
    } catch (e) {
      return res.status(e.status || 401).json({ error: e.message });
    }

    const fileId = req.params.id;
    const { addEnvelopes = [], removeUserIds = [] } = req.body;

    const { getFileMetadata } = require('./fileService'); 
    const meta = await getFileMetadata(fileId);
    
    if (!meta) return res.status(404).json({ error: 'File không tồn tại' });
    
    const isCreator = meta.owner === session.client_id;
    const isCoOwner = meta.metadata.envelope_keys?.some(e => e.recipient_id === session.client_id);

    if (!isCreator && !isCoOwner) {
      return res.status(403).json({ error: 'Chỉ Người tạo gốc hoặc Đồng sở hữu mới có quyền chia sẻ tệp tin này.' });
    }

    const { Pool } = require('pg');
    const DB_CONNECTION = process.env.FILE_DB_URL || process.env.DB_URL || 'postgresql://postgres:23120408@localhost:5432/file_server';
    const pool = new Pool({ connectionString: DB_CONNECTION });

    try {
      await pool.query('BEGIN');

      if (removeUserIds.length > 0) {
        await pool.query(
          'DELETE FROM file_recipients WHERE file_id = $1 AND recipient_id = ANY($2::text[])',
          [fileId, removeUserIds]
        );
      }

      if (addEnvelopes.length > 0) {
        for (const env of addEnvelopes) {
          await pool.query('DELETE FROM file_recipients WHERE file_id = $1 AND recipient_id = $2', [fileId, env.recipient_id]);
          
          await pool.query(
            `INSERT INTO file_recipients (file_id, recipient_id, ek, algo) VALUES ($1, $2, $3, $4)`,
            [fileId, env.recipient_id, env.ek, env.algo]
          );
        }
      }

      const recipientsRes = await pool.query('SELECT recipient_id, ek, algo FROM file_recipients WHERE file_id = $1', [fileId]);
      
      meta.metadata.envelope_keys = recipientsRes.rows;

      await pool.query('UPDATE files SET metadata = $1 WHERE id = $2', [JSON.stringify(meta.metadata), fileId]);

      await pool.query('COMMIT');

      const { insertAudit } = require('./fileService');
      try { await insertAudit(session.client_id, 'share_update', fileId, JSON.stringify({ added: addEnvelopes.length, removed: removeUserIds })); } catch (e) {}

      return res.status(200).json({ message: 'Cập nhật quyền chia sẻ thành công' });
    } catch (dbErr) {
      await pool.query('ROLLBACK');
      console.error('Database Error during share:', dbErr);
      return res.status(500).json({ error: 'Lỗi đồng bộ dữ liệu chia sẻ' });
    }

  } catch (err) {
    console.error('Lỗi Share API:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

const PORT = process.env.PORT || 4001;

async function start() {
  await initDb();
  app.listen(PORT, () => console.log(`file-service listening on ${PORT}`));
}

start().catch((err) => {
  console.error('file-service failed to start', err);
  process.exit(1);
});
