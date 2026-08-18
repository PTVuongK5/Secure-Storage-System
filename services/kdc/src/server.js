require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();
app.use(express.json());

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-client-time, x-request-id, x-service-authenticator');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

const PORT = process.env.PORT || 4000;
const AAD = Buffer.from('secure-storage-kdc-v1');
const TGT_TTL_MS = 8 * 60 * 60 * 1000;
const ST_TTL_MS = 15 * 60 * 1000;
const AUTH_WINDOW_MS = 5 * 60 * 1000;

function parseSecretKey(value, name) {
  if (!value) {
    console.error(`Missing required environment variable ${name}`);
    process.exit(1);
  }
  if (/^[0-9a-fA-F]+$/.test(value)) {
    return Buffer.from(value, 'hex');
  }
  return Buffer.from(value, 'base64');
}
function parsePasswordHash(stored) {
  const parts = stored.split(':');
  if (parts.length !== 5 || parts[0] !== 'pbkdf2' || parts[1] !== 'sha256') {
    throw new Error('Unsupported password hash format');
  }
  return {
    iterations: Number(parts[2]),
    salt: parts[3],
    hash: parts[4]
  };
}
function verifyPassword(password, storedHash) {
  const { iterations, salt, hash } = parsePasswordHash(storedHash);
  const derived = crypto.pbkdf2Sync(password, salt, iterations, 32, 'sha256').toString('hex');
  return crypto.timingSafeEqual(Buffer.from(derived, 'hex'), Buffer.from(hash, 'hex'));
}
function deriveKeyFromPassword(password, storedHash) {
  const { iterations, salt } = parsePasswordHash(storedHash);
  return crypto.pbkdf2Sync(password, salt, iterations, 32, 'sha256');
}

const K_TGS = parseSecretKey(process.env.KDC_TGS_KEY, 'KDC_TGS_KEY');
const K_SERVICE = parseSecretKey(process.env.KDC_SERVICE_KEY, 'KDC_SERVICE_KEY');

const DB_URL = process.env.DB_URL || process.env.KDC_DB_URL;
if (!DB_URL) {
  console.error('Missing required environment variable DB_URL or KDC_DB_URL');
  process.exit(1);
}

const pool = new Pool({ connectionString: DB_URL });
const replayCache = new Map();

async function getUserByUsername(username) {
  const result = await pool.query(
    'SELECT user_id, username, password_hash, public_key, encrypted_private_key, status FROM users WHERE username = $1',
    [username]
  );
  return result.rows[0];
}

async function getUserById(userId) {
  const result = await pool.query(
    'SELECT user_id, username, status FROM users WHERE user_id = $1',
    [userId]
  );
  return result.rows[0];
}

async function getRolesForUser(userId) {
  const result = await pool.query(
    `SELECT r.role_name
     FROM user_roles ur
     JOIN roles r ON ur.role_id = r.role_id
     WHERE ur.user_id = $1`,
    [userId]
  );
  return result.rows.map((row) => row.role_name);
}

function deriveKey(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 120000, 32, 'sha256');
}

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

function makeError(code, message, status = 400) {
  return { status, body: { error: { code, message } } };
}


function guardHeaders(req) {
  if (!req.headers['x-request-id'] || !req.headers['x-client-time']) {
    return makeError('ERR_AUTH_001', 'Missing required headers X-Request-Id or X-Client-Time', 400);
  }

  const clientTime = Date.parse(req.headers['x-client-time']);
  if (Number.isNaN(clientTime)) {
    return makeError('ERR_AUTH_001', 'Invalid X-Client-Time header format', 400);
  }

  return null;
}
function cleanReplayCache() {
  const now = Date.now();
  for (const [key, expiresAt] of replayCache.entries()) {
    if (expiresAt < now) {
      replayCache.delete(key);
    }
  }
}
function checkReplay(clientId, serviceId, requestId) {
  cleanReplayCache();
  const key = `${clientId}|${serviceId}|${requestId}`;
  if (replayCache.has(key)) {
    return true;
  }
  replayCache.set(key, Date.now() + AUTH_WINDOW_MS);
  return false;
}

function nowIso() {
  return new Date().toISOString();
}

app.post('/api/v1/auth/login', async (req, res) => {
  const headerError = guardHeaders(req);
  if (headerError) {
    return res.status(headerError.status).json(headerError.body);
  }

  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: { code: 'ERR_AUTH_001', message: 'username and password are required' } });
  }

  const user = await getUserByUsername(username);
  if (!user || user.status !== 'active') {
    return res.status(401).json({ error: { code: 'ERR_AUTH_001', message: 'Invalid credentials' } });
  }

  const isDerivedHex = typeof password === 'string' && /^[0-9a-fA-F]{64}$/.test(password);

  try {
    if (isDerivedHex) {
      const { hash } = parsePasswordHash(user.password_hash);
      if (!crypto.timingSafeEqual(Buffer.from(password, 'hex'), Buffer.from(hash, 'hex'))) {
        return res.status(401).json({ error: { code: 'ERR_AUTH_001', message: 'Invalid credentials' } });
      }
    } else {
      if (!verifyPassword(password, user.password_hash)) {
        return res.status(401).json({ error: { code: 'ERR_AUTH_001', message: 'Invalid credentials' } });
      }
    }
  } catch (error) {
    return res.status(500).json({ error: { code: 'ERR_AUTH_001', message: 'Unable to verify credentials' } });
  }

  const roles = await getRolesForUser(user.user_id);
  const k_c_tgs = crypto.randomBytes(32);
  const now = Date.now();
  const tgtPayload = {
    client_id: user.user_id,
    username: user.username,
    tgs_id: 'kdc-tgs',
    valid_from: now,
    expires_at: now + TGT_TTL_MS,
    k_c_tgs: k_c_tgs.toString('base64')
  };

  const tgt = encryptAesGcm(K_TGS, JSON.stringify(tgtPayload));
  const envelopeKey = isDerivedHex ? Buffer.from(password, 'hex') : deriveKeyFromPassword(password, user.password_hash);
  const envelope = encryptAesGcm(envelopeKey, JSON.stringify({ k_c_tgs: k_c_tgs.toString('base64'), expires_at: tgtPayload.expires_at }));

  return res.status(200).json({
    request_id: req.headers['x-request-id'],
    data: {
      client_id: user.user_id,
      username: user.username,
      public_key: user.public_key,                          
      encrypted_private_key: user.encrypted_private_key,
      roles,
      tgt,
      envelope,
      expires_at: new Date(tgtPayload.expires_at).toISOString()
    }
  });
});

app.get('/api/v1/auth/challenge', async (req, res) => {
  const headerError = guardHeaders(req);
  if (headerError) {
    return res.status(headerError.status).json(headerError.body);
  }
  const username = req.query.username;
  if (!username) return res.status(400).json({ error: { code: 'ERR_AUTH_001', message: 'username required' } });
  const user = await getUserByUsername(username);
  if (!user) return res.status(404).json({ error: { code: 'ERR_AUTH_001', message: 'User not found' } });
  try {
    const parsed = parsePasswordHash(user.password_hash);
    return res.status(200).json({ request_id: req.headers['x-request-id'], data: { iterations: parsed.iterations, salt: parsed.salt } });
  } catch (err) {
    return res.status(500).json({ error: { code: 'ERR_AUTH_001', message: 'Unable to parse password format' } });
  }
});

app.post('/api/v1/auth/ticket', (req, res) => {
  const headerError = guardHeaders(req);
  if (headerError) {
    return res.status(headerError.status).json(headerError.body);
  }

  const { tgt, authenticator, service_id } = req.body || {};
  if (!tgt || !authenticator || !service_id) {
    return res.status(400).json({ error: { code: 'ERR_AUTH_001', message: 'tgt, authenticator, and service_id are required' } });
  }

  let tgtPayload;
  try {
    tgtPayload = JSON.parse(decryptAesGcm(K_TGS, tgt));
  } catch (error) {
    return res.status(401).json({ error: { code: 'ERR_AUTH_001', message: 'Invalid or expired TGT' } });
  }

  const now = Date.now();
  if (tgtPayload.expires_at < now) {
    return res.status(401).json({ error: { code: 'ERR_AUTH_001', message: 'TGT expired' } });
  }

  const k_c_tgs = Buffer.from(tgtPayload.k_c_tgs, 'base64');
  let authenticatorPayload;
  try {
    authenticatorPayload = JSON.parse(decryptAesGcm(k_c_tgs, authenticator));
  } catch (error) {
    return res.status(401).json({ error: { code: 'ERR_AUTH_001', message: 'Invalid authenticator' } });
  }

  if (authenticatorPayload.client_id !== tgtPayload.client_id || authenticatorPayload.service_id !== 'kdc-tgs') {
    return res.status(401).json({ error: { code: 'ERR_AUTH_001', message: 'Authenticator mismatch' } });
  }

  const authTime = Date.parse(authenticatorPayload.timestamp);
  if (Number.isNaN(authTime) || Math.abs(now - authTime) > AUTH_WINDOW_MS) {
    return res.status(401).json({ error: { code: 'ERR_AUTH_001', message: 'Authenticator timestamp invalid or expired' } });
  }

  const k_c_s = crypto.randomBytes(32);
  const stPayload = {
    client_id: tgtPayload.client_id,
    service_id,
    valid_from: now,
    expires_at: now + ST_TTL_MS,
    k_c_s: k_c_s.toString('base64')
  };

  const st = encryptAesGcm(K_SERVICE, JSON.stringify(stPayload));
  const sessionEnvelope = encryptAesGcm(k_c_tgs, JSON.stringify({ k_c_s: k_c_s.toString('base64'), service_id, expires_at: stPayload.expires_at }));

  return res.status(200).json({
    request_id: req.headers['x-request-id'],
    data: {
      st,
      session: sessionEnvelope,
      expires_at: new Date(stPayload.expires_at).toISOString()
    }
  });
});

app.post('/api/v1/auth/verify', async (req, res) => {
  const headerError = guardHeaders(req);
  if (headerError) {
    return res.status(headerError.status).json(headerError.body);
  }

  const { st, authenticator, service_id, request_id } = req.body || {};
  if (!st || !authenticator || !service_id || !request_id) {
    return res.status(400).json({ error: { code: 'ERR_AUTH_001', message: 'st, authenticator, service_id, and request_id are required' } });
  }

  let stPayload;
  try {
    stPayload = JSON.parse(decryptAesGcm(K_SERVICE, st));
  } catch (error) {
    return res.status(401).json({ error: { code: 'ERR_AUTH_001', message: 'Invalid ST' } });
  }

  const now = Date.now();
  if (stPayload.expires_at < now) {
    return res.status(401).json({ error: { code: 'ERR_AUTH_001', message: 'ST expired' } });
  }

  if (stPayload.service_id !== service_id) {
    return res.status(401).json({ error: { code: 'ERR_AUTH_001', message: 'Service mismatch in ST' } });
  }

  const k_c_s = Buffer.from(stPayload.k_c_s, 'base64');
  let authPayload;
  try {
    authPayload = JSON.parse(decryptAesGcm(k_c_s, authenticator));
  } catch (error) {
    return res.status(401).json({ error: { code: 'ERR_AUTH_001', message: 'Invalid service authenticator' } });
  }

  if (authPayload.client_id !== stPayload.client_id || authPayload.service_id !== service_id) {
    return res.status(401).json({ error: { code: 'ERR_AUTH_001', message: 'Authenticator fields mismatch' } });
  }

  const authTime = Date.parse(authPayload.timestamp);
  if (Number.isNaN(authTime) || Math.abs(now - authTime) > AUTH_WINDOW_MS) {
    return res.status(401).json({ error: { code: 'ERR_AUTH_001', message: 'Authenticator timestamp invalid or expired' } });
  }

  if (checkReplay(stPayload.client_id, service_id, request_id)) {
    return res.status(401).json({ error: { code: 'ERR_AUTH_002', message: 'Replay detected' } });
  }

  const user = await getUserById(stPayload.client_id);
  if (!user || user.status !== 'active') {
    return res.status(401).json({ error: { code: 'ERR_AUTH_001', message: 'Invalid ticket owner' } });
  }

  const roles = await getRolesForUser(stPayload.client_id);

  return res.status(200).json({
    request_id: req.headers['x-request-id'],
    data: {
      client_id: stPayload.client_id,
      service_id,
      roles,
      expires_at: new Date(stPayload.expires_at).toISOString()
    }
  });
});

app.get('/api/v1/auth/health', (req, res) => {
  res.status(200).json({ status: 'ok', timestamp: nowIso() });
});

app.listen(PORT, () => {
  console.log(`KDC service listening on http://localhost:${PORT}`);
});
