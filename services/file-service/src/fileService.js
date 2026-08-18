const path = require('path');
const fs = require('fs');
const { Pool } = require('pg');

const DB_URL = process.env.FILE_DB_URL || 'postgresql://:23120408@localhost:5432/file_server';

const pool = new Pool({ connectionString: DB_URL });

const MIGRATION_SQL = path.join(__dirname, '/migrations', '001_file_service_init.sql');

async function initDb() {
  try {
    const sql = fs.readFileSync(MIGRATION_SQL, 'utf8');
    await pool.query(sql);
    console.log('file-service: migrations applied (or already exist) on PostgreSQL');
  } catch (err) {
    console.error('migration error', err);
  }

  try {
    await pool.query('ALTER TABLE file_recipients ADD COLUMN IF NOT EXISTS cert_serial VARCHAR(100);');
    console.log('file-service: cert_serial column is ready');
  } catch (err) {
    console.error('Failed to add cert_serial column', err);
  }
}

async function insertFileMetadata(meta) {
  const query = `
    INSERT INTO files(id, original_name, owner, size, storage_path, metadata, created_at) 
    VALUES ($1, $2, $3, $4, $5, $6, $7)
    ON CONFLICT (id) DO UPDATE SET
      original_name = EXCLUDED.original_name,
      owner = EXCLUDED.owner,
      size = EXCLUDED.size,
      storage_path = EXCLUDED.storage_path,
      metadata = EXCLUDED.metadata;
  `;

  const values = [
    meta.id,
    meta.originalName,
    meta.owner,
    meta.size,
    meta.storagePath,
    JSON.stringify(meta.metadata || {}),
    meta.createdAt
  ];

  await pool.query(query, values);
}

async function getFileMetadata(id) {
  const query = `SELECT * FROM files WHERE id = $1`;
  const result = await pool.query(query, [id]);

  if (result.rows.length === 0) return null;

  const row = result.rows[0];
  let parsedMetadata = {};
  if (typeof row.metadata === 'string') {
    parsedMetadata = JSON.parse(row.metadata);
  } else if (typeof row.metadata === 'object' && row.metadata !== null) {
    parsedMetadata = row.metadata;
  }

  return {
    id: row.id,
    originalName: row.original_name,
    owner: row.owner,
    size: row.size,
    storagePath: row.storage_path,
    metadata: parsedMetadata,
    createdAt: row.created_at,
  };
}

async function insertFileRecipients(fileId, recipientsList) {
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const query = `INSERT INTO file_recipients(file_id, recipient_id, ek, algo, cert_serial, granted_at) VALUES ($1, $2, $3, $4, $5, $6)`;

    for (const r of recipientsList) {
      await client.query(query, [fileId, r.recipient_id, r.ek, r.algo || 'RSA-OAEP', r.cert_serial || null, new Date().toISOString()]);
    }

    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

async function insertAudit(actor, action, target, details) {
  const query = `INSERT INTO audit_log(timestamp, actor, action, target, details) VALUES ($1, $2, $3, $4, $5)`;
  const values = [new Date().toISOString(), actor, action, target, details];
  await pool.query(query, values);
}

async function getAllFiles() {
  const query = `
    SELECT id, original_name, owner, size, created_at, metadata
    FROM files
    ORDER BY created_at DESC
  `;
  const result = await pool.query(query);
  return result.rows;
}

module.exports = { initDb, insertFileMetadata, getFileMetadata, insertFileRecipients, insertAudit, getAllFiles };