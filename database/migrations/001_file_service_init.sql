BEGIN;

DROP TABLE IF EXISTS audit_log CASCADE;
DROP TABLE IF EXISTS file_recipients CASCADE;
DROP TABLE IF EXISTS files CASCADE;

CREATE TABLE IF NOT EXISTS files (
  id TEXT PRIMARY KEY,
  original_name TEXT,
  owner TEXT,
  size BIGINT,             
  storage_path TEXT,
  metadata JSONB,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS file_recipients (
  id SERIAL PRIMARY KEY,
  file_id TEXT NOT NULL,
  recipient_id TEXT NOT NULL, 
  ek TEXT,
  algo TEXT,
  cert_serial TEXT,
  granted_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  revoked_at TIMESTAMP WITH TIME ZONE,
  FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS audit_log (
  id SERIAL PRIMARY KEY,
  timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  actor TEXT,
  action TEXT NOT NULL,
  target TEXT,
  details TEXT
);

COMMIT;