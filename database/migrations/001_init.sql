BEGIN;

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

DROP TABLE IF EXISTS ca_audit_logs CASCADE;
DROP TABLE IF EXISTS audit_logs CASCADE;
DROP TABLE IF EXISTS crl_entries CASCADE;
DROP TABLE IF EXISTS certificates CASCADE;
DROP TABLE IF EXISTS tickets CASCADE;
DROP TABLE IF EXISTS envelope_keys CASCADE;
DROP TABLE IF EXISTS file_blobs CASCADE;
DROP TABLE IF EXISTS user_roles CASCADE;
DROP TABLE IF EXISTS files CASCADE;
DROP TABLE IF EXISTS roles CASCADE;
DROP TABLE IF EXISTS users CASCADE;

-- ==========================================
-- 1. BẢNG USERS ĐƯỢC CẬP NHẬT CẶP KHÓA RSA
-- ==========================================
CREATE TABLE users (
  user_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  username varchar(255) NOT NULL UNIQUE,
  password_hash text NOT NULL,
  public_key text,               -- [MỚI] Lưu khóa công khai (Dạng bản rõ, ai cũng xem được)
  encrypted_private_key text,    -- [MỚI] Lưu khóa bí mật (Đã bị mã hóa bằng Mật khẩu của user)
  status varchar(32) NOT NULL DEFAULT 'active',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE roles (
  role_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  role_name varchar(64) NOT NULL UNIQUE,
  description text
);

CREATE TABLE files (
  file_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id uuid NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
  version int NOT NULL DEFAULT 1,
  content_type varchar(128),
  size bigint,
  plaintext_hash char(64),
  ciphertext_hash char(64),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  status varchar(32) NOT NULL DEFAULT 'active'
);

CREATE TABLE user_roles (
  user_role_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  role_id uuid NOT NULL REFERENCES roles(role_id) ON DELETE CASCADE,
  file_id uuid REFERENCES files(file_id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE file_blobs (
  blob_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  file_id uuid NOT NULL REFERENCES files(file_id) ON DELETE CASCADE,
  storage_path text NOT NULL,
  nonce text,
  gcm_tag text,
  ciphertext_ref text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE envelope_keys (
  ek_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  file_id uuid NOT NULL REFERENCES files(file_id) ON DELETE CASCADE,
  recipient_id uuid NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  ek_ciphertext text NOT NULL,
  algo varchar(64) NOT NULL,
  status varchar(32) NOT NULL DEFAULT 'active',
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz
);

CREATE TABLE tickets (
  ticket_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  service_id varchar(128) NOT NULL,
  ticket_type varchar(16) NOT NULL,
  expires_at timestamptz NOT NULL,
  session_key_ref text,
  status varchar(32) NOT NULL DEFAULT 'active',
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE certificates (
  cert_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  subject varchar(255) NOT NULL,
  serial_number varchar(128) NOT NULL UNIQUE,
  fingerprint varchar(128),
  not_before timestamptz NOT NULL,
  not_after timestamptz NOT NULL,
  status varchar(32) NOT NULL DEFAULT 'active',
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz
);

CREATE TABLE crl_entries (
  crl_entry_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  serial_number varchar(128) NOT NULL,
  reason varchar(64),
  revoked_at timestamptz NOT NULL
);

CREATE TABLE audit_logs (
  event_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  timestamp timestamptz NOT NULL DEFAULT now(),
  event_type varchar(64) NOT NULL,
  actor_user_id uuid REFERENCES users(user_id) ON DELETE SET NULL,
  actor_role varchar(64),
  target_file_id uuid REFERENCES files(file_id) ON DELETE SET NULL,
  file_version int,
  recipient_user_id uuid REFERENCES users(user_id) ON DELETE SET NULL,
  client_ip varchar(64),
  user_agent text,
  cert_serial varchar(128),
  ticket_id_hash varchar(128),
  request_id uuid NOT NULL,
  result varchar(16) NOT NULL,
  error_code varchar(64)
);

CREATE TABLE ca_audit_logs (
  log_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  timestamp timestamptz NOT NULL DEFAULT now(),
  action varchar(64) NOT NULL, -- ISSUE_CERT, REVOKE_CERT, GENERATE_CRL
  details text,
  performed_by varchar(255)
);

CREATE INDEX idx_files_owner_id ON files(owner_id);
CREATE INDEX idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX idx_user_roles_file_id ON user_roles(file_id);
CREATE INDEX idx_file_blobs_file_id ON file_blobs(file_id);
CREATE INDEX idx_envelope_keys_file_id ON envelope_keys(file_id);
CREATE INDEX idx_envelope_keys_recipient_id ON envelope_keys(recipient_id);
CREATE INDEX idx_tickets_user_id ON tickets(user_id);
CREATE INDEX idx_certificates_serial ON certificates(serial_number);
CREATE INDEX idx_crl_entries_serial ON crl_entries(serial_number);
CREATE INDEX idx_audit_logs_request_id ON audit_logs(request_id);
CREATE INDEX idx_audit_logs_target_file_id ON audit_logs(target_file_id);
CREATE INDEX idx_ca_audit_logs_action ON ca_audit_logs(action);

COMMIT;