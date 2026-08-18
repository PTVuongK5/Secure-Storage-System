
-- ==========================================
-- 2. ĐƯA DỮ LIỆU MẪU VÀO CÁC BẢNG (SEED DATA)
-- ==========================================
BEGIN;

INSERT INTO roles (role_id, role_name, description)
VALUES
  ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'Owner', 'Full control'),
  ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', 'Editor', 'Modify and share'),
  ('cccccccc-cccc-cccc-cccc-cccccccccccc', 'Viewer', 'Read only')
ON CONFLICT (role_name) DO NOTHING;

-- Dữ liệu User mẫu đã được thêm public_key và encrypted_private_key
INSERT INTO users (user_id, username, password_hash, public_key, encrypted_private_key, status)
VALUES
  (
    '11111111-1111-1111-1111-111111111111', 
    'alice', 
    'pbkdf2:sha256:120000:a1b2c3d4e5f6a7b8:9d3cd70efd6d5af5e0579f4d375265aaaadd466a5735d1630a1147b9fc5495c6', 
    '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...[Alice_PublicKey_Mock]...\n-----END PUBLIC KEY-----', 
    'U2FsdGVkX19OzaB7m2w3qR...[Alice_PrivateKey_WrappedByPassword_Mock]...', 
    'active'
  ),
  (
    '22222222-2222-2222-2222-222222222222', 
    'bob', 
    'pbkdf2:sha256:120000:1a2b3c4d5e6f7a8b:25241ce7552fee7db96ea241d14c9bd5eabbefcbbdb7cdf84ccf1746dd9939d0',
    '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...[Bob_PublicKey_Mock]...\n-----END PUBLIC KEY-----', 
    'U2FsdGVkX18Kx9pZ4Lm1bQ...[Bob_PrivateKey_WrappedByPassword_Mock]...', 
    'active'
  )
ON CONFLICT (username) DO NOTHING;

INSERT INTO user_roles (user_role_id, user_id, role_id, created_at)
VALUES
  (gen_random_uuid(), '11111111-1111-1111-1111-111111111111', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', now()),
  (gen_random_uuid(), '22222222-2222-2222-2222-222222222222', 'cccccccc-cccc-cccc-cccc-cccccccccccc', now());

COMMIT;