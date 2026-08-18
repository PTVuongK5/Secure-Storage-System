## API
Base path: /api/v1/ca

### POST /api/v1/ca/init
Khởi tạo CA root nếu chưa có. Lệnh này idempotent.

Response 200:
```json
{
  "data": {
    "keyPath": "services/ca/ca/private/ca.key.pem",
    "certPath": "services/ca/ca/ca.cert.pem"
  }
}
```

Lỗi thường gặp:
- 500 nếu OpenSSL không chạy được hoặc cấu hình lỗi.

### POST /api/v1/ca/issue
Cấp chứng chỉ server hoặc client.

Request body:
```json
{
  "type": "server",
  "commonName": "file-service",
  "altNames": ["DNS:file-service", "DNS:localhost", "IP:127.0.0.1"],
  "includePem": true,
  "days": 365
}
```

Giải thích:
- type: server | client
- commonName: chỉ cho phép chữ, số, dấu chấm, gạch dưới, gạch ngang
- altNames: danh sách subjectAltName theo định dạng OpenSSL
- includePem: nếu true sẽ trả cả cert/key PEM trong response
- days: số ngày hiệu lực (mặc định theo CERT_DAYS)

Response 200:
```json
{
  "data": {
    "commonName": "file-service",
    "type": "server",
    "certPath": "services/ca/ca/certs/file-service.cert.pem",
    "keyPath": "services/ca/ca/private/file-service.key.pem",
    "csrPath": "services/ca/ca/csr/file-service.csr.pem",
    "certPem": "-----BEGIN CERTIFICATE-----...",
    "keyPem": "-----BEGIN PRIVATE KEY-----..."
  }
}
```

Lỗi thường gặp:
- 400 nếu commonName/altNames không hợp lệ
- 400 nếu cert đã tồn tại
- 500 nếu CA chưa init hoặc OpenSSL lỗi

### POST /api/v1/ca/revoke
Thu hồi cert theo commonName hoặc certPath và cập nhật CRL.

Request body (theo commonName):
```json
{ "commonName": "file-service", "reason": "keyCompromise" }
```

Request body (theo certPath):
```json
{ "certPath": "services/ca/ca/certs/file-service.cert.pem", "reason": "keyCompromise" }
```

Response 200:
```json
{ "data": { "crlPath": "services/ca/ca/crl/ca.crl.pem" } }
```

Lỗi thường gặp:
- 400 nếu cert không tồn tại hoặc reason không hợp lệ
- 500 nếu CA chưa init hoặc OpenSSL lỗi

### POST /api/v1/ca/crl
Sinh CRL mới.

Response 200:
```json
{ "data": { "crlPath": "services/ca/ca/crl/ca.crl.pem" } }
```

### GET /api/v1/ca/ca-cert
Trả CA root cert (PEM).

### GET /api/v1/ca/cert/:commonName
Trả cert theo common name (PEM).

### GET /api/v1/ca/crl
Trả CRL (PEM) và tự động sinh mới trước khi trả.

### GET /health
Health check.
}
```

POST /api/v1/ca/revoke
```json
{ "commonName": "file-service", "reason": "keyCompromise" }
```

POST /api/v1/ca/crl
- Sinh CRL mới.

GET /api/v1/ca/ca-cert
- Lấy CA root cert.

GET /api/v1/ca/cert/:commonName
- Lấy cert theo common name.

GET /api/v1/ca/crl
- Lấy CRL (tự động sinh mới).

GET /
- Health check.

## Biến môi trường
- PORT: cổng HTTP (mặc định 7002)
- OPENSSL_BIN: đường dẫn/binary OpenSSL (mặc định openssl)
- OPENSSL_CONFIG: đường dẫn openssl.cnf
- CA_DIR: thư mục lưu dữ liệu CA
- CA_SUBJECT: subject cho CA root
- CA_KEY_BITS: số bit RSA (mặc định 4096)
- CA_DAYS: số ngày hiệu lực CA (mặc định 3650)
- CERT_DAYS: số ngày hiệu lực cert (mặc định 365)
- CERT_SUBJECT_PREFIX: prefix cho subject cert

## Output mặc định (CA_DIR)
- ca.cert.pem (CA root cert)
- private/ca.key.pem (CA private key)
- certs/<cn>.cert.pem (issued cert)
- private/<cn>.key.pem (issued key)
- crl/ca.crl.pem (CRL)

## Ghi chú
- Cần gọi /api/v1/ca/init trước khi issue/revoke.
- altNames theo định dạng subjectAltName của OpenSSL (DNS:<name>, IP:<addr>).
- includePem=true sẽ trả PEM trong response.
- Không overwrite key/cert đã tồn tại.
- CA server chưa có auth, chỉ dùng nội bộ/local.
