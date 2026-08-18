# Secure Storage System

Hệ thống lưu trữ dữ liệu an toàn dựa trên kiến trúc phân tán.

## Cấu trúc dự án

- **`/services/ca`**: Certificate Authority (Quản lý cấp phát chứng chỉ số)
- **`/services/kdc`**: Key Distribution Center (Trung tâm phân phối khóa bảo mật - Kerberos)
- **`/services/file-service`**: Dịch vụ quản lý, lưu trữ và mã hóa file
- **`/services/user-service`**: Dịch vụ quản lý người dùng và public keys
- **`/client`**: Ứng dụng Frontend (Giao diện người dùng)

## Yêu cầu hệ thống
- **Node.js** (Khuyến nghị bản v18 trở lên)
- **PostgreSQL** (Đang chạy local hoặc trên server)

### Cài đặt thư viện/công cụ ngoài (External Tools)
Hệ thống CA (Certificate Authority) của dự án cần sử dụng trực tiếp công cụ **OpenSSL** để tạo và cấp phát chứng chỉ số. Do đó, bạn **bắt buộc** phải cài đặt OpenSSL vào hệ điều hành:

- **Windows:** 
  1. Tải bản cài đặt [Win32/Win64 OpenSSL](https://slproweb.com/products/Win32OpenSSL.html) (bản Light là đủ).
  2. Cài đặt bình thường.
  3. **Rất quan trọng:** Thêm đường dẫn thư mục `bin` của OpenSSL (vd: `C:\Program Files\OpenSSL-Win64\bin`) vào biến môi trường **PATH** của Windows.
- **macOS:** Mở Terminal chạy lệnh `brew install openssl` (yêu cầu đã cài Homebrew).
- **Linux (Ubuntu/Debian):** Chạy lệnh `sudo apt-get install openssl`.

*(Cách kiểm tra cài đặt: Mở cửa sổ Terminal mới và gõ lệnh `openssl version`. Nếu hiện ra phiên bản là đã thành công).*

---

## Hướng dẫn cài đặt và chạy toàn bộ dự án

### 1. Chuẩn bị Cơ sở dữ liệu (Database)
1. Đảm bảo PostgreSQL đã được cài đặt và đang chạy.
2. Tạo các database bằng pgAdmin hoặc dòng lệnh:
   - Tạo DB tên `secure_storage` (Dành cho user-service, KDC và CA) là file database/migrations/001_init.sql
   - Tạo DB tên `file_server` (Dành cho file-service) là file là file database/migrations/001_in001_file_service_initit.sql

### 2. Thiết lập các file cấu hình (.env)
Đi vào từng thư mục dịch vụ và đổi tên/sao chép file `.env.example` thành `.env`. Mở file `.env` lên và điền đúng Username/Password của Database PostgreSQL của bạn.

- `services/ca/.env`
- `services/kdc/.env`
- `services/file-service/.env`
- `services/user-service/.env`

*(Lưu ý: Nếu Frontend `client` có yêu cầu `.env`, hãy làm tương tự).*

### 3. Cài đặt thư viện (Dependencies)
Cần chạy lệnh cài đặt npm cho **tất cả 5 thư mục** (gồm 4 dịch vụ và 1 client). Bạn có thể mở nhiều cửa sổ Terminal/Command Prompt để thực hiện:

```bash
# 1. Cài đặt CA
cd services/ca && npm install

# 2. Cài đặt KDC
cd ../kdc && npm install

# 3. Cài đặt User Service
cd ../user-service && npm install

# 4. Cài đặt File Service
cd ../file-service && npm install

# 5. Cài đặt Client (Frontend)
cd ../../client && npm install
```

---

### 4. Khởi động toàn bộ Hệ thống
Mở 5 cửa sổ terminal khác nhau (hoặc sử dụng các tính năng chia màn hình trong terminal/IDE) và khởi động lần lượt các dịch vụ theo thứ tự ưu tiên sau:

**Terminal 1 (CA Service):**
```bash
cd services/ca
npm run start
```
*(Note: Trong lần chạy đầu tiên, bạn có thể cần gọi API `POST http://localhost:7002/api/v1/ca/init` để khởi tạo hệ thống CA).*

**Terminal 2 (KDC Service):**
```bash
cd services/kdc
npm run start
```

**Terminal 3 (User Service):**
```bash
cd services/user-service
npm run start
```

**Terminal 4 (File Service):**
```bash
cd services/file-service
npm run start
```

**Terminal 5 (Client - Frontend):**
```bash
cd client
npm run dev
```

### 5. Truy cập Ứng dụng
Sau khi Frontend đã khởi chạy thành công, mở trình duyệt web và truy cập vào đường dẫn mà Vite/React cung cấp (thường là `http://localhost:5173` hoặc `http://localhost:3000`).

Bây giờ bạn đã có thể Đăng ký, Đăng nhập và bắt đầu sử dụng Hệ thống Secure Storage!
