const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const envPath = path.join(__dirname, '..', '.env');

// Sinh khóa ngẫu nhiên 32-byte và chuyển sang Hex
const generateKey = () => crypto.randomBytes(32).toString('hex');

const envContent = `
PORT=4000
DB_URL=postgresql://postgres:23120408@localhost:5432/secure_storage

# Keys generated automatically
KDC_TGS_KEY=${generateKey()}
KDC_SERVICE_KEY=${generateKey()}
`;

fs.writeFileSync(envPath, envContent.trim());
console.log('✅ Đã sửa lỗi và tạo file .env thành công tại thư mục kdc!');