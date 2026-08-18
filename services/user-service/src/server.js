require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const crypto = require('crypto');
const { createUser } = require('./userService');

const app = express();
app.use(helmet());
app.use(morgan('dev'));
app.use(express.json());
app.use(cors());

function hashPasswordForKdc(password) {
  const iterations = 120000;
  const salt = crypto.randomBytes(16).toString('hex');
  const derivedKey = crypto.pbkdf2Sync(password, salt, iterations, 32, 'sha256');
  const hashHex = derivedKey.toString('hex');
  return `pbkdf2:sha256:${iterations}:${salt}:${hashHex}`;
}

app.post('/api/v1/users/register', async (req, res) => {
  try {
    const { username, password, public_key, encrypted_private_key } = req.body;

    if (!username || !password || !public_key || !encrypted_private_key) {
      return res.status(400).json({ error: 'Thiếu thông tin đăng ký bắt buộc' });
    }

    const kdcCompatibleHash = hashPasswordForKdc(password);

    const newUserId = await createUser(username, kdcCompatibleHash, public_key, encrypted_private_key);

    return res.status(201).json({ 
      message: 'Đăng ký tài khoản và lưu trữ khóa thành công!',
      userId: newUserId 
    });

  } catch (err) {
    console.error('Lỗi đăng ký:', err);
    if (err.code === '23505') {
      return res.status(409).json({ error: 'Tên đăng nhập đã tồn tại' });
    }
    return res.status(500).json({ error: 'Lỗi máy chủ nội bộ' });
  }
});

app.post('/api/v1/users/public-keys', async (req, res) => {
  try {
    const { usernames } = req.body;
    if (!usernames || !Array.isArray(usernames) || usernames.length === 0) {
      return res.status(200).json({ keys: [] });
    }

    const { Pool } = require('pg');
    const pool = new Pool({ connectionString: process.env.DB_URL });

    const result = await pool.query(
      'SELECT user_id, public_key FROM users WHERE username = ANY($1) AND status = \'active\'',
      [usernames]
    );

    return res.status(200).json({ keys: result.rows });
  } catch (err) {
    console.error('Lỗi lấy Public Keys:', err);
    return res.status(500).json({ error: 'Không thể truy vấn danh sách khóa công khai' });
  }
});

const PORT = process.env.PORT || 4002;
app.listen(PORT, () => {
  console.log(`User Service đang chạy tại http://localhost:${PORT}`);
});