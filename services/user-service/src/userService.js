const { Pool } = require('pg');

const pool = new Pool({ connectionString: process.env.DB_URL });

async function createUser(username, passwordHash, publicKey, encryptedPrivateKey) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const userResult = await client.query(
      `INSERT INTO users (username, password_hash, public_key, encrypted_private_key, status)
       VALUES ($1, $2, $3, $4, 'active') RETURNING user_id`,
      [username, passwordHash, publicKey, encryptedPrivateKey]
    );
    const userId = userResult.rows[0].user_id;

    const roleResult = await client.query(`SELECT role_id FROM roles WHERE role_name = 'Viewer'`);
    if (roleResult.rows.length > 0) {
      const viewerRoleId = roleResult.rows[0].role_id;
      await client.query(
        `INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)`,
        [userId, viewerRoleId]
      );
    }

    await client.query('COMMIT');
    return userId;
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

module.exports = {
  createUser
};