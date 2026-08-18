const express = require("express");
const fs = require("fs");
const path = require("path");
const rateLimit = require("express-rate-limit");
const dotenv = require("dotenv");

dotenv.config();

const {
  getConfig,
  initCa,
  issueCert,
  revokeCert,
  genCrl,
  readPem,
  getCaCertPath,
  certPaths,
  getCertInfo
} = require("./openssl");

const { Pool } = require("pg");

const pool = new Pool({
  connectionString: process.env.DB_URL || process.env.DATABASE_URL
});

const app = express();
app.use(express.json({ limit: "2mb" }));

const config = getConfig();

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS certificates (
      id SERIAL PRIMARY KEY,
      subject TEXT NOT NULL,
      serial_number TEXT NOT NULL UNIQUE,
      fingerprint TEXT,
      not_before TIMESTAMP WITH TIME ZONE,
      not_after TIMESTAMP WITH TIME ZONE,
      status TEXT NOT NULL DEFAULT 'active',
      revoked_at TIMESTAMP WITH TIME ZONE,
      created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS crl_entries (
      id SERIAL PRIMARY KEY,
      serial_number TEXT NOT NULL,
      reason TEXT NOT NULL,
      revoked_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
      created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS ca_audit_logs (
      id SERIAL PRIMARY KEY,
      action TEXT NOT NULL,
      details JSONB,
      performed_by TEXT,
      created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    );
  `);
  console.log("CA database tables are ready");
}

app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "http://localhost:5173");
  res.header(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization, x-api-key"
  );
  res.header(
    "Access-Control-Allow-Methods",
    "GET, POST, PUT, DELETE, OPTIONS"
  );

  if (req.method === "OPTIONS") {
    return res.sendStatus(200);
  }

  next();
});
const issueLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: { error: { message: "Too many requests, please try again later." } }
});

function requireApiKey(req, res, next) {
  const apiKey = req.headers["x-api-key"];
  if (!apiKey || apiKey !== process.env.CA_API_KEY) {
    return res.status(401).json({ error: { message: "Unauthorized" } });
  }
  next();
}


function sendError(res, status, message, internalError = null) {
  if (internalError) {
    console.error(`[ERROR] ${message}:`, internalError.message || internalError);
  }
  return res.status(status).json({
    error: {
      message: "Internal CA Error or Invalid Request"
    }
  });
}

async function auditLog(action, details, performedBy = "system") {
  try {
    await pool.query(
      `INSERT INTO ca_audit_logs (action, details, performed_by)
       VALUES ($1, $2, $3)`,
      [action, JSON.stringify(details), performedBy]
    );
  } catch (err) {
    console.error("Failed to write audit log:", err.message);
  }
}

app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

app.post("/api/v1/certs/issue", requireApiKey, issueLimiter, async (req, res) => {
  try {
    const result = issueCert(config, req.body);
    const certInfo = getCertInfo(config, result.certPath);
    const certPem = readPem(result.certPath);
    await pool.query(
      `INSERT INTO certificates
        (subject, serial_number, fingerprint, not_before, not_after, status)
       VALUES ($1, $2, $3, $4, $5, 'active')
       ON CONFLICT (serial_number) DO UPDATE SET
        subject = EXCLUDED.subject,
        fingerprint = EXCLUDED.fingerprint,
        not_before = EXCLUDED.not_before,
        not_after = EXCLUDED.not_after,
        status = 'active',
        revoked_at = NULL`,
      [
        req.body.commonName,
        certInfo.serial_number,
        certInfo.fingerprint,
        certInfo.not_before,
        certInfo.not_after
      ]
    );

    await auditLog("ISSUE_CERT", {
      commonName: req.body.commonName,
      type: req.body.type,
      serial: certInfo.serial_number
    }, req.body.commonName);

    res.json({
      data: result,
      certificate: certPem
    });
  } catch (err) {
    sendError(res, 400, "Issue cert failed", err);
  }
});

/* =========================
   REVOKE
========================= */
app.post("/api/v1/certs/revoke", requireApiKey, async (req, res) => {
  try {
    const paths = certPaths(config, req.body.commonName);
    let serial_number = "UNKNOWN";

    if (fs.existsSync(paths.certPath)) {
      const certInfo = getCertInfo(config, paths.certPath);
      serial_number = certInfo.serial_number;
    }

    const result = revokeCert(config, req.body);
    const revokedAt = new Date();

    if (serial_number !== "UNKNOWN") {
      await pool.query(
        `UPDATE certificates
         SET status = 'revoked', revoked_at = $2
         WHERE serial_number = $1`,
        [serial_number, revokedAt]
      );

      await pool.query(
        `INSERT INTO crl_entries (serial_number, reason, revoked_at)
         VALUES ($1, $2, $3)`,
        [serial_number, req.body.reason || "keyCompromise", revokedAt]
      );
    }

    await auditLog("REVOKE_CERT", req.body, req.body.commonName);

    res.json({ data: result });
  } catch (err) {
    sendError(res, 400, "Revoke cert failed", err);
  }
});

/* =========================
   GENERATE CRL
========================= */
app.post("/api/v1/certs/crl", requireApiKey, async (req, res) => {
  try {
    const result = genCrl(config);
    await auditLog("GENERATE_CRL", {});
    res.json({ data: result });
  } catch (err) {
    sendError(res, 500, "Gen CRL failed", err);
  }
});

/* =========================
   DOWNLOAD CA CERT
========================= */
app.get("/api/v1/ca/cert", (req, res) => {
  try {
    const certPath = getCaCertPath(config);
    res.download(certPath);
  } catch (err) {
    sendError(res, 500, "Download CA failed", err);
  }
});

/* =========================
   DOWNLOAD CERT
========================= */
app.get("/api/v1/certs/:commonName", requireApiKey, (req, res) => {
  try {
    const paths = certPaths(config, req.params.commonName);
    if (!fs.existsSync(paths.certPath)) {
      return res.status(404).json({ error: { message: "Certificate not found" } });
    }
    res.download(paths.certPath);
  } catch (err) {
    sendError(res, 400, "Download Cert failed", err);
  }
});

/* =========================
   DOWNLOAD CRL
========================= */
app.get("/api/v1/certs/crl/download", (req, res) => {
  try {
    const result = genCrl(config);
    res.download(result.crlPath);
  } catch (err) {
    sendError(res, 500, "Download CRL failed", err);
  }
});

const port = Number(process.env.PORT || 7002);

try {
  initCa(config);
  console.log("CA ready");
} catch (err) {
  console.error("Failed to init CA:", err.message);
  process.exit(1);
}

initDb()
  .then(() => {
    app.listen(port, () => {
      console.log(`CA Service running on port ${port}`);
    });
  })
  .catch(err => {
    console.error("Failed to init CA database:", err.message);
    process.exit(1);
  });
