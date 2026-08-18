const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const COMMON_NAME_REGEX = /^[A-Za-z0-9._-]+$/;
const VALID_CRL_REASONS = new Set([
  "unspecified",
  "keyCompromise",
  "CACompromise",
  "affiliationChanged",
  "superseded",
  "cessationOfOperation",
  "certificateHold",
  "removeFromCRL",
  "privilegeWithdrawn",
  "AACompromise"
]);

function resolvePath(value, fallback) {
  if (!value) {
    return fallback;
  }
  return path.resolve(value);
}

function validateCsr(config, csrPath) {
  runOpenSSL(config, [
    "req",
    "-in",
    csrPath,
    "-noout",
    "-verify"
  ]);
}

function getCsrSubject(config, csrPath) {
  return runOpenSSL(config, [
    "req",
    "-in",
    csrPath,
    "-noout",
    "-subject"
  ]);
}

function getConfig() {
  const root = path.resolve(__dirname, "..");
  const caDir = resolvePath(process.env.CA_DIR, path.join(root, process.env.CA_DIR|| "authority"));
  const opensslConfig = resolvePath(
    process.env.OPENSSL_CONFIG,
    path.join(root, "openssl.cnf")
  );
  const opensslBin = process.env.OPENSSL_BIN || "openssl";
  const keyBits = Number(process.env.CA_KEY_BITS || "4096");
  const caDays = Number(process.env.CA_DAYS || "3650");
  const certDays = Number(process.env.CERT_DAYS || "365");
  const subject =
    process.env.CA_SUBJECT ||
    "/C=VN/O=SecureStorage/OU=Dev/CN=SecureStorage Root CA";

  return {
    root,
    caDir,
    opensslConfig,
    opensslBin,
    keyBits,
    caDays,
    certDays,
    subject
  };
}

function runOpenSSL(config, args) {
  const result = spawnSync(config.opensslBin, args, {
    encoding: "utf8",
    cwd: config.root
  });

  if (result.error) {
    throw result.error;
  }

  if (result.status !== 0) {
    const detail = (result.stderr || result.stdout || "").trim();
    const message = detail ? `OpenSSL error: ${detail}` : "OpenSSL failed";
    throw new Error(message);
  }

  return (result.stdout || "").trim();
}

function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

function ensureFile(filePath, content) {
  if (!fs.existsSync(filePath)) {
    fs.writeFileSync(filePath, content, "utf8");
  }
}

function ensureCaStructure(config) {
  const dirs = [
    config.caDir,
    path.join(config.caDir, "private"),
    path.join(config.caDir, "certs"),
    path.join(config.caDir, "newcerts"),
    path.join(config.caDir, "crl"),
    path.join(config.caDir, "csr")
  ];

  dirs.forEach(ensureDir);

  ensureFile(path.join(config.caDir, "index.txt"), "");
  ensureFile(path.join(config.caDir, "serial"), "1000");
  ensureFile(path.join(config.caDir, "crlnumber"), "1000");
}

/* ---------------------------------------------------------
   KHỞI TẠO CA (CA vẫn phải tự giữ Private Key của chính nó)
--------------------------------------------------------- */
function initCa(config) {
  ensureCaStructure(config);

  const keyPath = path.join(config.caDir, "private", "ca.key.pem");
  const certPath = path.join(config.caDir, "ca.cert.pem");

  if (!fs.existsSync(keyPath)) {
    runOpenSSL(config, [
      "genpkey",
      "-algorithm",
      "RSA",
      "-pkeyopt",
      `rsa_keygen_bits:${config.keyBits}`,
      "-out",
      keyPath
    ]);
  }

  if (!fs.existsSync(certPath)) {
    runOpenSSL(config, [
      "req",
      "-new",
      "-x509",
      "-days",
      String(config.caDays),
      "-sha256",
      "-key",
      keyPath,
      "-out",
      certPath,
      "-subj",
      config.subject,
      "-config",
      config.opensslConfig
    ]);
  }

  return { keyPath, certPath };
}

function assertCommonName(commonName) {
  if (!commonName || !COMMON_NAME_REGEX.test(commonName)) {
    throw new Error("commonName is missing or contains invalid characters");
  }
}

/* ---------------------------------------------------------
   ĐƯỜNG DẪN LƯU TRỮ (Không còn lưu key của client nữa)
--------------------------------------------------------- */
function certPaths(config, commonName) {
  return {
    csrPath: path.join(
      config.caDir,
      "csr",
      `${commonName}.csr.pem`
    ),

    certPath: path.join(
      config.caDir,
      "certs",
      `${commonName}.cert.pem`
    )
  };
}

function ensureCaReady(config) {
  const keyPath = path.join(config.caDir, "private", "ca.key.pem");
  const certPath = path.join(config.caDir, "ca.cert.pem");

  if (!fs.existsSync(keyPath) || !fs.existsSync(certPath)) {
    throw new Error("CA is not initialized. Call /api/v1/ca/init first.");
  }
}

/* ---------------------------------------------------------
   KÝ CHỨNG CHỈ TỪ CSR CỦA CLIENT (CẬP NHẬT CHÍNH)
--------------------------------------------------------- */
function issueCert(config, options) {
  const {
    commonName,
    csr,
    type
  } = options;

  const days =
    Number(options.days) || config.certDays;

  if (!commonName) {
    throw new Error("commonName required");
  }

  if (!csr) {
    throw new Error("csr required");
  }

  if (
    type !== "server" &&
    type !== "client"
  ) {
    throw new Error(
      "type must be server or client"
    );
  }

  assertCommonName(commonName);

  ensureCaStructure(config);
  ensureCaReady(config);

  const { csrPath, certPath } =
    certPaths(config, commonName);

  if (fs.existsSync(certPath)) {
    throw new Error(
      "certificate already exists"
    );
  }

  fs.writeFileSync(csrPath, csr, "utf8");

  validateCsr(config, csrPath);

  const subject = getCsrSubject(
    config,
    csrPath
  );

  const match =
  subject.match(/CN\s*=\s*([^,\n\/]+)/);

  if (!match) {
    throw new Error(
      "Cannot extract CN from CSR"
    );
  }

  const csrCN = match[1].trim();

  if (csrCN !== commonName) {
    throw new Error(
      "CSR commonName does not match request commonName"
    );
  }

  runOpenSSL(config, [
    "ca",
    "-config",
    config.opensslConfig,
    "-extensions",
    type === "server"
      ? "server_cert"
      : "client_cert",
    "-days",
    String(days),
    "-notext",
    "-md",
    "sha256",
    "-in",
    csrPath,
    "-out",
    certPath,
    "-batch"
  ]);

  return {
    commonName,
    type,
    certPath,
    csrPath
  };
}

/* ---------------------------------------------------------
   LẤY THÔNG TIN CHỨNG CHỈ
--------------------------------------------------------- */
function getCertInfo(config, certPath) {
  const output = runOpenSSL(config, [
    "x509",
    "-in",
    certPath,
    "-noout",
    "-serial",
    "-dates",
    "-fingerprint",
    "-sha256"
  ]);


  const lines = output.split("\n");
  let serial_number = "";
  let not_before = new Date();
  let not_after = new Date();
  let fingerprint = "";

  lines.forEach(line => {
    if (line.startsWith("serial=")) {
      serial_number = line.split("=")[1].trim();
    } else if (line.startsWith("notBefore=")) {
      not_before = new Date(line.split("=")[1].trim());
    } else if (line.startsWith("notAfter=")) {
      not_after = new Date(line.split("=")[1].trim());
    } else if (line.includes("Fingerprint=")) {
      fingerprint = line.split("=")[1].trim();
    }
  });

  return {
    serial_number,
    not_before,
    not_after,
    fingerprint
  };
}

/* ---------------------------------------------------------
   THU HỒI CHỨNG CHỈ
--------------------------------------------------------- */
function revokeCert(config, options) {
  const reason =
    options.reason ||
    "keyCompromise";

  if (!VALID_CRL_REASONS.has(reason)) {
    throw new Error(
      "invalid CRL reason"
    );
  }

  let certPath = options.certPath;

  if (
    !certPath &&
    options.commonName
  ) {
    certPath = certPaths(
      config,
      options.commonName
    ).certPath;
  }

  if (!certPath) {
    throw new Error(
      "certPath or commonName required"
    );
  }

  if (!fs.existsSync(certPath)) {
    throw new Error(
      "certificate not found"
    );
  }

  runOpenSSL(config, [
    "ca",
    "-config",
    config.opensslConfig,
    "-revoke",
    certPath,
    "-crl_reason",
    reason
  ]);

  return genCrl(config);
}

/* ---------------------------------------------------------
   TẠO FILE CRL
--------------------------------------------------------- */
function genCrl(config) {
  ensureCaStructure(config);
  ensureCaReady(config);

  const crlPath = path.join(config.caDir, "crl", "ca.crl.pem");

  runOpenSSL(config, [
    "ca",
    "-config",
    config.opensslConfig,
    "-gencrl",
    "-out",
    crlPath
  ]);

  return { crlPath };
}

function readPem(filePath) {
  return fs.readFileSync(filePath, "utf8");
}

function getCaCertPath(config) {
  return path.join(config.caDir, "ca.cert.pem");
}

module.exports = {
  getConfig,
  initCa,
  issueCert,
  revokeCert,
  genCrl,
  readPem,
  getCaCertPath,
  certPaths,
  getCertInfo
};