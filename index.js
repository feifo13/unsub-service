import "dotenv/config";
import express from "express";
import crypto from "crypto";
import mysql from "mysql2/promise";

const app = express();

const PORT = Number(process.env.PORT || 4180);
const HOST = process.env.BIND_HOST || "127.0.0.1";

const UNSUB_SECRET = process.env.UNSUB_SECRET || "cambiame";

// Opciones:
// - TARGET_ONLY (default): suprime SOLO ese email en ficha_cliente_target_mail
// - CLIENT_PAUSE: pausa cliente (fc.send_mail=1) en base al email
// - BOTH: hace ambas
const UNSUB_MODE = (process.env.UNSUB_MODE || "TARGET_ONLY").toUpperCase();

// IMPORTANTE: para soportar POST "one-click" (application/x-www-form-urlencoded)
app.use(express.urlencoded({ extended: false }));

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
});

function escapeHtml(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function verifyToken(token, maxAgeSeconds = 60 * 60 * 24 * 180) {
  try {
    const raw = Buffer.from(String(token || ""), "base64url").toString("utf8");
    const [email, tsStr, sigHex] = raw.split("|");
    const ts = Number(tsStr);

    if (!email || !ts || !sigHex) return null;

    const age = Math.floor(Date.now() / 1000) - ts;
    if (age < 0 || age > maxAgeSeconds) return null;

    const data = `${email}|${ts}`;
    const expectedHex = crypto
      .createHmac("sha256", UNSUB_SECRET)
      .update(data)
      .digest("hex");

    // Comparación segura en bytes (hex -> bytes)
    const a = Buffer.from(sigHex, "hex");
    const b = Buffer.from(expectedHex, "hex");
    if (a.length !== b.length) return null;
    if (!crypto.timingSafeEqual(a, b)) return null;

    return email;
  } catch {
    return null;
  }
}

async function suppressTargetEmail(email) {
  // suprime SOLO ese email (recomendado)
  await pool.query(
    `
    UPDATE ficha_cliente_target_mail
    SET is_suppressed = 1,
        suppressed_reason = COALESCE(suppressed_reason, 'UNSUBSCRIBE'),
        suppressed_at = COALESCE(suppressed_at, NOW())
    WHERE LOWER(email) = LOWER(?)
    `,
    [email]
  );
}

async function pauseClientByEmail(email) {
  // send_mail = 0 => enviar | send_mail = 1 => NO enviar (pausado)
  await pool.query(
    `
    UPDATE ficha_cliente fc
    JOIN ficha_cliente_target_mail tm ON tm.cliente_id = fc.id
    SET fc.send_mail = 1
    WHERE LOWER(tm.email) = LOWER(?)
    `,
    [email]
  );
}

async function applyUnsub(email) {
  if (UNSUB_MODE === "TARGET_ONLY") {
    await suppressTargetEmail(email);
    return;
  }
  if (UNSUB_MODE === "CLIENT_PAUSE") {
    await pauseClientByEmail(email);
    return;
  }
  // BOTH
  await suppressTargetEmail(email);
  await pauseClientByEmail(email);
}

function sendHtml(res, status, html) {
  res.status(status);
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.setHeader("Cache-Control", "no-store, max-age=0");
  res.send(html);
}

function ok(res) {
  res.setHeader("Cache-Control", "no-store, max-age=0");
  return res.status(200).send("OK");
}

// Healthcheck simple
app.get("/health", (req, res) => res.json({ ok: true }));

async function handleUnsubPost(req, res) {
  // One-click: responder OK aunque el token sea inválido (evita ruido/reintentos)
  const email = verifyToken(req.query.token);
  if (!email) return ok(res);

  try {
    await applyUnsub(email);
    return ok(res);
  } catch {
    return res.status(500).send("Error");
  }
}

async function handleUnsubGet(req, res) {
  const email = verifyToken(req.query.token);

  if (!email) {
    return sendHtml(
      res,
      400,
      `
      <div style="font-family:Arial;max-width:720px;margin:40px auto;line-height:1.5">
        <h2>Enlace inválido</h2>
        <p>El enlace es inválido o venció.</p>
      </div>
    `
    );
  }

  try {
    await applyUnsub(email);

    return sendHtml(
      res,
      200,
      `
      <div style="font-family:Arial;max-width:720px;margin:40px auto;line-height:1.5">
        <h2>Listo</h2>
        <p>Dimos de baja los envíos para <strong>${escapeHtml(
          email
        )}</strong>.</p>
      </div>
    `
    );
  } catch {
    return res.status(500).send("Error interno.");
  }
}

// Rutas: mantenemos la actual y sumamos alias nuevo
app.post("/preferencias-email", handleUnsubPost);
app.get("/preferencias-email", handleUnsubGet);

app.post("/unsubscribe", handleUnsubPost);
app.get("/unsubscribe", handleUnsubGet);

app.listen(PORT, HOST, () => {
  console.log(`Unsub service listening on http://${HOST}:${PORT}`);
  console.log(`UNSUB_MODE=${UNSUB_MODE}`);
});
