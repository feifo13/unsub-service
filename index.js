import "dotenv/config";
import express from "express";
import crypto from "crypto";
import mysql from "mysql2/promise";

const app = express();
const PORT = Number(process.env.PORT || 4180);
const UNSUB_SECRET = process.env.UNSUB_SECRET || "cambiame";
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
    const raw = Buffer.from(String(token), "base64url").toString("utf8");
    const [email, tsStr, sig] = raw.split("|");
    const ts = Number(tsStr);
    if (!email || !ts || !sig) return null;

    const age = Math.floor(Date.now() / 1000) - ts;
    if (age < 0 || age > maxAgeSeconds) return null;

    const data = `${email}|${ts}`;
    const expected = crypto.createHmac("sha256", UNSUB_SECRET).update(data).digest("hex");
    if (sig.length !== expected.length) return null;
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;

    return email;
  } catch {
    return null;
  }
}

async function pauseByEmail(email) {
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

app.post("/preferencias-email", async (req, res) => {
  // One-click: responder OK aunque el token sea inválido (evita ruido/reintentos)
  const email = verifyToken(req.query.token);
  if (!email) return res.status(200).send("OK");

  try {
    await pauseByEmail(email);
    return res.status(200).send("OK");
  } catch {
    return res.status(500).send("Error");
  }
});

app.get("/preferencias-email", async (req, res) => {
  res.setHeader("Content-Type", "text/html; charset=utf-8");

  const email = verifyToken(req.query.token);
  if (!email) {
    return res.status(400).send(`
      <div style="font-family:Arial;max-width:720px;margin:40px auto;line-height:1.5">
        <h2>Enlace inválido</h2>
        <p>El enlace es inválido o venció.</p>
      </div>
    `);
  }

  try {
    await pauseByEmail(email);

    return res.status(200).send(`
      <div style="font-family:Arial;max-width:720px;margin:40px auto;line-height:1.5">
        <h2>Listo</h2>
        <p>Pausamos los envíos para <strong>${escapeHtml(email)}</strong>.</p>
      </div>
    `);
  } catch {
    return res.status(500).send("Error interno.");
  }
});


app.listen(PORT, "127.0.0.1", () => {
  console.log(`Unsub service: http://127.0.0.1:${PORT}`);
});
