// Simple license key server.
// Run:  ADMIN_SECRET=your-long-secret node server.js
const express = require("express");
const crypto = require("crypto");
const fs = require("fs");

const PORT = process.env.PORT || 3000;
const ADMIN_SECRET = process.env.ADMIN_SECRET;
const DB_FILE = process.env.DB_FILE || "./keys.json";

// Links are kept in a Render environment variable (LINKS_JSON), NOT in this file,
// so they never appear on GitHub. Example value:
// [{"name":"YouTube","url":"https://youtube.com"},{"name":"Claude","url":"https://claude.ai/new"}]
let LINKS = [];
try { LINKS = JSON.parse(process.env.LINKS_JSON || "[]"); }
catch (e) { console.error("LINKS_JSON is not valid JSON"); }

if (!ADMIN_SECRET) {
  console.error("Set ADMIN_SECRET env var first.");
  process.exit(1);
}

const app = express();
app.use(express.json());

// Allow web pages (any site) to call /validate from the browser
app.use((req, res, next) => {
  res.set("Access-Control-Allow-Origin", "*");
  res.set("Access-Control-Allow-Headers", "Content-Type, x-admin-secret");
  res.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

// ---- tiny JSON "database" ----
let db = fs.existsSync(DB_FILE) ? JSON.parse(fs.readFileSync(DB_FILE, "utf8")) : {};
const save = () => fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));

// ---- basic rate limit (per IP, 30 req/min) ----
const hits = new Map();
app.use((req, res, next) => {
  const now = Date.now();
  const arr = (hits.get(req.ip) || []).filter((t) => now - t < 60000);
  arr.push(now);
  hits.set(req.ip, arr);
  if (arr.length > 30) return res.status(429).json({ ok: false, reason: "rate_limited" });
  next();
});

const isAdmin = (req) => {
  const a = Buffer.from(req.get("x-admin-secret") || "");
  const b = Buffer.from(ADMIN_SECRET);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
};

// ---- ADMIN: create keys ----
// POST /admin/create  { "days": 30, "count": 5, "maxDevices": 1 }
app.post("/admin/create", (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false });
  const { days = 30, count = 1, maxDevices = 1 } = req.body || {};
  const out = [];
  for (let i = 0; i < Math.min(count, 100); i++) {
    const key = crypto.randomBytes(12).toString("hex").toUpperCase().match(/.{1,6}/g).join("-");
    db[key] = {
      createdAt: Date.now(),
      expiresAt: days > 0 ? Date.now() + days * 86400000 : null, // days=0 -> lifetime
      maxDevices,
      devices: [],
      revoked: false,
    };
    out.push(key);
  }
  save();
  res.json({ ok: true, keys: out });
});

// ---- ADMIN: revoke / reset devices / list ----
app.post("/admin/revoke", (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false });
  const k = db[req.body.key];
  if (!k) return res.status(404).json({ ok: false, reason: "not_found" });
  k.revoked = true;
  save();
  res.json({ ok: true });
});

app.post("/admin/reset", (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false });
  const k = db[req.body.key];
  if (!k) return res.status(404).json({ ok: false, reason: "not_found" });
  k.devices = [];
  save();
  res.json({ ok: true });
});

app.get("/admin/list", (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ ok: false });
  res.json({ ok: true, keys: db });
});

// ---- PUBLIC: validate ----
// POST /validate  { "key": "...", "hwid": "..." }
app.post("/validate", (req, res) => {
  const { key, hwid } = req.body || {};
  if (typeof key !== "string" || typeof hwid !== "string" || !hwid)
    return res.json({ ok: false, reason: "bad_request" });

  const k = db[key.trim().toUpperCase()];
  if (!k) return res.json({ ok: false, reason: "invalid_key" });
  if (k.revoked) return res.json({ ok: false, reason: "revoked" });
  if (k.expiresAt && Date.now() > k.expiresAt) return res.json({ ok: false, reason: "expired" });

  if (!k.devices.includes(hwid)) {
    if (k.devices.length >= k.maxDevices) return res.json({ ok: false, reason: "device_limit" });
    k.devices.push(hwid); // first use binds the key to this device
    save();
  }
  res.json({ ok: true, expiresAt: k.expiresAt, links: LINKS });
});

app.listen(PORT, () => console.log("Key server on :" + PORT));
