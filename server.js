// Drop-in key check (Node 18+). Put SERVER_URL as your deployed server's URL.
const fs = require("fs");
const os = require("os");
const crypto = require("crypto");
const readline = require("readline");

const SERVER_URL = "https://kefyf.onrender.com"; // <-- change this
const KEY_FILE = "./key.txt";

function getHwid() {
  const raw = [os.hostname(), os.platform(), os.arch(), os.cpus()[0]?.model,
    Object.values(os.networkInterfaces()).flat().find((n) => !n.internal && n.mac !== "00:00:00:00:00:00")?.mac,
  ].join("|");
  return crypto.createHash("sha256").update(raw).digest("hex");
}

function ask(q) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((r) => rl.question(q, (a) => { rl.close(); r(a.trim()); }));
}

async function checkKey(key) {
  const res = await fetch(SERVER_URL + "/validate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ key, hwid: getHwid() }),
  });
  return res.json();
}

async function requireLicense() {
  let key = fs.existsSync(KEY_FILE) ? fs.readFileSync(KEY_FILE, "utf8").trim() : "";
  if (!key) key = await ask("Enter your key: ");

  let result;
  try { result = await checkKey(key); }
  catch { console.error("Can't reach license server."); process.exit(1); }

  if (!result.ok) {
    console.error("License check failed: " + result.reason);
    if (fs.existsSync(KEY_FILE)) fs.unlinkSync(KEY_FILE);
    process.exit(1);
  }
  fs.writeFileSync(KEY_FILE, key); // remember it for next launch
  console.log("License OK" + (result.expiresAt ? " (expires " + new Date(result.expiresAt).toLocaleDateString() + ")" : " (lifetime)"));
}

(async () => {
  await requireLicense();
  // ---- your program starts here ----
  console.log("Running...");
})();
