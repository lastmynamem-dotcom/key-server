// ============================================================
//  KEY SERVER — deploy on Railway (railway.app)
//
//  SETUP (takes ~2 min):
//  1. Go to railway.app → New Project → Deploy from GitHub repo
//     OR: New Project → Empty Project → Add Service → GitHub Repo
//     Upload this file as server.js in a repo, also add package.json
//  2. Railway gives you a public URL like:
//     https://yourapp.up.railway.app
//  3. Set one environment variable in Railway:
//     API_SECRET = anything you want (e.g. ks_fire99)
//  4. Put that URL + secret in destination.html and KeySystem.lua
// ============================================================

const http  = require("http");
const PORT  = process.env.PORT || 3000;
const SECRET = process.env.API_SECRET || "changeme";

// In-memory store — keys live here until they expire
// (Railway restarts wipe this, but keys only last 1 min so that's fine)
const keys = new Map();

// Auto-clean expired keys every 30s
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of keys) {
    if (now > v.expires_at) keys.delete(k);
  }
}, 30000);

function send(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    "Content-Type":                "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods":"GET, POST, OPTIONS",
    "Access-Control-Allow-Headers":"Content-Type",
  });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let raw = "";
    req.on("data", chunk => raw += chunk);
    req.on("end", () => {
      try { resolve(JSON.parse(raw)); }
      catch { reject(new Error("bad json")); }
    });
    req.on("error", reject);
  });
}

const server = http.createServer(async (req, res) => {
  // CORS preflight
  if (req.method === "OPTIONS") {
    res.writeHead(204, {
      "Access-Control-Allow-Origin":  "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    });
    return res.end();
  }

  const url = req.url.split("?")[0];

  // ── GET /ping ───────────────────────────────────────────────
  if (url === "/ping" && req.method === "GET") {
    return send(res, 200, { ok: true, ts: Date.now(), keys: keys.size });
  }

  // ── POST /register ──────────────────────────────────────────
  // Called by destination.html when a key is generated
  // Body: { key, expires_at, secret, token }
  // token = the ?hash= value from work.ink redirect — verified here
  if (url === "/register" && req.method === "POST") {
    let body;
    try { body = await readBody(req); }
    catch { return send(res, 400, { error: "bad json" }); }

    if (body.secret !== SECRET) return send(res, 401, { error: "unauthorized" });

    // ── Verify work.ink token ──────────────────────────────────
    const hash = body.token;

    // Admin bypass — skip work.ink check for lifetime key generation
    if (hash === "admin_bypass") {
      console.log("[register] admin bypass — skipping work.ink check");
    } else {
      if (!hash || hash === "{TOKEN}" || hash.trim() === "") {
        console.log("[register] blocked — no work.ink token");
        return send(res, 403, { error: "no_token", message: "Complete the work.ink checkpoint first." });
      }

    try {
      const checkRes = await fetch(`https://work.ink/_api/v2/token/isValid/${encodeURIComponent(hash)}?deleteToken=1`);
      const checkData = await checkRes.json();
      if (!checkData.valid) {
        console.log(`[register] blocked — invalid/used token: ${hash}`);
        return send(res, 403, { error: "invalid_token", message: "Invalid or already used work.ink token." });
      }
      console.log(`[register] work.ink token valid: ${hash}`);
    } catch(e) {
      console.error("[register] work.ink API error:", e.message);
      return send(res, 503, { error: "verification_unavailable" });
    }
    } // end else (admin_bypass check)

    const expiresAt = new Date(body.expires_at).getTime();
    if (isNaN(expiresAt)) return send(res, 400, { error: "invalid expires_at" });

    keys.set(body.key, {
      key:        body.key,
      expires_at: expiresAt,
      hwid:       null,
      created_at: Date.now(),
    });

    console.log(`[register] key=${body.key} expires=${body.expires_at}`);
    return send(res, 200, { ok: true });
  }

  // ── POST /validate ──────────────────────────────────────────
  // Called by the Lua script
  // Body: { key, hwid }
  if (url === "/validate" && req.method === "POST") {
    let body;
    try { body = await readBody(req); }
    catch { return send(res, 400, { error: "bad json" }); }

    const { key, hwid } = body;
    if (!key || !hwid) return send(res, 400, { valid: false, reason: "missing_fields" });

    const record = keys.get(key);

    if (!record) {
      console.log(`[validate] not_found key=${key}`);
      return send(res, 200, { valid: false, reason: "not_found" });
    }

    // Expired? (lifetime keys have expires_at = year 9999, skip check)
    const isLifetime = record.expires_at > 253370764800000; // year 9999 in ms
    if (!isLifetime && Date.now() > record.expires_at) {
      keys.delete(key);
      console.log(`[validate] expired key=${key}`);
      return send(res, 200, { valid: false, reason: "expired" });
    }

    // First use — bind HWID
    if (!record.hwid) {
      record.hwid = hwid;
      console.log(`[validate] bound key=${key} hwid=${hwid}`);
      return send(res, 200, { valid: true, reason: "bound" });
    }

    // Wrong device
    if (record.hwid !== hwid) {
      console.log(`[validate] wrong_hwid key=${key}`);
      return send(res, 200, { valid: false, reason: "wrong_hwid" });
    }

    console.log(`[validate] ok key=${key}`);
    return send(res, 200, { valid: true, reason: "ok" });
  }

  return send(res, 404, { error: "not found" });
});

server.listen(PORT, () => {
  console.log(`[KeyServer] Running on port ${PORT}`);
});
