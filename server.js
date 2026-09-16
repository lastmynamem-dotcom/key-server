/**
 * server.js — Checkpoint verification + key issuance backend
 *
 * CHANGES FROM YOUR VERSION (see fixes.txt for the full explanation):
 *   1. Added POST /register — this is what checkpoint's destination.html
 *      actually calls. Your old file only had /api/verify, which nothing
 *      on the front end calls anymore. That mismatch alone meant every
 *      redemption attempt was hitting a route that doesn't exist.
 *   2. verifyLootlabs() no longer fails closed. LootLabs doesn't expose a
 *      "check this token" endpoint the way Linkvertise/Work.ink do — its
 *      real anti-bypass mechanism for this use case is the Postback API
 *      (LootLabs calls YOU, server-to-server, when a task completes). See
 *      GET /api/lootlabs/postback below, and fixes.txt for the panel
 *      setup you still need to do on LootLabs' side.
 *   3. Error messages now include the real provider name, instead of a
 *      hardcoded string — this is almost certainly the source of the
 *      "Invalid or already used work.ink token" message you saw while
 *      using Linkvertise.
 *   4. /register replay-guards on `${provider}:${token}` instead of a
 *      bare token, and issued keys are tracked (with expiry) in
 *      `issuedKeys` so you have somewhere to point a future Roblox-side
 *      "is this key valid" check.
 *
 * Run:
 *   npm install
 *   cp .env.example .env      # fill in your real values, see fixes.txt
 *   node server.js
 */

const express = require('express');
const path = require('path');

const app = express();
app.use(express.json());

// checkpoint2.html / destination.html live on Hostinger, not here — so
// this is a cross-origin call. Allow only your real domain(s), not "*".
const ALLOWED_ORIGINS = [
  'https://synthhub.net',
  'https://www.synthhub.net'
];
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// The /public folder here is optional now that the pages are served
// from Hostinger — kept in case you want to test locally.
app.use(express.static(path.join(__dirname, 'public')));

// Health check endpoint for Railway
app.get('/ping', (req, res) => {
  res.status(200).send('ok');
});

const PORT = process.env.PORT || 3000;

// Secret Linkvertise Anti-Bypass token — NEVER sent to the browser.
const LINKVERTISE_TOKEN = process.env.LINKVERTISE_ANTI_BYPASS_TOKEN || '';

// Must match the API_SECRET constant hardcoded in destination.html
// ('ks_fire99' as of your current file). Note this is NOT a real secret —
// anyone can view-source the page and read it. It only filters out
// random noise hitting /register; the actual security boundary is the
// per-provider token verification below.
const API_SECRET = process.env.API_SECRET || '';

// In-memory replay guard: a provider+token pair that's already been
// redeemed can't be redeemed again. Fine for a single instance; swap
// for Redis/a DB if you ever run more than one server process.
const usedTokens = new Set();

// Keys this server has issued, so something (e.g. your Roblox-side
// check, once you wire it up) has somewhere to look them up.
const issuedKeys = new Map(); // key -> { provider, expiresAt, issuedAt }

// Very small per-IP rate limit so these endpoints can't be hammered.
const hits = new Map(); // ip -> [timestamps]
const RATE_WINDOW_MS = 10_000;
const RATE_MAX = 8;
function rateLimited(ip) {
  const now = Date.now();
  const arr = (hits.get(ip) || []).filter(t => now - t < RATE_WINDOW_MS);
  arr.push(now);
  hits.set(ip, arr);
  return arr.length > RATE_MAX;
}

async function verifyLinkvertise(hash) {
  if (!LINKVERTISE_TOKEN) {
    console.error('[verify] LINKVERTISE_ANTI_BYPASS_TOKEN is not set');
    return false;
  }
  const url = `https://publisher.linkvertise.com/api/v1/anti_bypassing?token=${encodeURIComponent(LINKVERTISE_TOKEN)}&hash=${encodeURIComponent(hash)}`;
  try {
    const res = await fetch(url, { method: 'POST' });
    const raw = (await res.text()).trim();
    console.log('[verify:linkvertise] status', res.status, 'body:', raw);
    if (raw.toLowerCase() === 'true') return true;
    try {
      const parsed = JSON.parse(raw);
      if (parsed === true) return true;
      if (parsed && (parsed.result === true || parsed.valid === true)) return true;
    } catch (_) { /* not JSON, already handled above */ }
    return false;
  } catch (err) {
    console.error('[verify:linkvertise] request failed', err);
    return false;
  }
}

async function verifyWorkink(hash) {
  const url = `https://work.ink/_api/v2/token/isValid/${encodeURIComponent(hash)}?deleteToken=1`;
  try {
    const res = await fetch(url);
    const data = await res.json();
    console.log('[verify:workink] status', res.status, 'body:', data);
    return data && data.valid === true;
  } catch (err) {
    console.error('[verify:workink] request failed', err);
    return false;
  }
}

/* ══════════════════════════════════════════════════════════════
   LOOTLABS — Postback-based verification
   ══════════════════════════════════════════════════════════════
   LootLabs has no "check this token" endpoint like the other two
   providers. Its documented anti-bypass mechanism for reward/key
   systems is the Postback API: you configure a URL in the LootLabs
   panel (Advanced tab -> Postback), and LootLabs itself sends a GET
   request to that URL, server-to-server, the moment a user finishes
   a task. That request is treated as ground truth here.

   You still need to, on LootLabs' side:
     1. Enable Postback in the panel and set the postback URL to:
          https://key-server-production-e99d.up.railway.app/api/lootlabs/postback
     2. Confirm (from LootLabs' own docs/panel) exactly which query
        params they send back — the docs snippet available at the
        time this was written mentions click_id, ip, and unique_id,
        but that wording has changed before and may again. The first
        few times a real completion comes through, check your Railway
        logs for the "[lootlabs:postback] query:" line and confirm
        the field names below still match what's actually arriving.
     3. Append &puid=<a value you generate> to the outgoing LootLabs
        link for checkpoint 2 (see fixes.txt — this happens in
        checkpoint-2.html, not here) so you have something to match
        the postback call back up to the specific visitor.
*/
const lootlabsCompleted = new Map(); // puid -> { ts, ip, raw }
const LOOTLABS_COMPLETION_TTL_MS = 30 * 60 * 1000; // 30 min to redeem after completing

function cleanupLootlabs() {
  const now = Date.now();
  for (const [k, v] of lootlabsCompleted) {
    if (now - v.ts > LOOTLABS_COMPLETION_TTL_MS) lootlabsCompleted.delete(k);
  }
}

app.get('/api/lootlabs/postback', (req, res) => {
  console.log('[lootlabs:postback] query:', req.query);
  const puid = req.query.puid || req.query.unique_id || req.query.click_id;
  if (!puid) {
    console.warn('[lootlabs:postback] no identifying field in query — cannot mark complete. Check the field names against your LootLabs panel.');
    return res.status(400).send('missing id');
  }
  lootlabsCompleted.set(String(puid), {
    ts: Date.now(),
    ip: req.query.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress,
    raw: req.query
  });
  res.status(200).send('ok');
});

// Lets the front end poll "has the postback for this visitor landed
// yet" without burning a /register attempt while it waits.
app.get('/api/lootlabs/status', (req, res) => {
  cleanupLootlabs();
  const puid = String(req.query.puid || '');
  res.json({ ready: !!puid && lootlabsCompleted.has(puid) });
});

async function verifyLootlabs(puid) {
  cleanupLootlabs();
  if (!puid) return false;
  const entry = lootlabsCompleted.get(puid);
  if (!entry) return false;
  lootlabsCompleted.delete(puid); // single use
  return true;
}

/* ══════════════════════════════════════════════════════════════
   /register — what destination.html actually calls
   ══════════════════════════════════════════════════════════════ */
app.post('/register', async (req, res) => {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
  if (rateLimited(ip)) {
    return res.status(429).json({ ok: false, error: 'rate_limited' });
  }

  const body = req.body || {};
  const { key, expires_at, secret, provider } = body;
  const token = body.token || body.hash || '';

  if (!API_SECRET) {
    console.error('[register] API_SECRET is not set on the server');
    return res.status(500).json({ ok: false, message: 'Server misconfigured.' });
  }
  if (secret !== API_SECRET) {
    return res.status(401).json({ ok: false, error: 'bad_secret' });
  }
  if (!key || !expires_at || !provider || !token) {
    return res.status(400).json({ ok: false, error: 'missing_fields' });
  }

  const replayId = `${provider}:${token}`;
  if (usedTokens.has(replayId)) {
    return res.status(409).json({
      ok: false,
      message: `Invalid or already used ${provider} token.`
    });
  }

  let verified = false;
  if (provider === 'linkvertise') verified = await verifyLinkvertise(token);
  else if (provider === 'workink') verified = await verifyWorkink(token);
  else if (provider === 'lootlabs') verified = await verifyLootlabs(token);
  else return res.status(400).json({ ok: false, error: 'unknown_provider' });

  if (!verified) {
    return res.status(403).json({
      ok: false,
      message: `Invalid or already used ${provider} token.`
    });
  }

  usedTokens.add(replayId);
  issuedKeys.set(key, { provider, expiresAt: expires_at, issuedAt: Date.now() });

  return res.json({ ok: true, key });
});

/* ══════════════════════════════════════════════════════════════
   Kept for backwards compatibility / manual testing. Nothing in
   the files you gave me currently calls this — /register is the
   one destination.html uses.
   ══════════════════════════════════════════════════════════════ */
app.post('/api/verify', async (req, res) => {
  const { provider, token } = req.body || {};
  if (!provider || !token || typeof token !== 'string') {
    return res.status(400).json({ ok: false, error: 'missing_fields' });
  }
  let verified = false;
  if (provider === 'linkvertise') verified = await verifyLinkvertise(token);
  else if (provider === 'workink') verified = await verifyWorkink(token);
  else if (provider === 'lootlabs') verified = await verifyLootlabs(token);
  else return res.status(400).json({ ok: false, error: 'unknown_provider' });

  if (!verified) {
    return res.status(403).json({ ok: false, message: `Invalid or already used ${provider} token.` });
  }
  return res.json({ ok: true });
});

// Minimal starting point for a future Roblox-side "is this key valid"
// check. Nothing calls this yet — wire your Lua HttpService request to
// it (or adapt the shape to whatever your script already expects) once
// you're ready to close the loop on redemption.
app.get('/api/keys/:key/valid', (req, res) => {
  const entry = issuedKeys.get(req.params.key);
  const valid = !!entry && new Date(entry.expiresAt).getTime() > Date.now();
  res.json({ valid });
});

setInterval(() => {
  cleanupLootlabs();
  const now = Date.now();
  for (const [k, v] of issuedKeys) {
    if (new Date(v.expiresAt).getTime() < now) issuedKeys.delete(k);
  }
}, 5 * 60 * 1000);

app.listen(PORT, () => {
  console.log(`Checkpoint verification server listening on :${PORT}`);
});
