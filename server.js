/**
 * server.js — Checkpoint verification + key issuance backend
 */

const express = require('express');
const path = require('path');

const app = express();
app.use(express.json());

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

app.use(express.static(path.join(__dirname, 'public')));

app.get('/ping', (req, res) => {
  res.status(200).send('ok');
});

const PORT = process.env.PORT || 3000;
const LINKVERTISE_TOKEN = process.env.LINKVERTISE_ANTI_BYPASS_TOKEN || '';
const API_SECRET = process.env.API_SECRET || '';

const usedTokens = new Set();
const issuedKeys = new Map(); // key -> { provider, expiresAt, issuedAt, hwid }

const hits = new Map();
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
  if (!LINKVERTISE_TOKEN) return false;
  const url = `https://publisher.linkvertise.com/api/v1/anti_bypassing?token=${encodeURIComponent(LINKVERTISE_TOKEN)}&hash=${encodeURIComponent(hash)}`;
  try {
    const res = await fetch(url, { method: 'POST' });
    const raw = (await res.text()).trim();
    if (raw.toLowerCase() === 'true') return true;
    try {
      const parsed = JSON.parse(raw);
      if (parsed === true || (parsed && (parsed.result === true || parsed.valid === true))) return true;
    } catch (_) {}
    return false;
  } catch { return false; }
}

async function verifyWorkink(hash) {
  const url = `https://work.ink/_api/v2/token/isValid/${encodeURIComponent(hash)}?deleteToken=1`;
  try {
    const res = await fetch(url);
    const data = await res.json();
    return data && data.valid === true;
  } catch { return false; }
}

const lootlabsCompleted = new Map();
const LOOTLABS_COMPLETION_TTL_MS = 30 * 60 * 1000;

function cleanupLootlabs() {
  const now = Date.now();
  for (const [k, v] of lootlabsCompleted) {
    if (now - v.ts > LOOTLABS_COMPLETION_TTL_MS) lootlabsCompleted.delete(k);
  }
}

app.get('/api/lootlabs/postback', (req, res) => {
  const puid = req.query.puid || req.query.unique_id || req.query.click_id;
  if (!puid) return res.status(400).send('missing id');
  lootlabsCompleted.set(String(puid), { ts: Date.now(), ip: req.query.ip, raw: req.query });
  res.status(200).send('ok');
});

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
  lootlabsCompleted.delete(puid);
  return true;
}

/* /register — destination.html calls this */
app.post('/register', async (req, res) => {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
  if (rateLimited(ip)) return res.status(429).json({ ok: false, error: 'rate_limited' });

  const body = req.body || {};
  const { key, expires_at, secret, provider } = body;
  const token = body.token || body.hash || '';

  if (!API_SECRET) return res.status(500).json({ ok: false, message: 'Server misconfigured.' });
  if (secret !== API_SECRET) return res.status(401).json({ ok: false, error: 'bad_secret' });
  if (!key || !expires_at || !provider || !token) return res.status(400).json({ ok: false, error: 'missing_fields' });

  const replayId = `${provider}:${token}`;
  if (usedTokens.has(replayId)) return res.status(409).json({ ok: false, message: `Invalid or already used ${provider} token.` });

  let verified = false;
  if (provider === 'workink')     verified = await verifyWorkink(token);
  else if (provider === 'linkvertise') verified = await verifyLinkvertise(token);
  else if (provider === 'lootlabs')   verified = await verifyLootlabs(token);
  else if (token === 'admin_bypass')  verified = true; // admin key generator
  else return res.status(400).json({ ok: false, error: 'unknown_provider' });

  if (!verified) return res.status(403).json({ ok: false, message: `Invalid or already used ${provider} token.` });

  usedTokens.add(replayId);
  issuedKeys.set(key, { provider, expiresAt: expires_at, issuedAt: Date.now(), hwid: null });

  return res.json({ ok: true, key });
});

/* /validate — called by the Roblox Lua key system
   Body: { key: string, hwid: string }
   Returns: { valid: bool, reason: string } */
app.post('/validate', (req, res) => {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
  if (rateLimited(ip)) return res.status(429).json({ valid: false, reason: 'rate_limited' });

  const { key, hwid } = req.body || {};
  if (!key || !hwid) return res.json({ valid: false, reason: 'missing_fields' });

  const entry = issuedKeys.get(key);
  if (!entry) {
    console.log('[validate] not_found key=' + key);
    return res.json({ valid: false, reason: 'not_found' });
  }

  // Check expiry — year 9999 = lifetime
  const expiry = new Date(entry.expiresAt).getTime();
  const isLifetime = expiry > 253370764800000;
  if (!isLifetime && Date.now() > expiry) {
    issuedKeys.delete(key);
    console.log('[validate] expired key=' + key);
    return res.json({ valid: false, reason: 'expired' });
  }

  // HWID binding
  if (!entry.hwid) {
    entry.hwid = hwid;
    console.log('[validate] bound key=' + key + ' hwid=' + hwid);
    return res.json({ valid: true, reason: 'bound' });
  }
  if (entry.hwid !== hwid) {
    console.log('[validate] wrong_hwid key=' + key);
    return res.json({ valid: false, reason: 'wrong_hwid' });
  }

  console.log('[validate] ok key=' + key);
  return res.json({ valid: true, reason: 'ok' });
});

app.post('/api/verify', async (req, res) => {
  const { provider, token } = req.body || {};
  if (!provider || !token) return res.status(400).json({ ok: false, error: 'missing_fields' });
  let verified = false;
  if (provider === 'linkvertise') verified = await verifyLinkvertise(token);
  else if (provider === 'workink') verified = await verifyWorkink(token);
  else if (provider === 'lootlabs') verified = await verifyLootlabs(token);
  else return res.status(400).json({ ok: false, error: 'unknown_provider' });
  if (!verified) return res.status(403).json({ ok: false, message: `Invalid or already used ${provider} token.` });
  return res.json({ ok: true });
});

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
  console.log('Checkpoint verification server listening on :' + PORT);
});
