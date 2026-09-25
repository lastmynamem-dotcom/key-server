/**
 * server.js — Checkpoint verification + key issuance backend
 */

const express = require('express');
const path = require('path');

const app = express();
app.use(express.json());
// Allows checkpoint verification without a cross-origin JSON preflight.
app.use(express.urlencoded({ extended: false, limit: '4kb' }));

const ALLOWED_ORIGINS = [
  'https://synthhub.net',
  'https://www.synthhub.net'
];
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.vary('Origin');
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
const LINKVERTISE_TOKEN = (process.env.LINKVERTISE_ANTI_BYPASS_TOKEN || '').trim();
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
  const fail = (status, error, message) => ({ ok: false, status, error, message });
  if (!LINKVERTISE_TOKEN) {
    return fail(503, 'linkvertise_not_configured', 'Linkvertise verification is not configured on this server. Please contact the site owner.');
  }
  if (LINKVERTISE_TOKEN.length !== 64 || /\s/.test(LINKVERTISE_TOKEN)) {
    return fail(503, 'linkvertise_config_invalid', 'The server has an incorrectly formatted Linkvertise publisher token. Please contact the site owner.');
  }
  if (typeof hash !== 'string' || hash.length !== 64 || /\s/.test(hash)) {
    return fail(400, 'linkvertise_hash_malformed', 'A valid Linkvertise redirect hash was not received. Complete checkpoint 1 again.');
  }
  const url = new URL('https://publisher.linkvertise.com/api/v1/anti_bypassing');
  url.searchParams.set('token', LINKVERTISE_TOKEN);
  url.searchParams.set('hash', hash);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8000);
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { Accept: 'application/json' },
      signal: controller.signal,
      redirect: 'error'
    });
    const raw = (await res.text()).trim();
    // Never log the request URL: it contains the publisher secret and visitor hash.
    if (/invalid\s+(?:authentication\s+)?token/i.test(raw)) {
      return fail(503, 'linkvertise_auth_rejected', 'Linkvertise rejected the server publisher token. Please contact the site owner.');
    }
    if (!res.ok) {
      return fail(502, 'linkvertise_upstream_http', 'Linkvertise could not verify this visit right now. Complete the checkpoint again shortly.');
    }
    let parsed;
    try { parsed = JSON.parse(raw); } catch (_) { parsed = raw; }
    // Accept explicit true only. Strings such as "false" are never truthy proof.
    const positive = parsed === true ||
      (typeof parsed === 'string' && parsed.toLowerCase() === 'true') ||
      (parsed && typeof parsed === 'object' && (parsed.result === true || parsed.valid === true));
    if (positive) return { ok: true };
    const negative = parsed === false ||
      (typeof parsed === 'string' && parsed.toLowerCase() === 'false') ||
      (parsed && typeof parsed === 'object' && (parsed.result === false || parsed.valid === false));
    if (negative) {
      return fail(403, 'linkvertise_hash_rejected', 'Linkvertise did not recognize this hash. It may have expired or already been used. Complete the checkpoint again for a fresh link.');
    }
    return fail(502, 'linkvertise_unexpected_response', 'Linkvertise returned an unexpected verification response. Please contact the site owner.');
  } catch (error) {
    return fail(502,
      error.name === 'AbortError' ? 'linkvertise_timeout' : 'linkvertise_unreachable',
      'The server could not get a verification response from Linkvertise. Complete the checkpoint again shortly.');
  } finally {
    clearTimeout(timer);
  }
}

function sendLinkvertiseFailure(res, result) {
  console.warn('[Linkvertise]', result.error);
  return res.status(result.status).json({ ok: false, error: result.error, message: result.message });
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
  else if (provider === 'linkvertise') {
    const result = await verifyLinkvertise(token);
    if (!result.ok) return sendLinkvertiseFailure(res, result);
    verified = true;
  }
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
  res.setHeader('Cache-Control', 'no-store');
  const { provider } = req.body || {};
  const token = req.body?.token || req.body?.hash || '';
  if (!provider || !token) return res.status(400).json({ ok: false, error: 'missing_fields' });
  let verified = false;
  if (provider === 'linkvertise') {
    const result = await verifyLinkvertise(token);
    if (!result.ok) return sendLinkvertiseFailure(res, result);
    verified = true;
  }
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
  if (!LINKVERTISE_TOKEN) {
    console.warn('[Linkvertise] Set LINKVERTISE_ANTI_BYPASS_TOKEN in Railway Variables to your publisher authentication token.');
  } else if (LINKVERTISE_TOKEN.length !== 64 || /\s/.test(LINKVERTISE_TOKEN)) {
    console.warn('[Linkvertise] LINKVERTISE_ANTI_BYPASS_TOKEN must be 64 characters, without quotes or whitespace.');
  } else {
    console.log('[Linkvertise] Publisher token configured; its validity is checked by Linkvertise when a visitor returns.');
  }
});
