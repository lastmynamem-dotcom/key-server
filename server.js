/**
 * server.js — Checkpoint 2 verification backend
 *
 * This is the only place that decides whether a checkpoint was really
 * completed. The HTML page never makes that decision itself — it just
 * asks this server and shows/hides content based on the answer.
 *
 * Run:
 *   npm install
 *   cp .env.example .env      # fill in your real values
 *   node server.js
 */

const express = require('express');
const path = require('path');

const app = express();
app.use(express.json());

// checkpoint2.html now lives on Hostinger, not here — so this is a
// cross-origin call. Allow only your real domain(s), not "*".
const ALLOWED_ORIGINS = [
  'https://synthhub.net',
  'https://www.synthhub.net'
];
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// The /public folder here is optional now that checkpoint2.html is
// served from Hostinger — kept in case you want to test locally.
app.use(express.static(path.join(__dirname, 'public')));

const PORT = process.env.PORT || 3000;

// Secret Linkvertise Anti-Bypass token — NEVER sent to the browser.
const LINKVERTISE_TOKEN = process.env.LINKVERTISE_ANTI_BYPASS_TOKEN || '';

// The real reward, only handed out after verification succeeds.
// Put your actual key/content behind this env var.
const ACCESS_KEY = process.env.ACCESS_KEY || 'REPLACE_ME_IN_ENV';

// In-memory replay guard: a hash/token that's already been redeemed
// can't be redeemed again. Fine for a single instance; swap for
// Redis/a DB if you ever run more than one server process.
const usedTokens = new Set();

// Very small per-IP rate limit so this endpoint can't be hammered.
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
    // Docs describe a bare boolean-style response. Handle both a plain
    // "true" string and a {"result":true}-style JSON body defensively.
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

async function verifyLootlabs(_hash) {
  // Deliberately fails closed. LootLabs' documented anti-bypass mechanism
  // is the Redirect API (pre-encrypt the destination URL server-side via
  // POST creators.lootlabs.gg/api/public/url_encryptor and pass it as
  // &data= on the LootLabs link) — not a post-redirect hash you validate
  // here. Confirm the real mechanism with LootLabs support/dashboard
  // before wiring this path up; shipping a guess would mean silently
  // trusting unverified traffic.
  console.warn('[verify:lootlabs] not implemented — failing closed');
  return false;
}

app.post('/api/verify', async (req, res) => {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
  if (rateLimited(ip)) {
    return res.status(429).json({ ok: false, error: 'rate_limited' });
  }

  const { provider, token } = req.body || {};
  if (!provider || !token || typeof token !== 'string') {
    return res.status(400).json({ ok: false, error: 'missing_fields' });
  }

  if (usedTokens.has(token)) {
    return res.status(409).json({ ok: false, error: 'already_used' });
  }

  let verified = false;
  if (provider === 'linkvertise') verified = await verifyLinkvertise(token);
  else if (provider === 'workink') verified = await verifyWorkink(token);
  else if (provider === 'lootlabs') verified = await verifyLootlabs(token);
  else return res.status(400).json({ ok: false, error: 'unknown_provider' });

  if (!verified) {
    return res.status(403).json({ ok: false, error: 'not_verified' });
  }

  usedTokens.add(token);
  return res.json({ ok: true, key: ACCESS_KEY });
});

app.listen(PORT, () => {
  console.log(`Checkpoint verification server listening on :${PORT}`);
});
