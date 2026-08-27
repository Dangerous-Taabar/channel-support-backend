require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const fetch = require('node-fetch');
const FormData = require('form-data');

const app = express();
app.use(express.json({ limit: '5mb' })); // 5mb so an uploaded channel-logo (base64) fits

const allowedOrigins = (process.env.ALLOWED_ORIGINS || '*').split(',').map(s => s.trim());
app.use(cors({
  origin: allowedOrigins.includes('*') ? true : allowedOrigins
}));

const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev_secret_change_me';
const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL || `http://localhost:${PORT}`;
const MIN_DWELL_SECONDS = parseInt(process.env.MIN_DWELL_SECONDS || '15', 10);

// ---------------------------------------------------------------------------
// SHARED STORAGE (Upstash Redis) — this is what actually makes data visible
// across every visitor: supporters, leaderboard, admins, settings, branding.
// Sign up free at upstash.com, create a Redis database, and put its REST URL
// + token in UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN env vars.
// ---------------------------------------------------------------------------
const UPSTASH_URL = process.env.UPSTASH_REDIS_REST_URL;
const UPSTASH_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;

async function redisCommand(cmd) {
  if (!UPSTASH_URL || !UPSTASH_TOKEN) throw new Error('Upstash not configured');
  const r = await fetch(UPSTASH_URL, {
    method: 'POST',
    headers: { Authorization: `Bearer ${UPSTASH_TOKEN}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(cmd)
  });
  const data = await r.json();
  if (data.error) throw new Error(data.error);
  return data.result;
}

app.post('/api/storage/get', async (req, res) => {
  try {
    const { key } = req.body || {};
    if (!key) return res.status(400).json({ error: 'key required' });
    const value = await redisCommand(['GET', key]);
    res.json({ value });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/storage/set', async (req, res) => {
  try {
    const { key, value } = req.body || {};
    if (!key) return res.status(400).json({ error: 'key required' });
    await redisCommand(['SET', key, value]);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/storage/list', async (req, res) => {
  try {
    const { prefix } = req.body || {};
    const keys = await redisCommand(['KEYS', (prefix || '') + '*']);
    res.json({ keys: keys || [] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Session store — persisted in Redis (Upstash) so it survives server
// restarts/redeploys, and works even if Render spins up a new instance.
// ---------------------------------------------------------------------------
async function sessionGet(id) {
  const raw = await redisCommand(['GET', 'session:' + id]);
  return raw ? JSON.parse(raw) : null;
}
async function sessionSet(id, record) {
  await redisCommand(['SET', 'session:' + id, JSON.stringify(record)]);
}

function signToken(sessionId) {
  const hmac = crypto.createHmac('sha256', SESSION_SECRET);
  hmac.update(sessionId);
  return hmac.digest('hex');
}

function verifyTokenSignature(sessionId, token) {
  const expected = signToken(sessionId);
  // constant-time compare
  const a = Buffer.from(expected);
  const b = Buffer.from(token || '');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

// ---------------------------------------------------------------------------
// 1) START a support session
//    Frontend calls this when the user clicks "Open Support Link".
//    We create a unique, signed session, wrap the callback URL through the
//    shortlink provider, and hand the shortlink back to the frontend.
//    Because the final callback URL contains a per-user signed token that is
//    only revealed *after* the shortlink is actually opened, generic
//    "shortlink bypasser" tools (which just extract a known static
//    destination) have nothing fixed to extract — each link is single-use
//    and tied to this one device/session.
// ---------------------------------------------------------------------------
app.post('/api/support/start', async (req, res) => {
  const { deviceId } = req.body || {};
  if (!deviceId) return res.status(400).json({ error: 'deviceId required' });

  const sessionId = crypto.randomBytes(16).toString('hex');
  const token = signToken(sessionId);
  await sessionSet(sessionId, { deviceId, createdAt: Date.now(), verified: false, verifiedAt: null, consumed: false });

  const callbackUrl = `${PUBLIC_BASE_URL}/api/support/callback?session=${sessionId}&token=${token}`;

  let finalLink = callbackUrl;
  try {
    if (process.env.GPLINKS_API_KEY) {
      const apiUrl = `${process.env.GPLINKS_API_URL}?api=${process.env.GPLINKS_API_KEY}&url=${encodeURIComponent(callbackUrl)}`;
      const r = await fetch(apiUrl);
      const data = await r.json();
      // GPLinks-style response shape: { status: "success", shortenedUrl: "..." }
      if (data && (data.shortenedUrl || data.short_url)) {
        finalLink = data.shortenedUrl || data.short_url;
      }
    }
  } catch (err) {
    console.error('Shortlink provider call failed, falling back to direct callback URL:', err.message);
  }

  res.json({ sessionId, shortlink: finalLink });
});

// ---------------------------------------------------------------------------
// 2) CALLBACK — this is the URL the shortlink redirects to once the user has
//    completed all of the provider's steps. We verify the signature (proves
//    it wasn't tampered with) and enforce a minimum dwell time (proves the
//    user didn't jump straight here). On success, it redirects the browser
//    straight back into your live site (FRONTEND_URL) with ?verified=1 so
//    the same tab picks up the completion — no cross-tab polling needed.
// ---------------------------------------------------------------------------
app.get('/api/support/callback', async (req, res) => {
  const { session, token } = req.query;
  const record = await sessionGet(session);

  if (!record || !verifyTokenSignature(session, token)) {
    return res.status(400).send('<h2>Invalid or expired support link.</h2>');
  }

  const elapsedSeconds = (Date.now() - record.createdAt) / 1000;
  if (elapsedSeconds < MIN_DWELL_SECONDS) {
    return res.status(400).send('<h2>Steps completed too quickly — please try again.</h2>');
  }

  // ---- Basic bypass-tool defense ----
  // A real completion arrives here as a browser redirect FROM the shortlink
  // provider's own domain — so the Referer header must be present AND point
  // to GPLinks. Anyone who opens this link directly (pasted, new tab, curl,
  // bypass-bot) sends no Referer at all, or the wrong one — both are
  // blocked. Note: a small number of privacy-hardened browsers strip
  // Referer even on legitimate navigation, which would false-positive a
  // real supporter — an accepted trade-off for real bypass protection.
  const referer = (req.headers['referer'] || req.headers['referrer'] || '').toLowerCase();
  const userAgent = (req.headers['user-agent'] || '').toLowerCase();
  const looksLikeScript = /python|curl|wget|axios|okhttp|go-http-client|node-fetch|postman|scrapy/.test(userAgent);
  const cameFromShortlinkProvider = referer.includes('gplinks');

  if (looksLikeScript || !cameFromShortlinkProvider) {
    return res.status(404).send(`
      <html><body style="background:#08050f;color:#fff;font-family:sans-serif;text-align:center;padding-top:60px;">
        <h2>404 — Not Found</h2>
        <p>Steps complete karke hi is link tak pahunch sakte ho.<br>Seedha yeh link kholna allowed nahi hai — bahut jaldi aa gaye ho 😉</p>
      </body></html>
    `);
  }

  record.verified = true;
  record.verifiedAt = Date.now();
  await sessionSet(session, record);

  if (process.env.FRONTEND_URL) {
    const redirectUrl = `${process.env.FRONTEND_URL.replace(/\/$/, '')}/?verified=1&session=${session}`;
    return res.send(`
      <html><head><meta http-equiv="refresh" content="0;url=${redirectUrl}"></head>
      <body style="background:#08050f;color:#fff;font-family:sans-serif;text-align:center;padding-top:60px;">
        <h2>✅ Support verified!</h2>
        <p>Redirecting you back…</p>
        <script>window.location.href = ${JSON.stringify(redirectUrl)};</script>
      </body></html>
    `);
  }

  res.send(`
    <html><body style="background:#08050f;color:#fff;font-family:sans-serif;text-align:center;padding-top:60px;">
      <h2>✅ Support verified!</h2>
      <p>You can close this tab and return to the app.</p>
    </body></html>
  `);
});

// ---------------------------------------------------------------------------
// 3) STATUS — quick peek at a session's verified state (used as a fallback).
// ---------------------------------------------------------------------------
app.get('/api/support/status', async (req, res) => {
  const { sessionId } = req.query;
  const record = await sessionGet(sessionId);
  if (!record) return res.status(404).json({ verified: false });
  res.json({ verified: !!record.verified });
});

// ---------------------------------------------------------------------------
// 3b) CONSUME — the frontend calls this exactly once after detecting
//     ?verified=1 in the URL. It only returns ok:true the FIRST time for a
//     given session, then marks it consumed — so someone can't replay a
//     saved verified-callback URL to farm streaks/credit repeatedly.
// ---------------------------------------------------------------------------
app.post('/api/support/consume', async (req, res) => {
  const { sessionId } = req.body || {};
  const record = await sessionGet(sessionId);
  if (!record || !record.verified) return res.json({ ok: false, error: 'Not verified' });
  if (record.consumed) return res.json({ ok: false, error: 'Already used' });
  record.consumed = true;
  await sessionSet(sessionId, record);
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// 4) ADMIN VERIFY — real Telegram check via Bot API. The bot must be an
//    admin of the channel/group for getChatMember to work reliably.
// ---------------------------------------------------------------------------
app.post('/api/admin/verify', async (req, res) => {
  const { telegramId } = req.body || {};
  if (!telegramId) return res.status(400).json({ error: 'telegramId required' });
  if (!process.env.TELEGRAM_BOT_TOKEN || !process.env.TELEGRAM_CHAT_ID) {
    return res.status(500).json({ error: 'Bot token / chat id not configured on server' });
  }

  try {
    const url = `https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/getChatMember?chat_id=${encodeURIComponent(process.env.TELEGRAM_CHAT_ID)}&user_id=${encodeURIComponent(telegramId)}`;
    const r = await fetch(url);
    const data = await r.json();

    if (!data.ok) {
      return res.status(400).json({ isAdmin: false, error: data.description || 'Telegram API error' });
    }

    const status = data.result.status; // 'creator' | 'administrator' | 'member' | 'left' | 'kicked'
    const isAdmin = status === 'creator' || status === 'administrator';
    res.json({ isAdmin, status, isOwner: status === 'creator' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ isAdmin: false, error: 'Server error contacting Telegram' });
  }
});

app.get('/', (req, res) => res.send('Channel Support backend is running.'));

// ---------------------------------------------------------------------------
// 5) TELEGRAM LOGIN WIDGET — verifies the signed payload the widget sends
//    after a user taps "Allow" in Telegram, then checks real admin status.
//    Docs: https://core.telegram.org/widgets/login
// ---------------------------------------------------------------------------
function verifyTelegramWidgetAuth(payload) {
  const { hash, ...rest } = payload;
  if (!hash) return false;
  const dataCheckString = Object.keys(rest)
    .sort()
    .map((k) => `${k}=${rest[k]}`)
    .join('\n');
  const secretKey = crypto.createHash('sha256').update(process.env.TELEGRAM_BOT_TOKEN).digest();
  const computedHash = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest('hex');
  const a = Buffer.from(computedHash);
  const b = Buffer.from(hash);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

app.post('/api/admin/telegram-auth', async (req, res) => {
  if (!process.env.TELEGRAM_BOT_TOKEN || !process.env.TELEGRAM_CHAT_ID) {
    return res.status(500).json({ verified: false, error: 'Bot token / chat id not configured on server' });
  }
  const payload = req.body || {};
  if (!payload.id || !payload.hash) {
    return res.status(400).json({ verified: false, error: 'Invalid Telegram payload' });
  }

  const isValid = verifyTelegramWidgetAuth(payload);
  if (!isValid) {
    return res.status(400).json({ verified: false, error: 'Signature check failed' });
  }

  // Reject stale login attempts (older than 1 day)
  const ageSeconds = Math.floor(Date.now() / 1000) - Number(payload.auth_date || 0);
  if (ageSeconds > 86400) {
    return res.status(400).json({ verified: false, error: 'Login expired, please try again' });
  }

  const name = [payload.first_name, payload.last_name].filter(Boolean).join(' ');
  const profile = {
    id: payload.id,
    name: name || payload.username || ('User ' + payload.id),
    username: payload.username || '',
    photoUrl: payload.photo_url || ''
  };

  // Best-effort check of real Telegram status, used only to auto-detect the
  // channel creator (for the one-time owner bootstrap). Access itself is
  // controlled by the frontend's own owner-maintained username whitelist —
  // so if this check fails or the person isn't a channel member at all, we
  // still return their verified profile instead of blocking them here.
  let isOwner = false;
  try {
    const url = `https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/getChatMember?chat_id=${encodeURIComponent(process.env.TELEGRAM_CHAT_ID)}&user_id=${encodeURIComponent(payload.id)}`;
    const r = await fetch(url);
    const data = await r.json();
    if (data.ok) isOwner = data.result.status === 'creator';
  } catch (err) {
    console.error('getChatMember check failed (non-fatal):', err.message);
  }

  res.json({ verified: true, isOwner, profile });
});

// ---------------------------------------------------------------------------
// 6) LIGHTWEIGHT IDENTITY VERIFY — used when a normal (non-admin) supporter
//    connects with Telegram. Only checks the signature (proves it's really
//    them), no admin/creator check needed here.
// ---------------------------------------------------------------------------
app.post('/api/telegram/verify-identity', (req, res) => {
  if (!process.env.TELEGRAM_BOT_TOKEN) {
    return res.status(500).json({ verified: false, error: 'Bot token not configured on server' });
  }
  const payload = req.body || {};
  if (!payload.id || !payload.hash) {
    return res.status(400).json({ verified: false, error: 'Invalid Telegram payload' });
  }
  if (!verifyTelegramWidgetAuth(payload)) {
    return res.status(400).json({ verified: false, error: 'Signature check failed' });
  }
  const name = [payload.first_name, payload.last_name].filter(Boolean).join(' ');
  res.json({
    verified: true,
    profile: {
      id: payload.id,
      name: name || payload.username || ('User ' + payload.id),
      username: payload.username || '',
      photoUrl: payload.photo_url || ''
    }
  });
});

// ---------------------------------------------------------------------------
// 7) GROUP NOTIFICATION — bot posts a message whenever a supporter completes
//    support (only called by the frontend when the owner has this toggled
//    ON in the admin panel). Optionally point this at a different chat
//    (e.g. your discussion group) via TELEGRAM_NOTIFY_CHAT_ID; otherwise it
//    falls back to TELEGRAM_CHAT_ID.
// ---------------------------------------------------------------------------
app.post('/api/notify/support', async (req, res) => {
  const targetChat = process.env.TELEGRAM_NOTIFY_CHAT_ID || process.env.TELEGRAM_CHAT_ID;
  if (!process.env.TELEGRAM_BOT_TOKEN || !targetChat) {
    return res.status(500).json({ sent: false, error: 'Bot token / chat id not configured' });
  }
  const { name, username, totalDays, streak } = req.body || {};
  const who = username ? '@' + username : (name || 'Someone');
  const caption = `🎉 ${who} ne channel ko support kiya!\n📅 Total support: ${totalDays} din\n🔥 Current streak: ${streak} din\n\n👇 Tum bhi support karo:`;
  const siteUrl = process.env.FRONTEND_URL || process.env.PUBLIC_BASE_URL;
  const replyMarkup = { inline_keyboard: [[{ text: '🚀 Support Now', url: siteUrl }]] };

  try {
    // Try to attach the channel logo (uploaded by the admin) as the photo.
    let imageBuffer = null;
    try {
      const brandingRaw = await redisCommand(['GET', 'branding']);
      if (brandingRaw) {
        const branding = JSON.parse(brandingRaw);
        if (branding.logoData && branding.logoData.includes(',')) {
          imageBuffer = Buffer.from(branding.logoData.split(',')[1], 'base64');
        }
      }
    } catch (e) { /* no logo set yet — fall back to text-only below */ }

    let data;
    if (imageBuffer) {
      const form = new FormData();
      form.append('chat_id', targetChat);
      form.append('caption', caption);
      form.append('reply_markup', JSON.stringify(replyMarkup));
      form.append('photo', imageBuffer, { filename: 'support.png', contentType: 'image/png' });
      const r = await fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendPhoto`, {
        method: 'POST',
        body: form
      });
      data = await r.json();
    } else {
      const r = await fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: targetChat, text: caption, reply_markup: replyMarkup })
      });
      data = await r.json();
    }
    res.json({ sent: !!data.ok, error: data.ok ? null : data.description });
  } catch (err) {
    console.error(err);
    res.status(500).json({ sent: false, error: 'Server error contacting Telegram' });
  }
});

app.listen(PORT, () => console.log(`Support backend listening on port ${PORT}`));
