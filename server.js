require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const zlib = require('zlib');
const fs = require('fs');
const path = require('path');
const fetch = require('node-fetch');
const FormData = require('form-data');
const { renderCertificate, tierForDays, clearTemplateCache, setProviders: setCertProviders, templateInfo, prepareTemplate, defaultLayout, inspectTemplate, looksLikeImage } = require('./certificate');

const app = express();
app.use(express.json({ limit: '5mb' })); // logos / branding images only (animated card clips were removed)

// ---------------------------------------------------------------------------
// SECURITY HEADERS — basic hardening without needing extra dependencies.
// ---------------------------------------------------------------------------
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Strict-Transport-Security', 'max-age=15552000; includeSubDomains');
  next();
});

// ---------------------------------------------------------------------------
// RATE LIMITING — simple in-memory sliding window per IP. Stops a script
// from hammering any endpoint (fake support sessions, admin-login brute
// force, storage spam). Resets naturally every WINDOW_MS.
// ---------------------------------------------------------------------------
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX = 60; // requests per IP per window
const rateLimitBuckets = new Map();
setInterval(() => rateLimitBuckets.clear(), RATE_LIMIT_WINDOW_MS).unref();

app.use((req, res, next) => {
  // Ludo game traffic (live polling) has its own per-player limits inside ludo/ludo.js
  if (req.path.startsWith('/api/ludo/')) return next();
  // Astra Store: the bots long-poll and the Mini App polls an order; store/store.js limits per user itself
  if (req.path.startsWith('/api/store/')) return next();
  const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown';
  const count = (rateLimitBuckets.get(ip) || 0) + 1;
  rateLimitBuckets.set(ip, count);
  if (count > RATE_LIMIT_MAX) {
    return res.status(429).json({ error: 'Too many requests — thodi der baad try karo.' });
  }
  next();
});

const allowedOrigins = (process.env.ALLOWED_ORIGINS || '*').split(',').map(s => s.trim());
app.use(cors({
  origin: allowedOrigins.includes('*') ? true : allowedOrigins,
  credentials: true
}));

// ---------------------------------------------------------------------------
// LUDO — multiplayer Ludo for the ASTRA Telegram bot (Mini App page: /ludo on the frontend).
// Needs LUDO_BOT_TOKEN + LUDO_BOT_SECRET (see .env.example). Mounted right after CORS on purpose.
// ---------------------------------------------------------------------------
app.use('/api/ludo', require('./ludo/ludo').router);

const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev_secret_change_me';
const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL || `http://localhost:${PORT}`;
const MIN_DWELL_SECONDS = parseInt(process.env.MIN_DWELL_SECONDS || '25', 10);
// Second gate, AFTER the shortlink leg, entirely on our own domain — see the
// callback/confirm endpoints below for why this exists. NOTE: 6s (the old
// default) was too short to matter — any human, bypass-bot or not, waits out
// 6 seconds without noticing. The real point of this gate isn't to be
// unautomatable (a person still just sits and waits, same as before); it's
// to make bypassing GPLinks pointless: once our OWN wait matches or exceeds
// what GPLinks would have taken anyway, there's nothing left to save by
// bypassing it. Tune via CONFIRM_DELAY_SECONDS to whatever GPLinks itself
// normally takes for your ad flow.
const CONFIRM_DELAY_SECONDS = parseInt(process.env.CONFIRM_DELAY_SECONDS || '15', 10);

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
    body: JSON.stringify(cmd),
    signal: AbortSignal.timeout(8000) // never hang forever on the database
  });
  const data = await r.json();
  if (data.error) throw new Error(data.error);
  return data.result;
}

// Only known key patterns are writable/readable — stops random/abusive keys
// and keeps the value size sane (branding logo can be a few hundred KB).
const ALLOWED_KEY_PATTERN = /^(profile|admins|settings|branding|admin_audit_log|supporter:[\w-]+|adminprofile:[\w-]+|cbfile:\d+|cbfile_seq|cbpost:\d+|cbpost_seq|cb:users|cb:admins|cbuser:[\w-]+|cb:log_total|cb:log_matched|session:[\w-]+|admin_pass:tg_[\w-]+)$/;
function isValidStorageKey(key) {
  return typeof key === 'string' && key.length <= 120 && ALLOWED_KEY_PATTERN.test(key);
}
// auth_epoch is a single global counter used to force everyone's browser to
// sign out on next load (see /api/admin/force-logout-all below). Reading it
// is harmless — it's just a number — but only that dedicated, owner-gated
// endpoint may ever change it, so it stays out of the generic write allowlist.
function isValidReadOnlyKey(key) {
  return key === 'auth_epoch';
}
const MAX_VALUE_BYTES = 1_500_000; // ~1.5MB — comfortably covers a base64 logo

// ---------------------------------------------------------------------------
// ASTRA STORE - Mini App store (/store on the frontend). Needs STORE_SECRET (+ STORE_BOT_TOKEN, or it
// reuses LUDO_BOT_TOKEN, the ASTRA bot token). Uses the same Redis as everything else.
// ---------------------------------------------------------------------------
app.use('/api/store', require('./store/store')(redisCommand));

app.post('/api/storage/get', async (req, res) => {
  try {
    const { key } = req.body || {};
    if (!isValidStorageKey(key) && !isValidReadOnlyKey(key)) return res.status(400).json({ error: 'invalid key' });
    const value = await redisCommand(['GET', key]);
    res.json({ value });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/storage/set', async (req, res) => {
  try {
    const { key, value } = req.body || {};
    if (!isValidStorageKey(key)) return res.status(400).json({ error: 'invalid key' });
    if (typeof value === 'string' && value.length > MAX_VALUE_BYTES) {
      return res.status(413).json({ error: 'value too large' });
    }
    await redisCommand(['SET', key, value]);
    // A supporter record just changed (new support, admin edit, etc.) — don't
    // make the bot's next leaderboard/rank lookup wait out the cache window.
    if (key.startsWith('supporter:')) invalidateSupportersCache();
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

// Batch read — the frontend needs every supporter record to build the
// leaderboard/dashboard/chart. Fetching them one key at a time meant one
// HTTP round trip per supporter (100 supporters = 100 requests, and the
// page got slower as the community grew). MGET returns them all in one.
app.post('/api/storage/mget', async (req, res) => {
  try {
    const { keys } = req.body || {};
    if (!Array.isArray(keys) || keys.length === 0) return res.json({ values: [] });
    if (keys.length > 500) return res.status(400).json({ error: 'too many keys' });
    if (!keys.every(isValidStorageKey)) return res.status(400).json({ error: 'invalid key' });
    const values = await redisCommand(['MGET', ...keys]);
    res.json({ values: values || [] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Health check — used by the admin panel's "Service status" card so an
// admin can tell at a glance whether the API is up and whether Redis is
// actually configured, instead of guessing from a blank dashboard.
app.get('/api/health', async (req, res) => {
  const out = { ok: true, uptimeSeconds: Math.round(process.uptime()), redis: 'unknown' };
  try {
    await redisCommand(['PING']);
    out.redis = 'ok';
  } catch (err) {
    out.ok = false;
    out.redis = (!UPSTASH_URL || !UPSTASH_TOKEN) ? 'not-configured' : 'error';
  }
  res.status(out.ok ? 200 : 503).json(out);
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
// Session-binding cookie — set on THIS browser the moment it starts a
// support session, checked when it comes back at /callback. No cookie
// library needed for this (Express doesn't parse cookies by default; we
// only ever need to read/write this one, so plain header parsing is enough).
//
// SameSite=None;Secure is required because the frontend (Cloudflare Pages)
// and this backend (Render) are different domains — a normal SameSite=Lax
// cookie wouldn't survive the cross-origin fetch() that creates the
// session. This is a real, if unlikely, single-purpose cross-origin cookie
// (not a tracking pattern), but SOME privacy-hardened browsers still block
// it — so a MISSING cookie is never treated as proof of tampering (that
// would repeat the old Referer-header mistake and could block real
// supporters). Only a cookie that's present AND doesn't match the session
// being opened is treated as certain — that can only happen if this
// browser is not the one that started the session.
function setSessionCookie(res, sessionId) {
  res.setHeader('Set-Cookie', `sup_bind=${sessionId}; Max-Age=1800; Path=/; HttpOnly; Secure; SameSite=None`);
}
function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', `sup_bind=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=None`);
}
function getSessionCookie(req) {
  const header = req.headers.cookie;
  if (!header) return null;
  const hit = header.split(';').map(s => s.trim()).find(s => s.startsWith('sup_bind='));
  return hit ? decodeURIComponent(hit.slice('sup_bind='.length)) : null;
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

  // Server-side 12-hour lock: the page disables the button too, but the browser alone is never trusted.
  try {
    const rawRec = await redisCommand(['GET', 'supporter:' + deviceId]);
    const rec = rawRec ? JSON.parse(rawRec) : null;
    if (rec && isCurrentlyActive(rec)) {
      const left = rec.lastSupportAt + (rec.testCooldownMs || SUPPORT_WINDOW_MS) - Date.now();
      return res.status(429).json({ error: `Aaj ka support ho chuka hai. Agla support ${formatRemaining(left)} baad.`, retryAfterMs: left });
    }
  } catch (e) { /* Redis hiccup: don't block a real supporter */ }

  const sessionId = crypto.randomBytes(16).toString('hex');
  const token = signToken(sessionId);
  const callbackUrl = `${PUBLIC_BASE_URL}/api/support/callback?session=${sessionId}&token=${token}`;

  // Provider chosen from the bot (Settings → Set Shortlink Provider / /setshortlink). Any GPLinks-style provider works.
  // If the provider is down or the key is wrong, users get the built-in Custom Ad Task instead of being blocked,
  // and the owners get one DM (max every 30 min).
  const cfg = await getShortlinkConfig();
  let shortlink = null, providerUsed = 'custom';
  if (cfg.provider && cfg.provider !== 'custom') {
    try { shortlink = await shortenWithProvider(cfg, callbackUrl); providerUsed = cfg.provider; }
    catch (e) { console.error(`[shortlink] ${cfg.provider} failed:`, e.message); alertShortlinkProblem(cfg.provider, e.message); }
  }
  if (!shortlink) shortlink = customTaskLink(callbackUrl);

  // createdAt starts when the user actually gets the link, so the minimum-dwell check measures real time spent on the steps.
  await sessionSet(sessionId, { deviceId, createdAt: Date.now(), verified: false, verifiedAt: null, consumed: false, provider: providerUsed });
  setSessionCookie(res, sessionId);
  return res.json({ sessionId, shortlink });
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

  // ---- Same-browser check (the actual "direct link = 404" gate) ----
  // sup_bind was set on THIS browser the moment it called /api/support/start
  // for THIS exact session. If the cookie is present but points at a
  // DIFFERENT session, this definitely isn't that browser — someone opened
  // a resolved/shared/bypassed link cold, without ever starting the flow
  // here. Reject immediately, before wasting anyone's time on the
  // confirm-wait screen below.
  //
  // A MISSING cookie is NOT treated as proof of anything — some browsers
  // block this kind of cross-origin cookie outright, and a real supporter
  // must never be blocked for that (this is exactly the mistake the old
  // Referer-header check made). A missing cookie just falls through to the
  // normal flow; the localStorage check on the frontend is the fallback
  // net for that case.
  const boundSession = getSessionCookie(req);
  if (boundSession && boundSession !== session) {
    return res.status(404).send(`
      <html><body style="background:#08050f;color:#fff;font-family:sans-serif;text-align:center;padding-top:60px;">
        <h2>404 — Not Found</h2>
        <p>Yeh link is browser ka nahi hai.<br>Support Center se khud shuru karo.</p>
      </body></html>
    `);
  }

  const elapsedSeconds = (Date.now() - record.createdAt) / 1000;
  if (elapsedSeconds < MIN_DWELL_SECONDS) {
    return res.status(400).send('<h2>Steps completed too quickly — please try again.</h2>');
  }

  // ---- Basic bypass-tool defense ----
  // The session ID + signed token + minimum-dwell-time checks above defeat
  // generic bypass tools that only know how to jump to a fixed final URL.
  // They do NOT defeat a "link-resolver" bot that a person pastes the real
  // shortlink into: that kind of bot actually visits the shortlink provider
  // itself (often from its own server, faster than a human would need to),
  // then hands back the genuine resulting URL — which still carries a valid
  // signature and a real elapsed time, so the checks above pass either way.
  // We can't tell that apart from here; the second gate below (CONFIRM) is
  // what actually raises the bar against that pattern — see its comment.
  const userAgent = (req.headers['user-agent'] || '').toLowerCase();
  const looksLikeScript = /python|curl|wget|axios|okhttp|go-http-client|node-fetch|postman|scrapy/.test(userAgent);

  if (looksLikeScript) {
    return res.status(404).send(`
      <html><body style="background:#08050f;color:#fff;font-family:sans-serif;text-align:center;padding-top:60px;">
        <h2>404 — Not Found</h2>
        <p>Steps complete karke hi is link tak pahunch sakte ho.<br>Seedha yeh link kholna allowed nahi hai — bahut jaldi aa gaye ho 😉</p>
      </body></html>
    `);
  }

  // Don't credit yet — only record that the shortlink leg passed, and send
  // the browser to a short confirmation step hosted on OUR OWN domain.
  record.gplinksAt = Date.now();
  await sessionSet(session, record);

  const confirmUrl = `${PUBLIC_BASE_URL}/api/support/confirm?session=${session}&token=${token}`;
  res.send(`
    <html><head><meta name="viewport" content="width=device-width, initial-scale=1"></head>
    <body style="background:#08050f;color:#fff;font-family:sans-serif;text-align:center;padding-top:60px;">
      <h2>✅ Almost done!</h2>
      <p>Ek aakhri step — button ${CONFIRM_DELAY_SECONDS} second me apne aap ready ho jayega.</p>
      <a id="go" href="${confirmUrl}" style="display:inline-block;margin-top:18px;padding:13px 26px;border-radius:10px;
        background:#3a3550;color:#8a8299;text-decoration:none;font-weight:600;pointer-events:none;transition:background .2s,color .2s;">
        Wait… <span id="n">${CONFIRM_DELAY_SECONDS}</span>s
      </a>
      <script>
        let n = ${CONFIRM_DELAY_SECONDS};
        const el = document.getElementById('go'), num = document.getElementById('n');
        const t = setInterval(() => {
          n--;
          if (n <= 0) {
            clearInterval(t);
            el.style.pointerEvents = 'auto'; el.style.background = '#ff3d8a'; el.style.color = '#fff';
            el.textContent = '✅ Confirm & Continue';
          } else { num.textContent = n; }
        }, 1000);
      </script>
    </body></html>
  `);
});

// ---------------------------------------------------------------------------
// CONFIRM — the second gate, reached only via the button on the page above.
// A generic public "link-bypass bot" (built to automate well-known shortlink
// providers like GPLinks) has no reason to know this endpoint exists, let
// alone drive a real browser through its JS-gated button — so this
// specifically raises the bar against exactly the pattern reported: pasting
// the shortlink into a resolver bot and opening the result. It won't stop a
// determined attacker who scripts OUR site specifically, but that is a much
// higher bar than using an off-the-shelf public bypass bot.
// ---------------------------------------------------------------------------
app.get('/api/support/confirm', async (req, res) => {
  const { session, token } = req.query;
  const record = await sessionGet(session);

  if (!record || !verifyTokenSignature(session, token) || !record.gplinksAt) {
    return res.status(400).send('<h2>Invalid or expired support link.</h2>');
  }
  if ((Date.now() - record.gplinksAt) / 1000 < CONFIRM_DELAY_SECONDS) {
    return res.status(400).send('<h2>Too fast — please use the button on the previous page.</h2>');
  }

  record.verified = true;
  record.verifiedAt = Date.now();
  await sessionSet(session, record);
  clearSessionCookie(res);

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
  if (!record) return res.json({ ok: false, error: 'Session not found' });

  // Dwell-time check: If user completed the steps on raysfinvidya via Google Search
  // (where query tokens get stripped) and spent >= 30 seconds on the tasks, mark verified!
  const elapsed = (Date.now() - record.createdAt) / 1000;
  if (!record.verified && elapsed >= 25) {
    record.verified = true;
    record.verifiedAt = Date.now();
  }

  if (!record.verified) return res.json({ ok: false, error: 'Not verified' });
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

// ---------------------------------------------------------------------------
// TELEGRAM WEBHOOK — handles incoming DMs to the bot. When someone messages
// the bot privately (e.g. /start), it checks whether they've ever supported
// (via their stable supporter:tg_<id> record) and nudges them with a joke +
// a Support Now button if not, or thanks them with their stats if they have.
// One-time setup after each deploy: visit GET /api/telegram/setup-webhook.
// ---------------------------------------------------------------------------
const NUDGE_JOKES = [
  "Bhai itni mehnat toh tu reels scroll karne me kar leta hai 😄 yeh toh sirf 3 minute ka kaam hai!",
  "Free me itna premium content chahiye aur 3 minute nahi de sakta? 😂 Chal, ho jaa shuru!",
  "Tera thumb itna busy rehta hai scrolling me, 3 min isko bhi de de yaar 🙏",
  "Itna toh tu load hone ka wait karne me time de deta hai bhai 😅 3 min lagayega toh kya chala jayega?",
  "Support karne me itni sharam kaisi — WiFi password maangne me toh nahi aati 😄",
  "Tu itna type kar raha hai bina support kiye — dil toota mera 💔 3 min de de yaar",
  "Bina support kiye baat karna? Bhai yeh toh 'bina ticket movie dekhna' wali baat ho gayi 🎬😂",
  "Chal jhooti mohabbat chhod, asli support kar 3 minute me 💪",
  "Group me sab kaam karte hai, tu sirf message karta hai? Chal thoda support bhi kar de 😅",
  "3 minute — itne me toh tu ek reel dekh ke bhool bhi jata hai. Yahan permanent credit milega bhai!",
];

// Special taunts reserved for admins who message without supporting.
function mainMenuKeyboard(isAdmin) {
  const siteUrl = process.env.FRONTEND_URL || process.env.PUBLIC_BASE_URL;
  const rows = [
    [{ text: '📊 My Stats', callback_data: 'my_stats' }, { text: '🏆 Leaderboard', callback_data: 'leaderboard' }],
    [{ text: '👥 Community Stats', callback_data: 'community_stats' }],
    [{ text: '🗂️ Browse Vault', callback_data: 'browse_menu' }],
  ];
  if (isAdmin) {
    rows.push([{ text: '🛠 Control Panel (/panel)', callback_data: 'panel:home' }]);
    rows.push([{ text: '🌐 Web Admin Panel', url: siteUrl + '/admin' }]);
    rows.push([{ text: '🔍 /check kaise use karu?', callback_data: 'check_help' }]);
  }
  rows.push([{ text: '🚀 Support Now', url: siteUrl }]);
  return { inline_keyboard: rows };
}

function backKeyboard() {
  return { inline_keyboard: [[{ text: '🔙 Back to Menu', callback_data: 'menu' }]] };
}

// ---------------------------------------------------------------------------
// Shared card builders — used by both the inline-menu buttons (My Stats /
// Leaderboard) AND the /mystatus /top10 slash commands, so the two entry
// points can never show different-looking output for the same data.
// ---------------------------------------------------------------------------
async function buildMyStatsCard(userId) {
  let supporter = null;
  try { const raw = await redisCommand(['GET', 'supporter:tg_' + userId]); supporter = raw ? JSON.parse(raw) : null; } catch (e) {}

  let text, showSupportBtn = false;
  if (supporter && supporter.totalDays) {
    let rank = '-', total = 0;
    try {
      const all = await fetchAllSupporters();
      all.sort((a, b) => (b.totalDays || 0) - (a.totalDays || 0));
      total = all.length;
      const idx = all.findIndex(s => s._key === 'supporter:tg_' + userId);
      rank = idx >= 0 ? idx + 1 : '-';
    } catch (e) {}

    const active = isCurrentlyActive(supporter);
    showSupportBtn = !active;
    const statusLine = active
      ? '🟢  <b>Active</b> — aaj ka support ho chuka hai'
      : `🟡  <b>Expired</b> — ${hoursAgo(supporter.lastSupportAt)} ghante pehle support kiya tha, dobara karo`;

    const premium = isPremiumSupporter(supporter);
    const toGo = Math.max(0, PREMIUM_STREAK_DAYS - (supporter.streak || 0));
    const premiumLine = premium
      ? '👑  <b>Premium unlocked</b> — Forward Bot se premium content chalu hai'
      : `🔒  Premium ${toGo} din aur (lagataar) — ${streakBar(supporter.streak || 0, PREMIUM_STREAK_DAYS)}`;

    const d = supporter.totalDays || 0;
    const userLvl = d >= 100 ? 8 : d >= 75 ? 7 : d >= 50 ? 6 : d >= 30 ? 5 : d >= 15 ? 4 : d >= 7 ? 3 : d >= 3 ? 2 : (d >= 1 ? 1 : 0);
    const titles = {
      0: 'Newbie',
      1: 'Recruit Sahyogi',
      2: 'Apprentice Sadasya',
      3: 'Streak Warrior',
      4: 'Elite Guardian',
      5: 'Channel Guardian',
      6: 'Grandmaster VIP (Maha Yoddha)',
      7: 'Mythic Titan',
      8: 'Immortal Legend'
    };
    const userTitle = titles[userLvl] || 'VIP Member';
    const xp = d * 100 + ((supporter.streak || 0) > 7 ? (supporter.streak - 7) * 20 : 0);

    text =
      `👑  <b>Royal VIP Supporter Card</b>\n` +
      `────────────────────\n` +
      `🎖️  <b>Level ${userLvl}:</b> ${userTitle}\n` +
      `⚡  <b>Power XP:</b> ${xp.toLocaleString()} XP\n` +
      `${statusLine}\n\n` +
      `🔥  Streak:      <b>${supporter.streak || 0} din</b> (Fire Streak)\n` +
      `🏆  Rank:        <b>#${rank}</b> of ${total} supporters\n\n` +
      `${premiumLine}`;
  } else {
    showSupportBtn = true;
    text =
      `👑  <b>Royal VIP Supporter Card</b>\n` +
      `────────────────────\n` +
      `Tumne abhi tak support nahi kiya hai.\n\n` +
      `Support karke apna Level badhao, Power XP kamao, aur ${PREMIUM_STREAK_DAYS} din lagataar support karke 👑 <b>Premium</b> unlock karo!`;
  }

  const rows = [[{ text: '🔄 Refresh', callback_data: 'my_stats' }]];
  if (showSupportBtn) rows.unshift([{ text: '🚀 Support Now', url: process.env.FRONTEND_URL || process.env.PUBLIC_BASE_URL }]);
  rows.push([{ text: '🔙 Back to Menu', callback_data: 'menu' }]);
  return { text, keyboard: { inline_keyboard: rows } };
}

async function buildLeaderboardCard(period) {
  period = period || 'all';
  const labels = { all: 'All-time', week: 'Is Hafte', month: 'Is Mahine' };
  let text = `🏆  <b>Top 10 Supporters</b>  ·  ${labels[period]}\n────────────────────\n`;
  try {
    const all = await fetchAllSupporters();
    const scored = all
      .map(s => ({ s, score: periodScore(s, period) }))
      .filter(x => period === 'all' || x.score > 0)
      .sort((a, b) => b.score - a.score);

    if (!scored.length) {
      text += period === 'all'
        ? 'Abhi koi supporter nahi hai — pehla naam tumhara ho sakta hai!'
        : 'Is period me abhi koi support nahi hai — sabse pehle tum ban sakte ho!';
    } else {
      const unit = period === 'all' ? 'din total' : period === 'week' ? 'is hafte' : 'is mahine';
      scored.slice(0, 10).forEach(({ s, score }, i) => {
        const crown = isPremiumSupporter(s) ? ' 👑' : '';
        const count = period === 'all' ? (s.totalDays || 0) : score;
        text += `${medal(i)}  <b>${esc(s.name || 'Supporter')}</b>${crown}\n` +
                `     ${count} ${unit}  ·  🔥 ${s.streak || 0} streak\n`;
      });
    }
  } catch (e) { text += 'Data load nahi ho paya, dobara try karo.'; }

  const per = (p, label) => ({ text: (p === period ? '• ' : '') + label, callback_data: 'leaderboard:' + p });
  return {
    text,
    keyboard: {
      inline_keyboard: [
        [per('all', 'All-time'), per('week', 'Is Hafte'), per('month', 'Is Mahine')],
        [{ text: '🔄 Refresh', callback_data: 'leaderboard:' + period }],
        [{ text: '🔙 Back to Menu', callback_data: 'menu' }],
      ]
    }
  };
}

// Cached for a few seconds so a burst of taps on "Top 10" / "My Stats" (or
// several people opening the leaderboard around the same moment) doesn't
// each trigger a fresh full scan — only the first request in that window
// pays the cost, everyone right behind it gets the cached result.
let _supportersCache = null, _supportersCacheAt = 0;
const SUPPORTERS_CACHE_MS = 8000;

async function fetchAllSupporters() {
  if (_supportersCache && (Date.now() - _supportersCacheAt) < SUPPORTERS_CACHE_MS) {
    return _supportersCache;
  }
  const keys = await redisCommand(['KEYS', 'supporter:tg_*']);
  let all = [];
  if (keys && keys.length) {
    // One MGET for every record instead of one GET per supporter — the
    // previous version did N sequential round trips to Upstash, which is
    // exactly what made the leaderboard and rank lookups feel slow as the
    // supporter count grew. This is the same fix already applied to the
    // website's own batch-read endpoint.
    const values = await redisCommand(['MGET', ...keys]);
    (values || []).forEach((raw, i) => {
      if (!raw) return;
      try { const rec = JSON.parse(raw); rec._key = keys[i]; all.push(rec); } catch (e) {}
    });
  }
  _supportersCache = all;
  _supportersCacheAt = Date.now();
  return all;
}
function invalidateSupportersCache() { _supportersCache = null; }

/* ---- Weekly / monthly windows — mirrors the same logic in index.html so
   the bot's "/top10 — is hafte" and the website's "Is hafte" tab always
   agree on exactly which day the week/month flipped, regardless of the
   server's own timezone (Render runs in UTC). Nothing needs to be reset by
   hand — once the calendar rolls over, the window itself has moved. */
function istNow() { return new Date(Date.now() + 5.5 * 60 * 60 * 1000); }
function istDayKeyOf(d) { return d.getUTCFullYear() + '-' + String(d.getUTCMonth() + 1).padStart(2, '0') + '-' + String(d.getUTCDate()).padStart(2, '0'); }
function weekKeyOf(dateStr) {
  const [y, m, d] = dateStr.split('-').map(Number);
  const dt = new Date(Date.UTC(y, m - 1, d));
  const dow = (dt.getUTCDay() + 6) % 7; // Mon=0..Sun=6
  dt.setUTCDate(dt.getUTCDate() - dow);
  return istDayKeyOf(dt);
}
function currentWeekKey() {
  const now = istNow();
  const dow = (now.getUTCDay() + 6) % 7;
  now.setUTCDate(now.getUTCDate() - dow);
  return istDayKeyOf(now);
}
/** The Monday of the week that JUST ENDED — used the moment a new week
 *  starts to figure out "who won last week", since currentWeekKey() at
 *  that point only has 0-1 days of data in it. */
function previousWeekKey() {
  const cur = currentWeekKey();
  const [y, m, d] = cur.split('-').map(Number);
  const dt = new Date(Date.UTC(y, m - 1, d));
  dt.setUTCDate(dt.getUTCDate() - 7);
  return istDayKeyOf(dt);
}
function currentMonthKey() { const n = istNow(); return n.getUTCFullYear() + '-' + String(n.getUTCMonth() + 1).padStart(2, '0'); }
function countForWeek(supportDates) { const cur = currentWeekKey(); return (supportDates || []).filter(ds => weekKeyOf(ds) === cur).length; }
function countForMonth(supportDates) { const cur = currentMonthKey(); return (supportDates || []).filter(ds => ds.slice(0, 7) === cur).length; }
function periodScore(s, period) {
  if (period === 'week') return countForWeek(s.supportDates);
  if (period === 'month') return countForMonth(s.supportDates);
  return s.totalDays || 0;
}

async function checkIsAdmin(userId, chatId) {
  if (!userId || !process.env.TELEGRAM_BOT_TOKEN) return false;

  // 1. Check Owner/Admin from Redis 'admins'
  try {
    const raw = await redisCommand(['GET', 'admins']);
    if (raw) {
      const a = JSON.parse(raw);
      if (String(a.ownerId) === String(userId)) return true;
      if (Array.isArray(a.list) && a.list.some(x => String(x.id || x) === String(userId))) return true;
    }
  } catch (e) {}

  // 2. Check CONTENT_OWNER_IDS env
  const owners = (process.env.CONTENT_OWNER_IDS || '').split(',').map(s => s.trim()).filter(Boolean);
  if (owners.includes(String(userId))) return true;

  // 2b. Permanent owners + admins added through Panel -> Admins Management (Redis set cb:admins).
  //     Without this, an admin added from the panel could never open /panel.
  try { if (await cbIsAdmin(userId)) return true; } catch (e) {}

  // 3. Check current chat admin status if provided
  if (chatId) {
    try {
      const r = await fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/getChatMember?chat_id=${encodeURIComponent(chatId)}&user_id=${userId}`);
      const d = await r.json();
      if (d.ok && (d.result.status === 'administrator' || d.result.status === 'creator')) return true;
    } catch (e) {}
  }

  // 4. Check fallback chats (COMMUNITY_CHAT_ID, TELEGRAM_CHAT_ID, TELEGRAM_NOTIFY_CHAT_ID)
  const fallbackChats = [process.env.COMMUNITY_CHAT_ID, process.env.TELEGRAM_CHAT_ID, process.env.TELEGRAM_NOTIFY_CHAT_ID].filter(Boolean);
  for (const c of fallbackChats) {
    try {
      const r = await fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/getChatMember?chat_id=${encodeURIComponent(c)}&user_id=${userId}`);
      const d = await r.json();
      if (d.ok && (d.result.status === 'administrator' || d.result.status === 'creator')) return true;
    } catch (e) {}
  }
  return false;
}

// ---------------------------------------------------------------------------
// SHORTLINK PROVIDER — configurable live via bot DM (no redeploy needed).
// Works with any GPLinks-style provider: GET {apiUrl}?api={key}&url={target}
// returning JSON with a "shortenedUrl" or "short_url" field.
// ---------------------------------------------------------------------------
// Presets so you can type just the name. ANY other GPLinks-style provider works too: /setshortlink <name> <apiKey> <https://their-api-url>
const KNOWN_PROVIDERS = {
  gplinks: 'https://api.gplinks.com/api',
  vplink: 'https://vplink.in/api',
  shrinkme: 'https://shrinkme.io/api',
  shrinkearn: 'https://shrinkearn.com/api',
  droplink: 'https://droplink.co/api',
  arolinks: 'https://arolinks.com/api',
  linkshortify: 'https://linkshortify.com/api',
};
const CUSTOM_TASK_BASE = process.env.CUSTOM_TASK_URL || 'https://raysfinvidya.pages.dev/?step=1';
const customTaskLink = (callbackUrl) => `${CUSTOM_TASK_BASE}${CUSTOM_TASK_BASE.includes('?') ? '&' : '?'}ret=${encodeURIComponent(callbackUrl)}`;

async function getShortlinkConfig() {
  try {
    const raw = await redisCommand(['GET', 'shortlink_config']);
    if (raw) return JSON.parse(raw);
  } catch (e) { /* fall through to env-based default below */ }
  // Nothing saved yet: GPLinks only if its key is in the env, otherwise the built-in Custom Ad Task.
  return process.env.GPLINKS_API_KEY
    ? { provider: 'gplinks', apiKey: process.env.GPLINKS_API_KEY, apiUrl: process.env.GPLINKS_API_URL || KNOWN_PROVIDERS.gplinks }
    : { provider: 'custom', apiKey: '', apiUrl: '' };
}
const maskKey = (k) => (k ? (k.length > 8 ? k.slice(0, 4) + '••••' + k.slice(-3) : '••••') : '(not set)');

// Asks the provider for a short link: GET {apiUrl}?api={key}&url={target}. Understands the common reply shapes
// (JSON with shortenedUrl / short_url / ..., or a bare URL as plain text). The API key never appears in error text.
async function shortenWithProvider(cfg, target) {
  if (!cfg || !cfg.apiKey || !cfg.apiUrl) throw new Error('API key ya API URL set nahi hai');
  const hide = (m) => String(m || '').split(cfg.apiKey).join('***').slice(0, 160);
  const url = `${cfg.apiUrl}${cfg.apiUrl.includes('?') ? '&' : '?'}api=${encodeURIComponent(cfg.apiKey)}&url=${encodeURIComponent(target)}`;
  let text;
  try {
    const r = await fetch(url, { timeout: 8000, headers: { 'User-Agent': 'Mozilla/5.0 (compatible; ChannelSupportBot/1.0)', Accept: 'application/json,text/plain,*/*' } });
    if (r.status >= 500) throw new Error(`provider HTTP ${r.status}`);
    text = await r.text();
  } catch (e) { throw new Error(hide(e.message || e)); }
  let j = null; try { j = JSON.parse(text); } catch (_) { /* maybe plain text */ }
  let short = null;
  if (j && typeof j === 'object') {
    if (/^(error|fail)/i.test(String(j.status || ''))) throw new Error(hide(j.message || j.msg || j.error || 'provider ne error diya'));
    const d = j.data && typeof j.data === 'object' ? j.data : {};
    short = j.shortenedUrl || j.shortened_url || j.short_url || j.shortUrl || j.result_url || j.link || j.url || d.shortenedUrl || d.short_url || d.url || null;
  } else if (/^https?:\/\/\S+$/i.test(String(text).trim())) short = String(text).trim();
  if (!short || !/^https?:\/\/\S+$/i.test(String(short)) || short === target) throw new Error('provider ne short link nahi diya (API key / domain approval check karo)');
  return String(short);
}
let _lastShortlinkAlert = 0;
function alertShortlinkProblem(provider, reason) {   // at most one DM per 30 minutes
  if (Date.now() - _lastShortlinkAlert < 30 * 60 * 1000) return;
  _lastShortlinkAlert = Date.now();
  for (const oid of cbOwnerIds()) tgSendText(oid, `⚠️ <b>Shortlink (${esc(provider)}) fail ho raha hai</b>\n${esc(reason)}\n\nUsers ko abhi <b>Custom Ad Task</b> (fallback) mil raha hai.\nAPI key / URL check karo ya Panel → Settings → 🧪 Test Shortlink chalao.`, { parse_mode: 'HTML' }).catch(() => {});
}
// One place for "/setshortlink ..." and the panel prompt. parts = [provider, apiKey, apiUrl?]
async function applyShortlinkSetting(parts) {
  const first = (parts[0] || '').toLowerCase();
  if (first === 'custom' || first === 'ads') {
    await setShortlinkConfig({ provider: 'custom', apiKey: '', apiUrl: '' });
    return { ok: true, text: '✅ Provider: <b>Custom Ad Task</b>\nUsers ab seedha ad-task portal se support karenge (koi shortlink nahi).' };
  }
  const presets = Object.keys(KNOWN_PROVIDERS).join(', ');
  if (parts.length < 2) return { ok: false, text: `Format: <code>&lt;provider&gt; &lt;apiKey&gt; [apiUrl]</code>\nPreset names: <code>${presets}</code>\nKoi bhi aur provider: <code>myprov KEY https://api.myprov.com/api</code>\nWapas ad-task: <code>custom</code>` };
  const provider = parts[0].toLowerCase(), apiKey = parts[1], apiUrl = parts[2] || KNOWN_PROVIDERS[provider];
  if (!/^[a-z0-9_-]{2,20}$/.test(provider)) return { ok: false, text: '❌ Provider ka naam sirf a-z, 0-9, - ya _ (2–20 akshar) ho sakta hai.' };
  if (apiKey.length < 6) return { ok: false, text: '❌ API key bahut chhoti lag rahi hai — poori key paste karo.' };
  if (!apiUrl) return { ok: false, text: `❌ <b>${esc(provider)}</b> ka API URL pata nahi. Poora URL bhi do:\n<code>${esc(provider)} KEY https://api.example.com/api</code>\nPresets: <code>${presets}</code>` };
  if (!/^https:\/\/[^\s]+$/i.test(apiUrl)) return { ok: false, text: '❌ API URL <code>https://</code> se shuru hona chahiye.' };
  const cfg = { provider, apiKey, apiUrl };
  await setShortlinkConfig(cfg);
  let test;
  try { test = `🧪 Test OK — short link bana: <code>${esc(await shortenWithProvider(cfg, `${PUBLIC_BASE_URL}/api/support/callback?session=test&token=test`))}</code>`; }
  catch (e) { test = `⚠️ Save ho gaya, par test fail: ${esc(e.message)}\nTab tak users ko fallback (Custom Ad Task) milega.`; }
  return { ok: true, text: `✅ Shortlink provider set: <b>${esc(provider)}</b>\nAPI URL: <code>${esc(apiUrl)}</code>\nKey: <code>${maskKey(apiKey)}</code>\n\n${test}\n\n<i>Agle support-attempt se yahi use hoga — redeploy nahi chahiye.</i>` };
}
async function setShortlinkConfig(cfg) {
  await redisCommand(['SET', 'shortlink_config', JSON.stringify(cfg)]);
}

// ---------------------------------------------------------------------------
// GLOBAL FREE-PASS — temporarily suspends the "must support" requirement
// everywhere that checks it (community chat gate + the /api/support/status-check
// endpoint that a connected content-bot relies on), without touching anyone's
// individual streak/support data.
// ---------------------------------------------------------------------------
function parseDuration(str) {
  const m = /^(\d+)\s*(d|h|m)$/i.exec((str || '').trim());
  if (!m) return null;
  const n = parseInt(m[1], 10);
  const unit = m[2].toLowerCase();
  const mult = unit === 'd' ? 24 * 60 * 60 * 1000 : unit === 'h' ? 60 * 60 * 1000 : 60 * 1000;
  return n * mult;
}
async function isGlobalFreePassActive() {
  try {
    const until = await redisCommand(['GET', 'global_free_pass_until']);
    return !!until && Date.now() < parseInt(until, 10);
  } catch (e) { return false; }
}
async function getGlobalFreePassUntil() {
  try {
    const until = await redisCommand(['GET', 'global_free_pass_until']);
    return until ? parseInt(until, 10) : null;
  } catch (e) { return null; }
}
function formatRemaining(ms) {
  if (ms <= 0) return '0m';
  const totalMin = Math.ceil(ms / 60000);
  const d = Math.floor(totalMin / 1440);
  const h = Math.floor((totalMin % 1440) / 60);
  const m = totalMin % 60;
  return [d ? d + 'd' : '', h ? h + 'h' : '', m ? m + 'm' : ''].filter(Boolean).join(' ') || '0m';
}

// ---------------------------------------------------------------------------
// Handles owner/admin-only DM commands. Returns true if the message WAS one
// of these commands (caller should stop processing), false otherwise.
// ---------------------------------------------------------------------------
async function shortlinkTestText(cfg) {
  if (!cfg.provider || cfg.provider === 'custom') return '🧪 Abhi <b>Custom Ad Task</b> active hai — test karne ke liye koi provider set nahi. <code>/setshortlink gplinks KEY</code> se provider jodo.';
  try { return `🧪 <b>${esc(cfg.provider)}</b> OK ✅\nShort link bana: <code>${esc(await shortenWithProvider(cfg, `${PUBLIC_BASE_URL}/api/support/callback?session=test&token=test`))}</code>`; }
  catch (e) { return `🧪 <b>${esc(cfg.provider)}</b> FAIL ❌\n${esc(e.message)}\n\nUsers ko abhi fallback (Custom Ad Task) mil raha hai.`; }
}
// ---------------------------------------------------------------------------
// GROUP REMINDER — the "Pehle support karo 👇 [Support Now]" reply the bot gives non-supporters who write in the
// community's General topic. Controls:
//   • ON/OFF switch  (/nudge on | off  ·  Panel → Settings → 💬 Group Reminder)
//   • per-user cooldown: one user gets AT MOST one reminder per N minutes (default 30)  (/nudge cooldown 45)
// Redis: nudge_enabled ('0' = off, default ON) · nudge_cooldown_min · nudge_cd:<userId> (expires by itself)
// ---------------------------------------------------------------------------
const NUDGE_DEFAULT_COOLDOWN_MIN = 30, NUDGE_MAX_COOLDOWN_MIN = 1440;
async function nudgeSettings() {
  let enabled = true, cooldownMin = NUDGE_DEFAULT_COOLDOWN_MIN;
  try {
    enabled = (await redisCommand(['GET', 'nudge_enabled'])) !== '0';
    const n = parseInt(await redisCommand(['GET', 'nudge_cooldown_min']), 10);
    if (n >= 1 && n <= NUDGE_MAX_COOLDOWN_MIN) cooldownMin = n;
  } catch (e) { /* defaults */ }
  return { enabled, cooldownMin };
}
function nudgeStatusText(st) {
  return `💬 <b>Group Reminder</b> (“Pehle support karo 👇”)\nStatus: <b>${st.enabled ? 'ON ✅' : 'OFF ⛔'}</b>\nCooldown: <b>${st.cooldownMin} min</b> — ek user ko itne time me sirf ek reminder\n\n<code>/nudge on</code> · <code>/nudge off</code> · <code>/nudge cooldown 45</code> · <code>/nudge status</code>`;
}
// words = what follows "/nudge". Returns the reply text (HTML).
async function nudgeApply(words) {
  const sub = String(words[0] || 'status').toLowerCase();
  if (sub === 'on') { await redisCommand(['DEL', 'nudge_enabled']); return '✅ Group reminder <b>ON</b> ho gaya.\n\n' + nudgeStatusText(await nudgeSettings()); }
  if (sub === 'off') { await redisCommand(['SET', 'nudge_enabled', '0']); return '⛔ Group reminder <b>OFF</b> — ab bot group me kisi ko "support karo" nahi bolega.\n\n' + nudgeStatusText(await nudgeSettings()); }
  if (sub === 'cooldown') {
    const n = /^\d{1,5}$/.test(String(words[1] || '')) ? parseInt(words[1], 10) : NaN;
    if (!(n >= 1 && n <= NUDGE_MAX_COOLDOWN_MIN)) return `⚠️ Cooldown 1 se ${NUDGE_MAX_COOLDOWN_MIN} minute ke beech ka number hona chahiye.\nExample: <code>/nudge cooldown 45</code>`;
    await redisCommand(['SET', 'nudge_cooldown_min', String(n)]);
    return `⏱ Cooldown <b>${n} min</b> set ho gaya.\n\n` + nudgeStatusText(await nudgeSettings());
  }
  if (sub === 'status') return nudgeStatusText(await nudgeSettings());
  return nudgeStatusText(await nudgeSettings());
}
const nudgeAllowed = async (userId) => { try { return await cbIsAdmin(userId); } catch (e) { return false; } }; // owners + panel-added admins

async function handleOwnerCommand(text, userId, msgId) {
  const lower = text.toLowerCase();

  if (lower === '/shortlinkstatus') {
    const cfg = await getShortlinkConfig();
    await tgSendText(userId, `🔗 <b>Current Shortlink Provider</b>\n\nProvider: <code>${esc(cfg.provider)}</code>\nAPI URL: <code>${esc(cfg.apiUrl || '(custom ad task)')}</code>\nAPI Key: <code>${maskKey(cfg.apiKey)}</code>`, { parse_mode: 'HTML' });
    return true;
  }

  if (/^\/nudge(@\S+)?(\s|$)/.test(lower)) {
    if (!(await nudgeAllowed(userId))) { await tgSendText(userId, '❌ Ye command sirf Owner / panel-admin ke liye hai.'); return true; }
    await tgSendText(userId, await nudgeApply(text.split(/\s+/).slice(1)), { parse_mode: 'HTML' });
    return true;
  }

  if (lower === '/testshortlink') {
    await tgSendText(userId, await shortlinkTestText(await getShortlinkConfig()), { parse_mode: 'HTML' });
    return true;
  }

  if (lower.startsWith('/setshortlink')) {
    // /setshortlink <provider> <apiKey> [apiUrl]   |   /setshortlink custom
    const words = text.split(/\s+/);
    const r = await applyShortlinkSetting(words.slice(1));
    await tgSendText(userId, r.text, { parse_mode: 'HTML' });
    if (r.ok && msgId && words.length > 2) tgDeleteMsgIn(userId, msgId); // that message contains the API key
    return true;
  }

  if (lower.startsWith('/freepass')) {
    const arg = text.split(/\s+/)[1];
    if (!arg) {
      await tgSendText(userId, `Usage: /freepass <duration>  ya  /freepass off\n\nExamples: /freepass 1d  (1 din)\n/freepass 12h  (12 ghante)\n/freepass 30m  (30 minute)\n/freepass off  (turant band karo)`);
      return true;
    }
    if (arg.toLowerCase() === 'off') {
      await redisCommand(['DEL', 'global_free_pass_until']);
      await tgSendText(userId, `✅ Free-pass band kar diya — support requirement wapas ON hai.`);
      return true;
    }
    const durationMs = parseDuration(arg);
    if (!durationMs) {
      await tgSendText(userId, `❌ Format samajh nahi aaya. Try: /freepass 1d ya /freepass 12h ya /freepass 30m`);
      return true;
    }
    const until = Date.now() + durationMs;
    await redisCommand(['SET', 'global_free_pass_until', String(until)]);
    await tgSendText(userId, `✅ Free-pass ON kar diya — agle ${formatRemaining(durationMs)} tak KISI KO bhi support karne ki zaroorat nahi hai. Community chat aur connected content-bot dono is dauran kuch nahi poochenge.\n\nJaldi band karna ho toh: /freepass off`);
    return true;
  }

  if (lower === '/freepassstatus') {
    const until = await getGlobalFreePassUntil();
    if (!until || Date.now() >= until) {
      await tgSendText(userId, `ℹ️ Abhi koi free-pass active nahi hai — support requirement normal hai.`);
    } else {
      await tgSendText(userId, `✅ Free-pass active hai — ${formatRemaining(until - Date.now())} baaki hai.`);
    }
    return true;
  }

  if (lower.startsWith('/testcooldown')) {
    // Sirf CALLER (admin) ke apne account ka support-cooldown chhota karta
    // hai — 12h wait kiye bina baar-baar support→streak→cooldown poora
    // cycle test kar sako. Baaki sabka cooldown normal 12h hi rehta hai.
    const arg = text.split(/\s+/)[1];
    const key = 'supporter:tg_' + userId;

    if (!arg) {
      await tgSendText(userId, `Usage: /testcooldown <duration>  ya  /testcooldown off\\n\\nSirf TUMHARE apne account ka cooldown chhota kar deta hai (testing ke liye) — baaki sabka 12 ghante wala hi rehta hai.\\n\\nExamples: /testcooldown 2m\\n/testcooldown off  (wapas normal 12h)`);
      return true;
    }

    if (arg.toLowerCase() === 'off') {
      try {
        const raw = await redisCommand(['GET', key]);
        if (raw) {
          const rec = JSON.parse(raw);
          delete rec.testCooldownMs;
          await redisCommand(['SET', key, JSON.stringify(rec)]);
          invalidateSupportersCache();
        }
      } catch (e) {}
      await tgSendText(userId, `✅ Test-cooldown band — ab tumhara bhi normal 12 ghante wala cooldown hai.`);
      return true;
    }

    const durationMs = parseDuration(arg);
    if (!durationMs) {
      await tgSendText(userId, `❌ Format samajh nahi aaya. Try: /testcooldown 2m ya /testcooldown 1h`);
      return true;
    }

    try {
      const raw = await redisCommand(['GET', key]);
      const rec = raw ? JSON.parse(raw) : { name: 'Admin', streak: 0, totalDays: 0, supportDates: [], lastSupportAt: null, firstSupportAt: null };
      rec.testCooldownMs = durationMs;
      await redisCommand(['SET', key, JSON.stringify(rec)]);
      invalidateSupportersCache();
      await tgSendText(userId, `✅ Sirf tumhare liye cooldown ${formatRemaining(durationMs)} kar diya — support complete karke turant (${formatRemaining(durationMs)} baad) dobara test kar sakte ho.\\n\\nBand karne ke liye: /testcooldown off`);
    } catch (e) {
      await tgSendText(userId, `❌ Save nahi ho paya — dobara try karo.`);
    }
    return true;
  }

  return false;
}

// Cooldown window — must match the frontend's COOLDOWN_MS (12 hours in production).
const SUPPORT_WINDOW_MS = 12 * 60 * 60 * 1000;

function isCurrentlyActive(supporter) {
  if (!supporter || !supporter.lastSupportAt) return false;
  // Per-account override, set via /testcooldown — lets ONE admin test the
  // full support→streak→cooldown cycle in minutes instead of real 12h,
  // without touching the real cooldown for anyone else.
  const window = supporter.testCooldownMs || SUPPORT_WINDOW_MS;
  return (Date.now() - supporter.lastSupportAt) < window;
}

function hoursAgo(ts) {
  if (!ts) return null;
  return Math.floor((Date.now() - ts) / (60 * 60 * 1000));
}

async function buildWelcomeText(userId) {
  let supporter = null;
  try { const raw = await redisCommand(['GET', 'supporter:tg_' + userId]); supporter = raw ? JSON.parse(raw) : null; } catch (e) {}

  if (await isGlobalFreePassActive()) {
    const until = await getGlobalFreePassUntil();
    return `🎉 Abhi free-pass chal raha hai — koi support nahi chahiye!\n⏳ ${formatRemaining(until - Date.now())} baaki hai.`;
  }

  if (!isCurrentlyActive(supporter)) {
    const joke = NUDGE_JOKES[Math.floor(Math.random() * NUDGE_JOKES.length)];
    const staleNote = (supporter && supporter.totalDays)
      ? `\n\n(Pichla support ${hoursAgo(supporter.lastSupportAt)} ghante pehle tha — ab dobara karna hoga)`
      : '';
    return `👋 Abhi support active nahi hai!${staleNote}\n\n${joke}\n\nBas 3 minute ki baat hai — neeche se dekho 👇`;
  }
  return `✅ Tumhara support abhi active hai!\n🔥 Streak: ${supporter.streak} din\n📅 Total: ${supporter.totalDays} din\n${isPremiumSupporter(supporter) ? '👑 Premium unlocked!' : `🔒 Premium ke liye ${Math.max(0, PREMIUM_STREAK_DAYS - (supporter.streak || 0))} din aur`}\n\nThanks for the support! 🙌`;
}

function tgSend(chatId, text, replyMarkup, parseMode) {
  return fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ chat_id: chatId, text, reply_markup: replyMarkup, parse_mode: parseMode })
  }).catch(() => {});
}

// Edits a message in place. Certificate previews are PHOTO messages, and Telegram refuses editMessageText on those
// ("there is no text in the message to edit") — that is exactly why the Back / Cards Menu / Panel Home buttons under
// a certificate preview did nothing. In that case the photo is replaced by a fresh text message instead.
async function tgEdit(chatId, messageId, text, replyMarkup, parseMode) {
  const post = (method, body) => fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/${method}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
  }).then(r => r.json()).catch(() => null);
  const r = await post('editMessageText', { chat_id: chatId, message_id: messageId, text, reply_markup: replyMarkup, parse_mode: parseMode });
  if (r && r.ok) return r;
  const desc = (r && r.description) || '';
  if (/not modified/i.test(desc)) return r; // same content tapped twice — nothing to do
  if (/no text in the message|message to edit not found|message can't be edited/i.test(desc)) {
    tgDeleteMsgIn(chatId, messageId);
    return post('sendMessage', { chat_id: chatId, text, reply_markup: replyMarkup, parse_mode: parseMode });
  }
  if (desc) console.error('[tgEdit] failed:', desc);
  return r;
}

// Telegram HTML parse_mode only understands a handful of tags — anything a
// user's own name contains (&, <, >) has to be escaped or the API rejects
// the whole message and the bot silently "does nothing".
function esc(s) {
  return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
function medal(i) { return i === 0 ? '🥇' : i === 1 ? '🥈' : i === 2 ? '🥉' : `#${i + 1}`; }
function streakBar(streak, goal) {
  const filled = Math.max(0, Math.min(goal, streak));
  return '🟩'.repeat(filled) + '⬜'.repeat(Math.max(0, goal - filled));
}

// =============================================================================
// CONTENT BOT (merged from "Forward Bot") — file vault, search, /tv /phone
// /filter, admin upload, broadcast. Same bot (TELEGRAM_BOT_TOKEN), same
// webhook, just a different feature set. Needs these extra env vars:
//   CONTENT_GROUP_CHAT_ID   — group where /tv /phone are typed
//   VAULT_CHANNEL_ID        — channel where files are stored/auto-indexed
//   CONTENT_OWNER_IDS       — comma-separated Telegram IDs, permanent owners
// =============================================================================

const CATEGORY_LABELS = { tv: '📺 Android TV', phone: '📱 Phone', live_tv: '📡 Live TV' };
const DELETE_AFTER_SECONDS = 120;

const _DEVICE_TV_PATTERNS = [/android\s*tv/i, /smart\s*tv/i, /fire\s*tv/i, /firestick/i, /google\s*tv/i, /set[- ]?top\s*box/i, /\bstb\b/i];
const _GENERIC_TV_PATTERN = /\btv\b/i;
const _VERSION_PATTERN = /[vV]?\d+(?:\.\d+){1,6}/;
const _EXTENSION_PATTERN = /\.\w{2,4}$/;
const _PAREN_PATTERN = /\([^)]*\)/g;
const _PUNCT_PATTERN = /[_\-+]+/g;
const _NOISE_WORDS = new Set(['android', 'arm64v8', 'arm64', 'arm', 'armv7', 'x86', 'x64', 'apk', 'app', 'mod', 'official', 'premium', 'pro', 'new', 'latest', 'update', 'version', 'beta', 'full', 'cracked', 'patched', 'unlocked']);

function categorize(name, caption) {
  const titleLine = (caption || '').trim().split('\n')[0] || '';
  const text = `${name || ''} ${titleLine}`;
  if (_DEVICE_TV_PATTERNS.some(p => p.test(text))) return 'tv';
  if (_GENERIC_TV_PATTERN.test(text)) return 'live_tv';
  return 'phone';
}
function extractVersion(name) {
  const m = _VERSION_PATTERN.exec(name || '');
  if (!m) return 'Latest';
  let v = m[0];
  if (!v.toLowerCase().startsWith('v')) v = 'v' + v;
  return v;
}
function extractBaseKeyword(name) {
  let text = (name || '').toLowerCase();
  text = text.replace(_EXTENSION_PATTERN, '');
  text = text.replace(_PAREN_PATTERN, ' ');
  text = text.replace(_VERSION_PATTERN, ' ');
  text = text.replace(_PUNCT_PATTERN, ' ');
  return text.split(/\s+/).filter(w => w && !_NOISE_WORDS.has(w)).join(' ').trim();
}

// ---- Storage (Redis) ----
async function cbNextId(seqKey) {
  return await redisCommand(['INCR', seqKey]);
}
async function cbAddFile(fileUniqueId, fileId, fileName, fileType, caption, category) {
  // Dedup by file_unique_id (Telegram's stable ID for the underlying media)
  const existingKeys = await redisCommand(['KEYS', 'cbfile:*']);
  for (const k of (existingKeys || [])) {
    const raw = await redisCommand(['GET', k]);
    if (raw && JSON.parse(raw).fileUniqueId === fileUniqueId) return null; // already indexed
  }
  const id = await cbNextId('cbfile_seq');
  const rec = { id, fileUniqueId, fileId, fileName, fileType, caption: caption || '', category: category || 'phone', addedAt: Date.now() };
  await redisCommand(['SET', 'cbfile:' + id, JSON.stringify(rec)]);
  return rec;
}
async function cbAllFiles() {
  const keys = await redisCommand(['KEYS', 'cbfile:*']);
  let out = [];
  for (const k of (keys || [])) {
    const raw = await redisCommand(['GET', k]);
    if (raw) out.push(JSON.parse(raw));
  }
  return out;
}
async function cbSearchFilesAll(query, category) {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (!words.length) return [];
  const all = await cbAllFiles();
  return all.filter(f => {
    const hay = (f.fileName + ' ' + (f.caption || '')).toLowerCase();
    if (!words.every(w => hay.includes(w))) return false;
    if (category && f.category !== category) return false;
    return true;
  }).sort((a, b) => b.id - a.id);
}
async function cbGetFileById(id) {
  const raw = await redisCommand(['GET', 'cbfile:' + id]);
  return raw ? JSON.parse(raw) : null;
}
async function cbDeleteFilesByName(query) {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (!words.length) return 0;
  const all = await cbAllFiles();
  let count = 0;
  for (const f of all) {
    const hay = (f.fileName + ' ' + (f.caption || '')).toLowerCase();
    if (words.every(w => hay.includes(w))) {
      await redisCommand(['DEL', 'cbfile:' + f.id]);
      count++;
    }
  }
  return count;
}
async function cbCountByCategory(category) {
  const all = await cbAllFiles();
  return all.filter(f => f.category === category).length;
}
async function cbListItemsByCategories(categories, offset, limit) {
  const all = await cbAllFiles();
  let combined = all.filter(f => categories.includes(f.category)).map(f => ({ tag: 'F' + f.id, name: f.fileName, category: f.category }));
  combined.sort((a, b) => a.name.toLowerCase().localeCompare(b.name.toLowerCase()));
  return { page: combined.slice(offset, offset + limit), total: combined.length };
}
async function cbAddUser(userId, username) {
  await redisCommand(['SADD', 'cb:users', String(userId)]);
  await redisCommand(['SET', 'cbuser:' + userId, JSON.stringify({ userId, username, firstSeen: Date.now() })]);
}
async function cbGetAllUserIds() {
  return (await redisCommand(['SMEMBERS', 'cb:users'])) || [];
}
function cbOwnerIds() {
  const envOwners = (process.env.CONTENT_OWNER_IDS || '').split(',').map(s => s.trim()).filter(Boolean);
  const defaultOwners = ['8928458677', '5839998019']; // Vishal & his friend (permanent owners)
  return Array.from(new Set([...envOwners, ...defaultOwners]));
}
async function cbIsAdmin(userId) {
  if (cbOwnerIds().includes(String(userId))) return true;
  return !!(await redisCommand(['SISMEMBER', 'cb:admins', String(userId)]));
}
async function cbAddAdmin(userId) { await redisCommand(['SADD', 'cb:admins', String(userId)]); }
async function cbRemoveAdmin(userId) { await redisCommand(['SREM', 'cb:admins', String(userId)]); }
async function cbGetDynamicAdmins() { return (await redisCommand(['SMEMBERS', 'cb:admins'])) || []; }
async function cbLogRequest(matched) {
  await redisCommand(['INCR', 'cb:log_total']);
  if (matched) await redisCommand(['INCR', 'cb:log_matched']);
}
async function cbGetStats() {
  const total = parseInt((await redisCommand(['GET', 'cb:log_total'])) || '0', 10);
  const matched = parseInt((await redisCommand(['GET', 'cb:log_matched'])) || '0', 10);
  return { total, matched };
}

// ---- Telegram send helpers ----
async function tgSendFile(chatId, rec, extra) {
  const method = { photo: 'sendPhoto', video: 'sendVideo', animation: 'sendAnimation' }[rec.fileType] || 'sendDocument';
  const fieldName = { photo: 'photo', video: 'video', animation: 'animation' }[rec.fileType] || 'document';
  const body = { chat_id: chatId, caption: rec.caption || rec.fileName, [fieldName]: rec.fileId, ...extra };
  const r = await fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/${method}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
  });
  return r.json();
}
async function tgDeleteMsgIn(chatId, messageId) {
  return fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/deleteMessage`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ chat_id: chatId, message_id: messageId })
  }).catch(() => {});
}
function cbScheduleDelete(chatId, messageId, delaySec = DELETE_AFTER_SECONDS) {
  setTimeout(() => tgDeleteMsgIn(chatId, messageId), delaySec * 1000);
}
async function tgSendText(chatId, text, extra) {
  const r = await fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ chat_id: chatId, text, ...extra })
  });
  return r.json();
}

// Delivers content to a user's private chat; returns {delivered, dmBlocked, displayName}
async function deliverContent(targetUserId, query, category) {
  const results = await cbSearchFilesAll(query, category);
  if (!results.length) return { delivered: false, dmBlocked: false };
  const rec = results[0]; // best/most-recent match
  const data = await tgSendFile(targetUserId, rec);
  if (!data.ok) {
    const blocked = /blocked|deactivated|not found/i.test(data.description || '');
    return { delivered: false, dmBlocked: blocked, displayName: rec.fileName };
  }
  return { delivered: true, dmBlocked: false, displayName: rec.fileName };
}
async function deliverSpecific(targetUserId, tag) {
  if (!tag.startsWith('F')) return { success: false, error: 'Unknown item type' };
  const rec = await cbGetFileById(tag.slice(1));
  if (!rec) return { success: false, error: 'Item mil nahi paya (delete ho chuka hoga).' };
  const data = await tgSendFile(targetUserId, rec);
  if (!data.ok) {
    const blocked = /blocked|deactivated|not found/i.test(data.description || '');
    return { success: false, displayName: rec.fileName, error: blocked ? 'Pehle bot ko /start karo.' : (data.description || 'Send fail hua.') };
  }
  return { success: true, displayName: rec.fileName };
}

function cbBrowseKeyboard(items, category, page, totalPages) {
  const rows = items.map(it => [{ text: it.name.length > 40 ? it.name.slice(0, 37) + '…' : it.name, callback_data: `get:${it.tag}` }]);
  const nav = [];
  if (page > 0) nav.push({ text: '⬅️ Prev', callback_data: `browse:${category}:${page - 1}` });
  if (page < totalPages - 1) nav.push({ text: 'Next ➡️', callback_data: `browse:${category}:${page + 1}` });
  if (nav.length) rows.push(nav);
  rows.push([{ text: '🔙 Categories', callback_data: 'browse_menu' }]);
  return { inline_keyboard: rows };
}

const CONTENT_PAGE_SIZE = 8;

function gateMessage() {
  const siteUrl = process.env.FRONTEND_URL || process.env.PUBLIC_BASE_URL;
  return `⚠️ Pehle channel ko support karo, tabhi content milega!\n👉 ${siteUrl}`;
}
async function hasSupportedTelegram(userId) {
  try {
    const raw = await redisCommand(['GET', 'supporter:tg_' + userId]);
    return isCurrentlyActive(raw ? JSON.parse(raw) : null);
  } catch (e) { return false; }
}

// Returns true if this message WAS a content-bot command (caller should stop
// processing it further); false if it wasn't one (caller falls through to
// the normal support-bot routing below).
async function handleContentCommand(msg) {
  const text = msg.text.trim();
  const chatId = msg.chat.id;
  const userId = msg.from.id;
  const isGroupContext = String(chatId) === String(process.env.CONTENT_GROUP_CHAT_ID);

  // ---- /start deep link: /start tv_netflix or /start phone_whatsapp ----
  if (/^\/start(@\S+)?(\s|$)/i.test(text)) {
    const payload = text.split(/\s+/)[1];
    if (payload && payload.includes('_')) {
      const [category, ...rest] = payload.split('_');
      const query = rest.join(' ').trim();
      if (CATEGORY_LABELS[category] && query) {
        await cbAddUser(userId, msg.from.username || msg.from.first_name || 'unknown');
        if (!(await cbIsAdmin(userId)) && !(await hasSupportedTelegram(userId))) {
          await tgSendText(chatId, gateMessage());
          return true;
        }
        const result = await deliverContent(userId, query, category);
        await cbLogRequest(result.delivered);
        if (!result.delivered) await tgSendText(chatId, `❌ '${query}' ${CATEGORY_LABELS[category]} Vault me nahi mila.`);
        return true;
      }
    }
    return false; // plain /start — let the support-bot's own welcome menu handle it
  }

  // ---- /tv <query>, /phone <query> ----
  const catMatch = text.match(/^\/(tv|phone)(@\S+)?\s+(.+)/i);
  if (catMatch) {
    const category = catMatch[1].toLowerCase();
    const query = catMatch[3].trim();
    await cbAddUser(userId, msg.from.username || msg.from.first_name || 'unknown');

    if (!(await cbIsAdmin(userId)) && !(await hasSupportedTelegram(userId))) {
      const gateMsg = gateMessage();
      if (isGroupContext) {
        const sent = await tgSendText(chatId, gateMsg, { reply_to_message_id: msg.message_id });
        if (sent.ok) cbScheduleDelete(chatId, sent.result.message_id);
        cbScheduleDelete(chatId, msg.message_id);
      } else {
        await tgSendText(chatId, gateMsg);
      }
      return true;
    }

    const result = await deliverContent(userId, query, category);
    await cbLogRequest(result.delivered);

    if (isGroupContext) {
      let replyText;
      if (result.delivered) replyText = `✅ ${result.displayName} sent to your Private Chat!`;
      else if (result.dmBlocked) replyText = `⚠️ Pehle mujhe DM me /start karo, phir dobara try karo.`;
      else replyText = `❌ '${query}' ${CATEGORY_LABELS[category]} Vault me nahi mila.`;
      const sent = await tgSendText(chatId, replyText, { reply_to_message_id: msg.message_id });
      if (sent.ok) cbScheduleDelete(chatId, sent.result.message_id);
      cbScheduleDelete(chatId, msg.message_id);
    } else {
      if (result.dmBlocked) await tgSendText(chatId, 'Pehle /start karo.');
      else if (!result.delivered) await tgSendText(chatId, `❌ '${query}' ${CATEGORY_LABELS[category]} Vault me nahi mila.`);
    }
    return true;
  }

  // ---- /filter — category picker ----
  if (/^\/filter(@\S+)?(\s|$)/i.test(text)) {
    await tgSendText(chatId, `🔎 Category choose karo:`, {
      reply_markup: { inline_keyboard: [
        [{ text: '📱 Phone', callback_data: 'browse:phone:0' }, { text: '📡 Live TV', callback_data: 'browse:live_tv:0' }],
        [{ text: '📺 Android TV', callback_data: 'browse:tv:0' }],
      ] }
    });
    return true;
  }

  // ---- Everything below is ADMIN-ONLY (silently ignored for non-admins) ----
  const isAdminHere = await cbIsAdmin(userId);

  if (/^\/search(@\S+)?\s+/i.test(text)) {
    if (!isAdminHere) return true;
    const rest = text.replace(/^\/search(@\S+)?\s+/i, '').trim();
    const parts = rest.split(/\s+/);
    let category = null;
    if (['tv', 'phone', 'live_tv'].includes((parts[parts.length - 1] || '').toLowerCase())) category = parts.pop().toLowerCase();
    const query = parts.join(' ');
    const results = await cbSearchFilesAll(query, category);
    if (!results.length) { await tgSendText(chatId, `❌ '${query}' ke liye kuch nahi mila.`); return true; }
    const buttons = results.slice(0, 20).map(f => [{ text: f.fileName.length > 45 ? f.fileName.slice(0, 42) + '…' : f.fileName, callback_data: `get:F${f.id}` }]);
    await tgSendText(chatId, `🔎 ${results.length} result(s) mile '${query}' ke liye.\n👇 Tap karo jo bhejwana hai:`, { reply_markup: { inline_keyboard: buttons } });
    return true;
  }

  if (/^\/vault(@\S+)?(\s|$)/i.test(text)) {
    if (!isAdminHere) return true;
    const all = await cbAllFiles();
    const tv = all.filter(f => f.category === 'tv').length;
    const phone = all.filter(f => f.category === 'phone').length;
    const liveTv = all.filter(f => f.category === 'live_tv').length;
    await tgSendText(chatId, `🗄️ Vault Stats\n\n📦 Total: ${all.length}\n📺 Android TV: ${tv}\n📱 Phone: ${phone}\n📡 Live TV: ${liveTv}`);
    return true;
  }

  if (/^\/filecount(@\S+)?(\s|$)/i.test(text)) {
    if (!isAdminHere) return true;
    await tgSendText(chatId, `📦 Total files in Vault: ${(await cbAllFiles()).length}`);
    return true;
  }

  if (/^\/listfiles(@\S+)?(\s|$)/i.test(text)) {
    if (!isAdminHere) return true;
    const all = (await cbAllFiles()).sort((a, b) => b.id - a.id).slice(0, 100);
    const listText = all.length ? all.map((f, i) => `${i + 1}. ${f.fileName} [${f.category}]`).join('\n') : 'Vault khaali hai.';
    await tgSendText(chatId, `📋 Latest Files:\n\n${listText}`);
    return true;
  }

  if (/^\/removefile(@\S+)?\s+/i.test(text)) {
    if (!isAdminHere) return true;
    const query = text.replace(/^\/removefile(@\S+)?\s+/i, '').trim();
    const count = await cbDeleteFilesByName(query);
    await tgSendText(chatId, count ? `🗑️ ${count} file(s) delete ho gayi.` : `❌ '${query}' se match karti koi file nahi mili.`);
    return true;
  }

  if (/^\/addadmin(@\S+)?\s+/i.test(text)) {
    if (!cbOwnerIds().includes(String(userId))) return true; // owner-only
    const targetId = text.replace(/^\/addadmin(@\S+)?\s+/i, '').trim();
    await cbAddAdmin(targetId);
    await tgSendText(chatId, `✅ ${targetId} ko admin bana diya.`);
    return true;
  }

  if (/^\/removeadmin(@\S+)?\s+/i.test(text)) {
    if (!cbOwnerIds().includes(String(userId))) return true;
    const targetId = text.replace(/^\/removeadmin(@\S+)?\s+/i, '').trim();
    await cbRemoveAdmin(targetId);
    await tgSendText(chatId, `✅ ${targetId} ko admin se hata diya.`);
    return true;
  }

  if (/^\/adminlist(@\S+)?(\s|$)/i.test(text)) {
    if (!isAdminHere) return true;
    const dynamic = await cbGetDynamicAdmins();
    await tgSendText(chatId, `👑 Owners:\n${cbOwnerIds().join('\n') || '-'}\n\n🛡️ Admins:\n${dynamic.join('\n') || '-'}`);
    return true;
  }

  if (/^\/broadcast(@\S+)?\s+/i.test(text)) {
    if (!isAdminHere) return true;
    const broadcastText = text.replace(/^\/broadcast(@\S+)?\s+/i, '');
    const userIds = await cbGetAllUserIds();
    let sent = 0, failed = 0;
    for (const uid of userIds) {
      try { const r = await tgSendText(uid, broadcastText); if (r.ok) sent++; else failed++; }
      catch (e) { failed++; }
      await new Promise(r => setTimeout(r, 60));
    }
    await tgSendText(chatId, `📢 Broadcast done!\n✅ Sent: ${sent}\n❌ Failed: ${failed}`);
    return true;
  }

  if (/^\/stats(@\S+)?(\s|$)/i.test(text)) {
    if (!isAdminHere) return true;
    const { total, matched } = await cbGetStats();
    await tgSendText(chatId, `📊 Content Bot Stats\n\n👤 Users: ${(await cbGetAllUserIds()).length}\n📨 Total Requests: ${total}\n✅ Matched: ${matched}`);
    return true;
  }

  return false;
}

// =============================================================================
// ADMIN CONTROL PANEL (Forward_Bot Style)
// =============================================================================

const panelPending = new Map(); // userId -> { action, ts, sectionKey }
const PANEL_PENDING_TTL = 5 * 60 * 1000; // 5 minutes

function panelHeader(icon, title, subtitle) {
  let s = `${icon ? icon + ' ' : ''}<b>${title}</b>`;
  if (subtitle) s += `\n<i>${subtitle}</i>`;
  return s + '\n━━━━━━━━━━━━━━━━━━━━';
}

function panelHomeText(firstName, isOwner) {
  const role = isOwner ? 'Owner 👑' : 'Admin 🛡️';
  return [
    panelHeader('🛠', 'CONTROL PANEL', `${esc(firstName || 'Admin')}  ·  ${role}`),
    'Bot aur Channel Support ka sabhi control yahin se manage karo.',
    'Koi bhi section choose karo 👇'
  ].join('\n');
}

function panelSectionText(title, subtitle) {
  return panelHeader('', title, subtitle) + '\n👇 Ek action chuno:';
}

function panelPromptText(title, instruction) {
  return [
    panelHeader('✍️', title),
    instruction,
    '',
    '<i>Agla message bhejo · 5 min me expire hoga</i>'
  ].join('\n');
}

const _PANEL_SECTIONS = {
  cert: {
    title: '🎖️ CERTIFICATES (CARDS)',
    sub: 'Silver, Gold & Diamond cards — upload from here, no site visit needed',
    ownerOnly: false,
    buttons: [
      [{ label: '🥈 Silver', kind: 's', action: 'cert_silver' }, { label: '🥇 Gold', kind: 's', action: 'cert_gold' }, { label: '💎 Diamond', kind: 's', action: 'cert_platinum' }],
      [{ label: '🎆 Festival Sets (1-tap switch + schedule)', kind: 'set', action: 'list' }],
      [{ label: '📝 Draft Mode (on/off)', kind: 'do', action: 'cert_draft_toggle' }, { label: '📣 Announce Cards', kind: 'do', action: 'cert_announce' }],
      [{ label: '💾 Backup Cards', kind: 'do', action: 'cert_backup' }, { label: '📥 Restore Backup', kind: 'ask', action: 'restore_backup' }],
      [{ label: 'ℹ️ Cards Status', kind: 'do', action: 'cert_status' }, { label: '♻️ Restore Default Cards', kind: 'do', action: 'restore_default_certs' }],
    ]
  },
  stats: {
    title: '📊 STATS & MONETIZATION',
    sub: 'Supporter analytics, vault & ad status',
    ownerOnly: false,
    buttons: [
      [{ label: '👥 Community Stats', kind: 'do', action: 'comm_stats' }, { label: '📦 Vault Stats', kind: 'do', action: 'vault_stats' }],
      [{ label: '🔗 Shortlink / Ads Config', kind: 'do', action: 'shortlink_stats' }, { label: '🏆 Top Supporters', kind: 'do', action: 'top_supporters' }],
    ]
  },
  broadcast: {
    title: '📢 BROADCAST',
    sub: 'Sabhi bot users ko direct message bhejo',
    ownerOnly: false,
    buttons: [
      [{ label: '📢 New Broadcast Message', kind: 'ask', action: 'broadcast' }],
    ]
  },
  access: {
    title: '🔑 ACCESS & PASS',
    sub: 'Grants, free-pass & user verification',
    ownerOnly: false,
    buttons: [
      [{ label: '🔓 Free-Pass Status', kind: 'do', action: 'freepass_status' }, { label: '⛔ Stop Free-Pass', kind: 'do', action: 'freepass_off' }],
      [{ label: '➕ Set Free-Pass', kind: 'ask', action: 'freepass_set' }, { label: '🩺 Check User', kind: 'ask', action: 'check_user' }],
      [{ label: '⏱️ Test Cooldown (Self)', kind: 'ask', action: 'test_cooldown' }],
    ]
  },
  admins: {
    title: '👥 ADMINS MANAGEMENT',
    sub: 'Bot & panel permissions',
    ownerOnly: true,
    buttons: [
      [{ label: '👥 Admin List', kind: 'do', action: 'admin_list' }],
      [{ label: '➕ Add Admin', kind: 'ask', action: 'add_admin' }, { label: '➖ Remove Admin', kind: 'ask', action: 'remove_admin' }],
    ]
  },
  settings: {
    title: '🎨 SETTINGS & SYSTEM',
    sub: 'Themes, target topic & provider setup',
    ownerOnly: false,
    buttons: [
      [{ label: '🎭 Set Season Theme', kind: 'ask', action: 'set_season' }],
      [{ label: '📍 Support Topic Status', kind: 'do', action: 'topic_status' }],
      [{ label: '💬 Group Reminder (on/off)', kind: 'do', action: 'nudge_toggle' }, { label: '⏱ Reminder Cooldown', kind: 'ask', action: 'nudge_cooldown' }],
      [{ label: '🔗 Set Shortlink Provider', kind: 'ask', action: 'set_shortlink' }, { label: '🧪 Test Shortlink', kind: 'do', action: 'shortlink_test' }],
    ]
  },
  vault: {
    title: '🗄️ CONTENT VAULT',
    sub: 'Browse, search & manage indexed files',
    ownerOnly: false,
    buttons: [
      [{ label: '📋 Vault Summary', kind: 'do', action: 'vault_summary' }, { label: '🔎 Search Vault', kind: 'ask', action: 'search_vault' }],
      [{ label: '🗑 Remove File', kind: 'ask', action: 'remove_file' }],
    ]
  }
};

for (const t of ['silver', 'gold', 'platinum']) {
  const m = { silver: ['🥈', 'Silver'], gold: ['🥇', 'Gold'], platinum: ['💎', 'Diamond'] }[t];
  _PANEL_SECTIONS['cert_' + t] = {
    title: `${m[0]} ${m[1].toUpperCase()} CARD`,
    sub: 'Template, text position & live preview',
    ownerOnly: false,
    back: 'cert',
    buttons: [
      [{ label: `🧪 Test ${m[1]}`, kind: 'do', action: `test_cert:${t}` }, { label: '📤 Update Template', kind: 'ask', action: `upload_cert:${t}` }],
      [{ label: '📐 Adjust Text Position', kind: 'lay', action: `${t}:name:sel:1` }, { label: '🧭 Layout Guide', kind: 'do', action: `cert_guide:${t}` }],
      [{ label: '📝 Draft', kind: 'draft', action: `${t}:open` }, { label: '🕘 History', kind: 'hist', action: `${t}:list` }],
      [{ label: '↩️ Undo Last Update', kind: 'do', action: `cert_undo:${t}` }, { label: '🗂 Use GitHub File', kind: 'do', action: `cert_pkg:${t}` }],
    ]
  };
}

const _PANEL_HOME_ORDER = [
  ['cert', 'stats'],
  ['broadcast', 'access'],
  ['settings', 'vault'],
  ['admins']
];

function panelHomeKeyboard(isOwner) {
  const rows = [];
  for (const pair of _PANEL_HOME_ORDER) {
    const row = [];
    for (const key of pair) {
      const sec = _PANEL_SECTIONS[key];
      if (sec.ownerOnly && !isOwner) continue;
      row.push({ text: sec.title.split(' ')[0] + ' ' + sec.title.split(' ').slice(1).join(' '), callback_data: `panel:s:${key}` });
    }
    if (row.length) rows.push(row);
  }
  rows.push([{ text: '🔙 Back to Menu', callback_data: 'menu' }]);
  return { inline_keyboard: rows };
}

function panelSectionKeyboard(sectionKey) {
  const sec = _PANEL_SECTIONS[sectionKey];
  const rows = [];
  if (sec && sec.buttons) {
    for (const rowBtns of sec.buttons) {
      rows.push(rowBtns.map(b => ({
        text: b.label,
        callback_data: `panel:${b.kind}:${b.action}`
      })));
    }
  }
  rows.push([sec && sec.back
    ? { text: '⬅️ Back to Cards', callback_data: `panel:s:${sec.back}` }
    : { text: '⬅️ Back to Panel', callback_data: 'panel:home' }]);
  return { inline_keyboard: rows };
}

function panelPromptKeyboard(sectionKey) {
  return {
    inline_keyboard: [
      [{ text: '❌ Cancel', callback_data: `panel:s:${sectionKey}` }]
    ]
  };
}

const _PANEL_ASK = {
  'restore_backup': {
    title: 'RESTORE CARDS BACKUP',
    instruction: '<b>cards-backup-....json.gz</b> file bhejo (jo 💾 Backup Cards ne diya tha) — File/Document ki tarah.\n\n⚠️ Backup ke live cards aur saare sets wapas aa jayenge. Pehle wale live cards ki History me copy bachti hai.',
    ownerOnly: true,
    section: 'cert'
  },
  'upload_cert:silver': {
    title: 'UPLOAD SILVER CARD',
    instruction: 'Naye <b>Silver Certificate</b> ki blank template image bhejo (naam/numbers ke bina).\n\n📎 <b>Best quality:</b> image ko <b>File / Document</b> ki tarah bhejo (📎 → File). Photo ki tarah bhejoge to Telegram compress kar dega — phir bhi chalega.\n📐 16:9 image best hai (jaise 1672×941 ya 1024×576).\nBot template save karke live preview dikhayega; text sahi jagah na ho to wahin se adjust kar sakte ho.',
    section: 'cert_silver'
  },
  'upload_cert:gold': {
    title: 'UPLOAD GOLD CARD',
    instruction: 'Naye <b>Gold Certificate</b> ki blank template image bhejo (naam/numbers ke bina).\n\n📎 <b>Best quality:</b> image ko <b>File / Document</b> ki tarah bhejo (📎 → File). Photo ki tarah bhejoge to Telegram compress kar dega — phir bhi chalega.\n📐 16:9 image best hai (jaise 1672×941 ya 1024×576).\nBot template save karke live preview dikhayega; text sahi jagah na ho to wahin se adjust kar sakte ho.',
    section: 'cert_gold'
  },
  'upload_cert:platinum': {
    title: 'UPLOAD DIAMOND CARD',
    instruction: 'Naye <b>Diamond Certificate</b> ki blank template image bhejo (naam/numbers ke bina).\n\n📎 <b>Best quality:</b> image ko <b>File / Document</b> ki tarah bhejo (📎 → File). Photo ki tarah bhejoge to Telegram compress kar dega — phir bhi chalega.\n📐 16:9 image best hai (jaise 1672×941 ya 1024×576).\nBot template save karke live preview dikhayega; text sahi jagah na ho to wahin se adjust kar sakte ho.',
    section: 'cert_platinum'
  },
  'broadcast': {
    title: 'NEW BROADCAST',
    instruction: 'Jo message sabhi bot users ko broadcast karna hai wo type karke bhejo.\nHTML tags allowed hain.',
    section: 'broadcast'
  },
  'freepass_set': {
    title: 'GRANT FREE-PASS',
    instruction: 'Free-pass ka time duration bhejo.\nExample: <code>1d</code> (1 din), <code>12h</code> (12 ghante), <code>30m</code> (30 minute).',
    section: 'access'
  },
  'check_user': {
    title: 'CHECK USER',
    instruction: 'User ka <code>@username</code> ya numeric Telegram ID bhejo unka live support & streak dekhne ke liye.',
    section: 'access'
  },
  'test_cooldown': {
    title: 'TEST COOLDOWN',
    instruction: 'Sirf tumhare account ke liye test cooldown time bhejo (e.g. <code>2m</code>, <code>5m</code>) ya <code>off</code> likho normal 12h wapas karne ke liye.',
    section: 'access'
  },
  'add_admin': {
    title: 'ADD ADMIN',
    instruction: 'Naye admin ki numeric Telegram ID bhejo (e.g. <code>123456789</code>).',
    section: 'admins',
    ownerOnly: true
  },
  'remove_admin': {
    title: 'REMOVE ADMIN',
    instruction: 'Hataane wale admin ki numeric Telegram ID bhejo.',
    section: 'admins',
    ownerOnly: true
  },
  'set_season': {
    title: 'SET FESTIVAL SEASON',
    instruction: 'Active season theme ka naam bhejo:\n<code>normal</code> | <code>navratri</code> | <code>diwali</code>',
    section: 'settings'
  },
  'nudge_cooldown': {
    title: 'GROUP REMINDER COOLDOWN',
    instruction: 'Cooldown <b>minutes</b> me bhejo (1 se 1440).\nEk user ko itne time me sirf <b>ek</b> "support karo" reminder milega.\nExample: <code>30</code>',
    section: 'settings'
  },
  'set_shortlink': {
    title: 'SET SHORTLINK PROVIDER',
    instruction: 'Shortlink details bhejo:\nFormat: <code>&lt;provider&gt; &lt;apiKey&gt; [apiUrl]</code>\n\n• <code>gplinks YOUR_KEY</code>\n• Presets: <code>gplinks, vplink, shrinkme, shrinkearn, droplink, arolinks, linkshortify</code>\n• Koi bhi aur provider: <code>myprov KEY https://api.myprov.com/api</code>\n• Wapas ad-task: <code>custom</code>\n\n<i>Key wala message bot save karke delete kar dega.</i>',
    section: 'settings'
  },
  'search_vault': {
    title: 'SEARCH VAULT',
    instruction: 'Vault me file dhundhne ke liye app/file ka naam bhejo.',
    section: 'vault'
  },
  'remove_file': {
    title: 'REMOVE FILE FROM VAULT',
    instruction: 'File ka naam ya keyword bhejo jise delete karna hai.',
    section: 'vault'
  }
};

async function downloadTelegramFile(fileId) {
  const getFileUrl = `https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/getFile?file_id=${encodeURIComponent(fileId)}`;
  const r = await fetch(getFileUrl);
  const data = await r.json();
  if (!data.ok || !data.result || !data.result.file_path) {
    throw new Error((data && data.description) || 'Telegram se file info nahi mili');
  }
  const dlUrl = `https://api.telegram.org/file/bot${process.env.TELEGRAM_BOT_TOKEN}/${data.result.file_path}`;
  const res = await fetch(dlUrl);
  if (!res.ok) throw new Error(`Download fail hua (HTTP ${res.status})`);
  return await res.buffer();
}

// ---------------------------------------------------------------------------
// CERTIFICATE TEMPLATE STORE — templates + text layouts live in Redis, NOT on Render's disk
// (Render wipes the disk on every deploy/restart, which is why a template updated from the bot used to
// silently revert). Packaged files in assets/cert/ stay as the fallback.
//   certtpl:<tier>        base64 JPEG of the live template      certlayout:<tier>       JSON text layout (fractions)
//   certtpl_prev:<tier>   previous template (for Undo)          certlayout_prev:<tier>  previous layout
// ---------------------------------------------------------------------------
const CERT_TIERS = ['silver', 'gold', 'platinum'];
const CERT_META = {
  silver:   { icon: '🥈', label: 'Silver',   test: { days: 12, streak: 7 } },
  gold:     { icon: '🥇', label: 'Gold',     test: { days: 35, streak: 14 } },
  platinum: { icon: '💎', label: 'Diamond', test: { days: 85, streak: 25 } },
};
async function certGetStoredTemplate(tier) {
  const b64 = await redisCommand(['GET', 'certtpl:' + tier]);
  return b64 ? Buffer.from(b64, 'base64') : null;
}
async function certGetStoredLayout(tier) {
  const raw = await redisCommand(['GET', 'certlayout:' + tier]);
  return raw ? JSON.parse(raw) : null;
}
setCertProviders({ loadTemplate: certGetStoredTemplate, loadLayout: certGetStoredLayout });

function certCachesClear(tier) { clearTemplateCache(tier); _certCache.clear(); }

async function currentTemplateBuffer(tier) { // what is live right now: Redis override, else the packaged file
  try { const st = await certGetStoredTemplate(tier); if (st) return st; } catch (e) {}
  const f = path.join(__dirname, 'assets', 'cert', tier + '.png');
  return fs.existsSync(f) ? fs.readFileSync(f) : null;
}

// Saves a new template. If you had hand-tuned the text positions, the new template keeps them (so swapping in a same-style
// festival card needs no re-calibration); otherwise the right preset is chosen from the new image. Throws (and saves nothing as "success") if Redis rejects it.
async function saveCertificateTemplate(tier, imageBuffer) {
  const prep = await prepareTemplate(imageBuffer);          // decode + Redis-safe JPEG
  let layoutNow = null, keepLayout = false;
  try {
    const info = await templateInfo(tier);
    layoutNow = info.layout;
    keepLayout = info.layoutSource === 'custom';               // only a hand-tuned layout is carried over to the new image
  } catch (e) { /* no readable current card */ }
  await stashPrevious(tier, 'Upload');                         // Undo slot + history
  await redisCommand(['SET', 'certtpl:' + tier, prep.buffer.toString('base64')]);
  if (layoutNow && keepLayout) await redisCommand(['SET', 'certlayout:' + tier, JSON.stringify(layoutNow)]);
  else await redisCommand(['DEL', 'certlayout:' + tier]);  // untouched preset -> pick the right style for the NEW image size
  certCachesClear(tier);
  await syncActiveSet(tier);
  return prep;
}

async function undoCertificateTemplate(tier) {
  const prev = await redisCommand(['GET', 'certtpl_prev:' + tier]);
  if (!prev) return false;
  const prevLayout = await redisCommand(['GET', 'certlayout_prev:' + tier]);
  const cur = await redisCommand(['GET', 'certtpl:' + tier]);
  const curLayout = await redisCommand(['GET', 'certlayout:' + tier]);
  await redisCommand(['SET', 'certtpl:' + tier, prev]);                       // swap, so pressing Undo again = Redo
  if (prevLayout) await redisCommand(['SET', 'certlayout:' + tier, prevLayout]); else await redisCommand(['DEL', 'certlayout:' + tier]);
  if (cur) await redisCommand(['SET', 'certtpl_prev:' + tier, cur]); else await redisCommand(['DEL', 'certtpl_prev:' + tier]);
  if (curLayout) await redisCommand(['SET', 'certlayout_prev:' + tier, curLayout]); else await redisCommand(['DEL', 'certlayout_prev:' + tier]);
  certCachesClear(tier);
  await syncActiveSet(tier);
  return true;
}

async function restoreDefaultCertificates() {
  const dir = path.join(__dirname, 'assets', 'cert', 'defaults');
  const done = [];
  for (const t of CERT_TIERS) {
    const f = path.join(dir, t + '.png');
    if (!fs.existsSync(f)) continue;
    const prep = await prepareTemplate(fs.readFileSync(f));
    await redisCommand(['SET', 'certtpl:' + t, prep.buffer.toString('base64')]);
    await redisCommand(['DEL', 'certlayout:' + t]);
    done.push(t);
  }
  await redisCommand(['DEL', 'certset_active']);
  certCachesClear();
  return done;
}

async function certPreviewName(fromUser) {
  return [fromUser && fromUser.first_name, fromUser && fromUser.last_name].filter(Boolean).join(' ') || 'Admin Supporter';
}
async function sendCardPreview(chatId, tier, fromUser, caption, keyboard, highlight) {
  const t = CERT_META[tier].test;
  const img = await renderCertificate({ name: await certPreviewName(fromUser), totalDays: t.days, streak: t.streak, tier, issuedAt: Date.now(), highlight });
  return sendCertificatePhoto(chatId, img, caption, keyboard);
}
function certLayoutLabel(info) { return (info.preset === 'festival' ? 'Festival' : 'Classic') + (info.layoutSource === 'custom' ? ' (custom)' : ''); }
async function certTierStatusLine(tier) {
  try {
    const i = await templateInfo(tier);
    return `${CERT_META[tier].icon} <b>${CERT_META[tier].label}</b> — <code>${i.width}×${i.height}</code> · ${i.source === 'bot' ? 'bot upload' : 'default file'} · layout: ${certLayoutLabel(i)}`;
  } catch (e) { return `${CERT_META[tier].icon} <b>${CERT_META[tier].label}</b> — ❌ template nahi mila (${esc(e.message)})`; }
}

// ---- "Adjust text position" screen (one photo message, edited in place on every tap) ----
const LAY_FIELDS = { name: '👤 Name', days: '📅 Days', streak: '🔥 Streak' };
const TIER_LETTER = { silver: 's', gold: 'g', platinum: 'p' };
const LETTER_TIER = { s: 'silver', g: 'gold', p: 'platinum' };
function layKeyboard(tier, field, step, draft) {
  const sfx = draft ? ':d' : '';
  const d = (f, op, st) => `panel:lay:${tier}:${f}:${op}:${st}${sfx}`;
  const rows = [
    Object.keys(LAY_FIELDS).map(f => ({ text: (f === field ? '• ' : '') + LAY_FIELDS[f], callback_data: d(f, 'sel', step) })),
    [{ text: '⬅️', callback_data: d(field, 'l', step) }, { text: '⬆️', callback_data: d(field, 'u', step) }, { text: '⬇️', callback_data: d(field, 'd', step) }, { text: '➡️', callback_data: d(field, 'r', step) }],
    [{ text: '➖ Size', callback_data: d(field, 'm', step) }, { text: '➕ Size', callback_data: d(field, 'p', step) }, { text: step ? '🔍 Switch to Fine' : '📏 Switch to Coarse', callback_data: d(field, 'sel', step ? 0 : 1) }],
    [{ text: '🔄 Reset', callback_data: d(field, 'reset', step) }, { text: '🎆 Festival', callback_data: d(field, 'fest', step) }, { text: '🏛 Classic', callback_data: d(field, 'classic', step) }],
  ];
  // copy the text positions of another card (works when both templates follow the same layout, e.g. made from the Layout Guide)
  if (!draft) rows.push(CERT_TIERS.filter(t => t !== tier).map(t => ({ text: `📋 Copy ← ${CERT_META[t].icon} ${CERT_META[t].label}`, callback_data: d(field, 'cp' + TIER_LETTER[t], step) })));
  rows.push([{ text: '✅ Done', callback_data: draft ? `panel:draft:${tier}:open` : `panel:s:cert_${tier}` }]);
  return { inline_keyboard: rows };
}
function layCaption(tier, field, step, lay, draft) {
  const f = lay[field];
  return [
    `📐 <b>ADJUST TEXT — ${CERT_META[tier].label.toUpperCase()}${draft ? ' (DRAFT)' : ''}</b>`,
    `Selected: <b>${LAY_FIELDS[field]}</b>  ·  Step: <b>${step ? 'Coarse' : 'Fine'}</b>`,
    `x <code>${(f.cx * 100).toFixed(1)}%</code> · y <code>${(f.base * 100).toFixed(1)}%</code> · size <code>${(f.size * 100).toFixed(1)}%</code>`,
    '',
    '<i>Arrows se cyan box ko sahi jagah le jao, ➕/➖ se size badlo. Done dabane par guide box hat jayega.</i>',
  ].join('\n');
}
async function tgEditPhoto(chatId, messageId, buffer, caption, replyMarkup) {
  const form = new FormData();
  form.append('chat_id', String(chatId));
  form.append('message_id', String(messageId));
  form.append('media', JSON.stringify({ type: 'photo', media: 'attach://pic', caption, parse_mode: 'HTML' }));
  form.append('reply_markup', JSON.stringify(replyMarkup));
  form.append('pic', buffer, { filename: 'certificate.jpg', contentType: 'image/jpeg' });
  const r = await fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/editMessageMedia`, { method: 'POST', body: form, headers: form.getHeaders() });
  return r.json();
}
async function handleLayoutCallback(cb, arg) {
  const [tier, field0, op, stepStr, dflag] = String(arg).split(':');
  if (!CERT_TIERS.includes(tier)) return;
  const draft = dflag === 'd';
  const field = LAY_FIELDS[field0] ? field0 : 'name';
  const step = stepStr === '0' ? 0 : 1;
  const chatId = cb.message.chat.id, messageId = cb.message.message_id;

  const draftData = draft ? await certDraftInfo(tier) : null;
  if (draft && !draftData) { await tgSendText(chatId, '⚠️ Ye draft ab nahi hai (publish ya discard ho chuka).'); return; }
  const info = draft ? draftData : await templateInfo(tier);
  let lay = JSON.parse(JSON.stringify(info.layout));
  const mv = step ? 0.01 : 0.002, P = lay[field];
  const clamp = (v, a, b) => Math.min(b, Math.max(a, v));
  if (op === 'l') P.cx = clamp(P.cx - mv, 0, 1);
  else if (op === 'r') P.cx = clamp(P.cx + mv, 0, 1);
  else if (op === 'u') P.base = clamp(P.base - mv, 0, 1);
  else if (op === 'd') P.base = clamp(P.base + mv, 0, 1);
  else if (op === 'p') P.size = clamp(P.size * (step ? 1.06 : 1.015), 0.02, 0.25);
  else if (op === 'm') P.size = clamp(P.size / (step ? 1.06 : 1.015), 0.02, 0.25);
  else if (op === 'reset') lay = defaultLayout(tier, lay.preset === 'festival' ? 'festival' : 'classic');
  else if (op === 'fest') lay = defaultLayout(tier, 'festival');
  else if (op === 'classic') lay = defaultLayout(tier, 'classic');
  else if (!draft && /^cp[sgp]$/.test(op)) {
    const src = LETTER_TIER[op[2]];
    if (src && src !== tier) lay = JSON.parse(JSON.stringify((await templateInfo(src)).layout));
  }
  if (['l', 'r', 'u', 'd', 'p', 'm', 'reset', 'fest', 'classic', 'cps', 'cpg', 'cpp'].includes(op)) {
    for (const k of ['name', 'days', 'streak']) for (const q of ['cx', 'base', 'size', 'maxW']) lay[k][q] = Math.round(lay[k][q] * 100000) / 100000;
    if (draft) await redisCommand(['SET', 'certdraftlay:' + tier, JSON.stringify(lay)]);
    else {
      await redisCommand(['SET', 'certlayout:' + tier, JSON.stringify(lay)]);
      certCachesClear(tier);
      await syncActiveSet(tier);
    }
  }

  const t = CERT_META[tier].test;
  const renderOpts = { name: await certPreviewName(cb.from), totalDays: t.days, streak: t.streak, tier, issuedAt: Date.now(), highlight: field };
  if (draft) { renderOpts.templateBuffer = draftData.buffer; renderOpts.layout = lay; }
  const img = await renderCertificate(renderOpts);
  const caption = layCaption(tier, field, step, lay, draft), kb = layKeyboard(tier, field, step, draft);
  if (cb.message.photo) {
    const r = await tgEditPhoto(chatId, messageId, img, caption, kb).catch(() => null);
    if (r && (r.ok || /not modified/i.test(r.description || ''))) return;
    tgDeleteMsgIn(chatId, messageId); // edit refused for another reason -> replace with a fresh photo
    await sendCertificatePhoto(chatId, img, caption, kb);
  } else {
    await sendCertificatePhoto(chatId, img, caption, kb); // opened from a text menu: show the photo, drop the menu
    tgDeleteMsgIn(chatId, messageId);
  }
}

// ---------------------------------------------------------------------------
// FESTIVAL SETS — one set = Silver + Gold + Diamond template (+ their text layout), saved under a name.
//   Activate = copies the set onto the live cards in one tap. A set can carry a date range: the bot then switches to it
//   automatically when the festival starts and back to "Normal" (or the GitHub default) when it ends.
//   Redis: certset_index (JSON id list) · certset:<id> (meta) · certsettpl:<id>:<tier> · certsetlay:<id>:<tier>
//          certset_active · certset_base (fallback "Normal" set) · certset_sched_last (what the scheduler applied last)
//   While a set is active, edits to the live cards (upload / adjust / undo) are mirrored into it automatically.
// ---------------------------------------------------------------------------
const SET_MAX = 12;
const IST_MS = 5.5 * 60 * 60 * 1000;
const MONTHS_S = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
function istParts(ms) { const d = new Date(ms + IST_MS); return { y: d.getUTCFullYear(), m: d.getUTCMonth() + 1, d: d.getUTCDate() }; }
function fmtIst(ms) { const p = istParts(ms); return `${String(p.d).padStart(2, '0')} ${MONTHS_S[p.m - 1]} ${p.y}`; }
function istDayStart(y, m, d) { return Date.UTC(y, m - 1, d) - IST_MS; }
// "01-11-2026 to 10-11-2026" / "1/11 - 10/11" (year optional, India day-month order) -> { from, to } in ms (IST days, end inclusive)
function parseSchedule(text) {
  const re = /(\d{1,2})[-\/.](\d{1,2})(?:[-\/.](\d{2,4}))?/g;
  const found = []; let m;
  while ((m = re.exec(String(text))) && found.length < 2) found.push(m);
  if (found.length < 2) return null;
  const nowY = istParts(Date.now()).y;
  const mk = (x) => {
    let yy = x[3] ? Number(x[3]) : nowY; if (yy < 100) yy += 2000;
    const dd = Number(x[1]), mm = Number(x[2]);
    const dt = new Date(Date.UTC(yy, mm - 1, dd));
    if (dt.getUTCMonth() !== mm - 1 || dt.getUTCDate() !== dd) return null;
    return { y: yy, m: mm, d: dd };
  };
  const a = mk(found[0]), b = mk(found[1]);
  if (!a || !b) return null;
  const from = istDayStart(a.y, a.m, a.d);
  let to = istDayStart(b.y, b.m, b.d) + 86400e3 - 1;
  if (!found[1][3] && to < from) to = istDayStart(b.y + 1, b.m, b.d) + 86400e3 - 1; // "25 Dec - 5 Jan"
  if (to < from) return null;
  return { from, to };
}

async function certSetIndex() { try { const r = await redisCommand(['GET', 'certset_index']); const a = r ? JSON.parse(r) : []; return Array.isArray(a) ? a : []; } catch (e) { return []; } }
async function certSetGet(id) { const r = await redisCommand(['GET', 'certset:' + id]); return r ? JSON.parse(r) : null; }
async function certSetPut(meta) { await redisCommand(['SET', 'certset:' + meta.id, JSON.stringify(meta)]); }
async function certSetList() { const out = []; for (const id of await certSetIndex()) { const m = await certSetGet(id).catch(() => null); if (m) out.push(m); } return out; }
async function certSetCreate(name) {
  const ids = await certSetIndex();
  if (ids.length >= SET_MAX) throw new Error(`Maximum ${SET_MAX} sets ho sakte hain — pehle koi purana set delete karo.`);
  const id = Math.random().toString(36).slice(2, 7);
  const meta = { id, name: String(name).replace(/\s+/g, ' ').trim().slice(0, 30) || 'Festival', created: Date.now(), from: null, to: null, tiers: {} };
  await certSetPut(meta);
  ids.push(id); await redisCommand(['SET', 'certset_index', JSON.stringify(ids)]);
  return meta;
}
async function certSetDelete(id) {
  for (const t of CERT_TIERS) { await redisCommand(['DEL', `certsettpl:${id}:${t}`]); await redisCommand(['DEL', `certsetlay:${id}:${t}`]); }
  await redisCommand(['DEL', 'certset:' + id]);
  await redisCommand(['SET', 'certset_index', JSON.stringify((await certSetIndex()).filter(x => x !== id))]);
  if ((await redisCommand(['GET', 'certset_active'])) === id) await redisCommand(['DEL', 'certset_active']);
  if ((await redisCommand(['GET', 'certset_base'])) === id) await redisCommand(['DEL', 'certset_base']);
}
async function certSetStoreTemplate(id, tier, jpegBuf) {
  const meta = await certSetGet(id); if (!meta) throw new Error('Set nahi mila (delete ho gaya?)');
  await redisCommand(['SET', `certsettpl:${id}:${tier}`, jpegBuf.toString('base64')]);
  await redisCommand(['DEL', `certsetlay:${id}:${tier}`]); // new image -> let the right preset be chosen again
  meta.tiers[tier] = true; await certSetPut(meta);
}
// Copies whatever is live right now into a set (used by "Save current as set" / "Overwrite from live").
async function certSetSnapshotLive(id) {
  const meta = await certSetGet(id); if (!meta) throw new Error('Set nahi mila');
  for (const tier of CERT_TIERS) {
    const info = await templateInfo(tier);
    let buf = await currentTemplateBuffer(tier); if (!buf) continue;
    if (buf.length > 640 * 1024) buf = (await prepareTemplate(buf)).buffer;
    await redisCommand(['SET', `certsettpl:${id}:${tier}`, buf.toString('base64')]);
    if (info.layoutSource === 'custom') await redisCommand(['SET', `certsetlay:${id}:${tier}`, JSON.stringify(info.layout)]);
    else await redisCommand(['DEL', `certsetlay:${id}:${tier}`]);
    meta.tiers[tier] = true;
  }
  await certSetPut(meta); return meta;
}
// Keeps the live card of a tier as "previous" (for the Undo button) before it gets replaced.
async function stashPrevious(tier, label) {
  await histPush(tier, label || 'Update');
  try {
    const info = await templateInfo(tier);
    const prevBuf = await currentTemplateBuffer(tier);
    if (!prevBuf) return;
    const small = prevBuf.length <= 640 * 1024 ? prevBuf : (await prepareTemplate(prevBuf)).buffer;
    await redisCommand(['SET', 'certtpl_prev:' + tier, small.toString('base64')]);
    await redisCommand(['SET', 'certlayout_prev:' + tier, JSON.stringify(info.layout)]);
  } catch (e) { console.warn('[cert] could not keep previous version:', e.message); }
}
async function certSetActivate(id) {
  const meta = await certSetGet(id); if (!meta) throw new Error('Set nahi mila');
  const applied = [];
  for (const tier of CERT_TIERS) {
    if (!meta.tiers[tier]) continue;
    const tpl = await redisCommand(['GET', `certsettpl:${id}:${tier}`]); if (!tpl) continue;
    await stashPrevious(tier, 'Set: ' + meta.name);
    await redisCommand(['SET', 'certtpl:' + tier, tpl]);
    const lay = await redisCommand(['GET', `certsetlay:${id}:${tier}`]);
    if (lay) await redisCommand(['SET', 'certlayout:' + tier, lay]); else await redisCommand(['DEL', 'certlayout:' + tier]);
    applied.push(tier);
  }
  if (!applied.length) throw new Error('Is set me abhi koi card upload nahi hai.');
  await redisCommand(['SET', 'certset_active', id]);
  certCachesClear();
  return { meta, applied };
}
async function certResetToDefault() { // live cards -> the files shipped in GitHub
  for (const tier of CERT_TIERS) {
    await stashPrevious(tier, 'Reset to default');
    await redisCommand(['DEL', 'certtpl:' + tier]); await redisCommand(['DEL', 'certlayout:' + tier]);
  }
  await redisCommand(['DEL', 'certset_active']);
  certCachesClear();
}
// Called after any edit of a live card: while a set is active, the set follows the live card.
async function syncActiveSet(tier) {
  try {
    const id = await redisCommand(['GET', 'certset_active']); if (!id) return;
    const meta = await certSetGet(id); if (!meta) return;
    const tpl = await redisCommand(['GET', 'certtpl:' + tier]); if (!tpl) return;
    await redisCommand(['SET', `certsettpl:${id}:${tier}`, tpl]);
    const lay = await redisCommand(['GET', 'certlayout:' + tier]);
    if (lay) await redisCommand(['SET', `certsetlay:${id}:${tier}`, lay]); else await redisCommand(['DEL', `certsetlay:${id}:${tier}`]);
    if (!meta.tiers[tier]) { meta.tiers[tier] = true; await certSetPut(meta); }
  } catch (e) { console.warn('[sets] sync failed:', e.message); }
}

// ---- Scheduler: switches sets on their start date and back when the festival is over ----
// Only acts on a CHANGE of the wanted set (festival starts / ends), so a manual choice made in between is respected.
async function runCertScheduler(now = Date.now()) {
  const sets = await certSetList();
  const due = sets.filter(x => x.from && x.to && x.from <= now && now <= x.to).sort((a, b) => b.from - a.from)[0] || null;
  const desired = due ? due.id : null;
  const lastRaw = await redisCommand(['GET', 'certset_sched_last']);
  const last = lastRaw && lastRaw !== 'none' ? lastRaw : null;
  if (desired === last) return null;
  let note;
  try {
    if (due) {
      await certSetActivate(due.id);
      note = `🎆 <b>${esc(due.name)}</b> schedule ke hisaab se <b>LIVE</b> ho gaya (${fmtIst(due.from)} → ${fmtIst(due.to)}).`;
    } else {
      const baseId = await redisCommand(['GET', 'certset_base']);
      const baseMeta = baseId ? await certSetGet(baseId).catch(() => null) : null;
      if (baseMeta) { await certSetActivate(baseId); note = `🏁 Festival khatam. Normal set <b>${esc(baseMeta.name)}</b> wapas lag gaya.`; }
      else { await certResetToDefault(); note = '🏁 Festival khatam. Cards wapas <b>GitHub default</b> par aa gaye.'; }
    }
  } catch (e) { note = `⚠️ Auto-switch fail hua: ${esc(e.message)}`; }
  await redisCommand(['SET', 'certset_sched_last', desired || 'none']);
  for (const oid of cbOwnerIds()) tgSendText(oid, note, { parse_mode: 'HTML' }).catch(() => {});
  return note;
}

// ---- Screens ----
async function sendPhotoGroup(chatId, items, threadId) {
  if (items.length === 1) return sendCertificatePhoto(chatId, items[0].buffer, items[0].caption, null, threadId);
  const form = new FormData();
  form.append('chat_id', String(chatId));
  if (threadId) form.append('message_thread_id', String(threadId));
  form.append('media', JSON.stringify(items.map((it, i) => ({ type: 'photo', media: 'attach://p' + i, caption: it.caption, parse_mode: 'HTML' }))));
  items.forEach((it, i) => form.append('p' + i, it.buffer, { filename: `card${i}.jpg`, contentType: 'image/jpeg' }));
  const r = await fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMediaGroup`, { method: 'POST', body: form, headers: form.getHeaders() });
  return r.json();
}
async function certSetPreviews(chatId, meta, fromUser) {
  const name = await certPreviewName(fromUser), items = [];
  for (const tier of CERT_TIERS) {
    if (!meta.tiers[tier]) continue;
    const tpl = await redisCommand(['GET', `certsettpl:${meta.id}:${tier}`]); if (!tpl) continue;
    const lay = await redisCommand(['GET', `certsetlay:${meta.id}:${tier}`]);
    const t = CERT_META[tier].test;
    const buffer = await renderCertificate({ name, totalDays: t.days, streak: t.streak, tier, issuedAt: Date.now(), templateBuffer: Buffer.from(tpl, 'base64'), layout: lay ? JSON.parse(lay) : null });
    items.push({ buffer, caption: `${CERT_META[tier].icon} <b>${CERT_META[tier].label}</b> — ${esc(meta.name)}` });
  }
  if (!items.length) return false;
  await sendPhotoGroup(chatId, items);
  return true;
}
const setTiersLine = (meta) => CERT_TIERS.map(t => `${CERT_META[t].icon} ${meta.tiers[t] ? '✅' : '➖'}`).join('   ');
const setBack = (to) => ({ inline_keyboard: [[{ text: '⬅️ Back', callback_data: to }]] });

async function setListView() {
  const sets = await certSetList();
  const active = await redisCommand(['GET', 'certset_active']);
  const base = await redisCommand(['GET', 'certset_base']);
  const act = sets.find(s => s.id === active);
  const lines = [
    panelHeader('🎆', 'FESTIVAL SETS', 'Ek tap me teeno cards badlo — schedule se auto on/off'),
    `▶️ Live set: <b>${act ? esc(act.name) : 'koi nahi (manual / GitHub default)'}</b>`,
  ];
  if (!sets.length) lines.push('', '<i>Abhi koi set nahi hai. ➕ New Set se teeno cards upload karo ya 📸 Save Current se abhi wale cards save karo.</i>');
  const kb = sets.map(s => [{ text: `${s.id === active ? '✅ ' : ''}🎆 ${s.name}${s.from ? ' 📅' : ''}${s.id === base ? ' ⭐' : ''}`.slice(0, 60), callback_data: `panel:set:open:${s.id}` }]);
  kb.push([{ text: '➕ New Set', callback_data: 'panel:set:new' }, { text: '📸 Save Current as Set', callback_data: 'panel:set:snap' }]);
  kb.push([{ text: '🗂 Use GitHub Default', callback_data: 'panel:set:def' }, { text: '🧭 ChatGPT Prompt', callback_data: 'panel:set:prompt' }]);
  kb.push([{ text: '⬅️ Back to Cards', callback_data: 'panel:s:cert' }]);
  lines.push('', '<i>📅 = scheduled · ⭐ = Normal (festival ke baad wapas yahi lagta hai)</i>');
  return { text: lines.join('\n'), kb: { inline_keyboard: kb } };
}
async function setScreenView(id) {
  const meta = await certSetGet(id); if (!meta) return null;
  const active = (await redisCommand(['GET', 'certset_active'])) === id;
  const isBase = (await redisCommand(['GET', 'certset_base'])) === id;
  const lines = [
    panelHeader('🎆', esc(meta.name).toUpperCase(), active ? '✅ Abhi LIVE hai' : 'Festival set'),
    `Cards: ${setTiersLine(meta)}`,
    meta.from ? `📅 Schedule: <b>${fmtIst(meta.from)}</b> → <b>${fmtIst(meta.to)}</b> (auto on/off)` : '📅 Schedule: nahi lagaya',
    `⭐ Normal set: ${isBase ? '<b>haan</b> — festival ke baad yahi wapas lagega' : 'nahi'}`,
  ];
  const kb = [
    [{ text: active ? '▶️ Re-apply Now' : '▶️ Activate Now', callback_data: `panel:set:act:${id}` }, { text: '👁 Preview', callback_data: `panel:set:prev:${id}` }],
    [{ text: '📅 Schedule', callback_data: `panel:set:sched:${id}` }, ...(meta.from ? [{ text: '🚫 Clear Schedule', callback_data: `panel:set:unsched:${id}` }] : [])],
    [{ text: '📤 Upload / Replace Cards', callback_data: `panel:set:wiz:${id}` }, { text: '📸 Overwrite from Live', callback_data: `panel:set:snapc:${id}` }],
    [{ text: isBase ? '⭐ Remove as Normal' : '⭐ Make Normal', callback_data: `panel:set:base:${id}` }, { text: '🗑 Delete', callback_data: `panel:set:del:${id}` }],
    [{ text: '⬅️ All Sets', callback_data: 'panel:set:list' }],
  ];
  return { text: lines.join('\n'), kb: { inline_keyboard: kb } };
}
// Edits the tapped message into a screen (photo messages are replaced automatically by tgEdit).
async function showView(cb, view) { await tgEdit(cb.message.chat.id, cb.message.message_id, view.text, view.kb, 'HTML'); }
async function sendView(chatId, view) { return tgSendText(chatId, view.text, { parse_mode: 'HTML', reply_markup: view.kb }); }

// ---- 3-card upload wizard ----
function wizardKeyboard(id) {
  return { inline_keyboard: [[{ text: '⏭ Skip', callback_data: `panel:set:skip:${id}` }, { text: '✅ Finish', callback_data: `panel:set:fin:${id}` }], [{ text: '❌ Cancel', callback_data: `panel:set:open:${id}` }]] };
}
async function wizardAsk(chatId, userId, meta, idx, prefix, editMessageId) {
  if (idx >= CERT_TIERS.length) return wizardFinish(chatId, userId, meta.id);
  const tier = CERT_TIERS[idx];
  panelPending.set(userId, { action: `set_wiz:${meta.id}:${idx}`, ts: Date.now(), section: 'cert' });
  const text = `${prefix ? prefix + '\n\n' : ''}🎆 <b>${esc(meta.name)}</b> — Step ${idx + 1}/${CERT_TIERS.length}\n\n${CERT_META[tier].icon} <b>${CERT_META[tier].label}</b> card ki blank template bhejo.\n📎 Best quality ke liye <b>File/Document</b> ki tarah bhejo.\n\n<i>Is card ko chhodna ho to ⏭ Skip dabao. Jitne upload karne the ho gaye to ✅ Finish.</i>`;
  if (editMessageId) return tgEdit(chatId, editMessageId, text, wizardKeyboard(meta.id), 'HTML');
  return tgSendText(chatId, text, { parse_mode: 'HTML', reply_markup: wizardKeyboard(meta.id) });
}
async function wizardFinish(chatId, userId, id, fromUser) {
  panelPending.delete(userId);
  const meta = await certSetGet(id); if (!meta) return;
  const have = CERT_TIERS.filter(t => meta.tiers[t]);
  if (!have.length) return tgSendText(chatId, '⚠️ Koi card upload nahi hua, set khali hai.', { reply_markup: setBack(`panel:set:open:${id}`) });
  await certSetPreviews(chatId, meta, fromUser || { first_name: 'Admin', last_name: 'Supporter' });
  return tgSendText(chatId, `✅ <b>${esc(meta.name)}</b> ready — ${setTiersLine(meta)}\nUpar preview dekho. Ab live karo ya schedule lagao 👇`, {
    parse_mode: 'HTML',
    reply_markup: { inline_keyboard: [[{ text: '▶️ Activate Now', callback_data: `panel:set:act:${id}` }, { text: '📅 Schedule', callback_data: `panel:set:sched:${id}` }], [{ text: '🎆 Open Set', callback_data: `panel:set:open:${id}` }]] }
  });
}

function certPromptText() {
  return [
    'Use the attached image as the EXACT layout reference for a certificate card (16:9, 1280x720).',
    'Create a new "[FESTIVAL NAME]" edition of this certificate: change only the colours, background art and festival decorations.',
    'Keep all printed words exactly as they are (CHANNEL SUPPORT CENTER, CERTIFICATE OF SUPPORT, This certifies that, has proudly supported the channel as a ..., TOTAL DAYS, CURRENT STREAK, the tier name, VERIFIED SUPPORTER, the footer line).',
    'The areas inside the three cyan dashed boxes (NAME, DAYS, STREAK) must stay completely EMPTY with a plain dark background - no text, numbers or decorations there.',
    'Do NOT draw the cyan boxes or their labels. Keep every element in the same position and size.',
  ].join('\n');
}
async function sendPromptMessage(chatId) {
  return tgSendText(chatId, `🧭 <b>ChatGPT Prompt</b>\nPehle card ke menu se <b>🧭 Layout Guide</b> dabao (guide image milegi), use ChatGPT me attach karo aur ye prompt bhejo:\n\n<pre>${esc(certPromptText())}</pre>`, { parse_mode: 'HTML' });
}

async function handleSetCallback(cb, action) {
  const chatId = cb.message.chat.id, userId = cb.from.id;
  const [op, id] = String(action).split(':');
  const needSet = async () => { const m = id ? await certSetGet(id).catch(() => null) : null; if (!m) { await showView(cb, await setListView()); return null; } return m; };
  if (op !== 'skip') panelPending.delete(userId);

  if (op === 'list') return showView(cb, await setListView());
  if (op === 'open') { const v = await setScreenView(id); return showView(cb, v || await setListView()); }
  if (op === 'prompt') return sendPromptMessage(chatId);

  if (op === 'new' || op === 'snap') {
    panelPending.set(userId, { action: op === 'new' ? 'set_new' : 'set_snap', ts: Date.now(), section: 'cert' });
    const t = op === 'new'
      ? '➕ <b>NEW SET</b>\n\nSet ka naam bhejo (jaise <code>Diwali 2026</code>). Uske baad bot teeno cards upload karwayega.'
      : '📸 <b>SAVE CURRENT AS SET</b>\n\nAbhi live teeno cards ko save karne ke liye set ka naam bhejo (jaise <code>Normal</code>).';
    return tgEdit(chatId, cb.message.message_id, t, setBack('panel:set:list'), 'HTML');
  }
  if (op === 'def') {
    return tgEdit(chatId, cb.message.message_id, '⚠️ <b>GitHub Default lagayein?</b>\n\nLive teeno cards GitHub wali original files se replace ho jayenge.\nBot se upload kiye cards agar kisi set me save nahi hain to <i>↩️ Undo</i> se hi wapas aa sakte hain — pehle <b>📸 Save Current as Set</b> kar lo.',
      { inline_keyboard: [[{ text: '✅ Haan, GitHub Default lagao', callback_data: 'panel:set:defc' }], [{ text: '❌ Cancel', callback_data: 'panel:set:list' }]] }, 'HTML');
  }
  if (op === 'defc') { await certResetToDefault(); return tgEdit(chatId, cb.message.message_id, '🗂 <b>Cards ab GitHub default par hain.</b>', { inline_keyboard: [[{ text: '🎆 Sets', callback_data: 'panel:set:list' }, { text: '🎖️ Cards', callback_data: 'panel:s:cert' }]] }, 'HTML'); }

  const meta = await needSet(); if (!meta) return;
  if (op === 'act') {
    const r = await certSetActivate(id);
    await tgEdit(chatId, cb.message.message_id, `▶️ <b>${esc(meta.name)}</b> ab <b>LIVE</b> hai!\nLive hue cards: ${r.applied.map(t => CERT_META[t].icon + ' ' + CERT_META[t].label).join(', ')}\n<i>Pehle wale cards ke liye har card me ↩️ Undo available hai.</i>`,
      { inline_keyboard: [[{ text: '📣 Announce in Support Topic', callback_data: 'panel:do:cert_announce' }], [{ text: '🎆 Open Set', callback_data: `panel:set:open:${id}` }, { text: '🎖️ Cards', callback_data: 'panel:s:cert' }]] }, 'HTML');
    return certSetPreviews(chatId, meta, cb.from);
  }
  if (op === 'prev') {
    const ok = await certSetPreviews(chatId, meta, cb.from);
    if (!ok) await tgSendText(chatId, '⚠️ Is set me abhi koi card nahi hai.');
    return;
  }
  if (op === 'sched') {
    panelPending.set(userId, { action: 'set_sched:' + id, ts: Date.now(), section: 'cert' });
    return tgEdit(chatId, cb.message.message_id, `📅 <b>SCHEDULE — ${esc(meta.name)}</b>\n\nStart aur end date bhejo (India dates, end date bhi shamil):\n<code>01-11-2026 to 10-11-2026</code>\nYa saal ke bina: <code>1/11 to 10/11</code>\n\nStart date par bot khud set live kar dega, end ke baad Normal / GitHub default wapas laga dega.`, setBack(`panel:set:open:${id}`), 'HTML');
  }
  if (op === 'unsched') { meta.from = null; meta.to = null; await certSetPut(meta); runCertScheduler().catch(() => {}); return showView(cb, await setScreenView(id)); }
  if (op === 'wiz') return wizardAsk(chatId, userId, meta, 0, '', cb.message.message_id);
  if (op === 'skip') {
    const p = panelPending.get(userId); const m = p && /^set_wiz:([^:]+):(\d+)$/.exec(p.action);
    if (!m || m[1] !== id) return wizardAsk(chatId, userId, meta, 0, '', cb.message.message_id);
    return wizardAsk(chatId, userId, meta, Number(m[2]) + 1, `⏭ ${CERT_META[CERT_TIERS[Number(m[2])]].label} skip kiya.`);
  }
  if (op === 'fin') return wizardFinish(chatId, userId, id, cb.from);
  if (op === 'snapc') {
    await certSetSnapshotLive(id);
    return showView(cb, Object.assign(await setScreenView(id), {}));
  }
  if (op === 'base') {
    const cur = await redisCommand(['GET', 'certset_base']);
    if (cur === id) await redisCommand(['DEL', 'certset_base']); else await redisCommand(['SET', 'certset_base', id]);
    return showView(cb, await setScreenView(id));
  }
  if (op === 'del') {
    return tgEdit(chatId, cb.message.message_id, `🗑 <b>${esc(meta.name)}</b> delete karein?\nSet ke saved cards hamesha ke liye hat jayenge (live cards nahi badlenge).`,
      { inline_keyboard: [[{ text: '✅ Haan, delete', callback_data: `panel:set:delc:${id}` }], [{ text: '❌ Cancel', callback_data: `panel:set:open:${id}` }]] }, 'HTML');
  }
  if (op === 'delc') { await certSetDelete(id); return showView(cb, await setListView()); }
}

// Text / image answers while a Festival Sets prompt is waiting. Returns true if handled.
async function handleSetPending(msg, action, userId) {
  const chatId = msg.chat.id;
  const text = typeof msg.text === 'string' ? msg.text.trim() : '';
  try {
    if (action === 'set_new' || action === 'set_snap') {
      if (!text) { await tgSendText(chatId, '⚠️ Set ka naam text me bhejo.'); return true; }
      panelPending.delete(userId);
      const meta = await certSetCreate(text);
      if (action === 'set_snap') {
        await certSetSnapshotLive(meta.id);
        await sendView(chatId, await setScreenView(meta.id));
      } else await wizardAsk(chatId, userId, meta, 0, `✅ Set <b>${esc(meta.name)}</b> ban gaya.`);
      return true;
    }
    if (action.startsWith('set_sched:')) {
      const id = action.split(':')[1];
      const sch = parseSchedule(text);
      if (!sch) { await tgSendText(chatId, '⚠️ Date samajh nahi aayi. Aise bhejo: <code>01-11-2026 to 10-11-2026</code>', { parse_mode: 'HTML' }); return true; }
      panelPending.delete(userId);
      const meta = await certSetGet(id); if (!meta) { await tgSendText(chatId, '⚠️ Set nahi mila.'); return true; }
      meta.from = sch.from; meta.to = sch.to; await certSetPut(meta);
      await runCertScheduler().catch(e => console.warn('[sets] scheduler:', e.message));
      await sendView(chatId, await setScreenView(id));
      return true;
    }
    const w = /^set_wiz:([^:]+):(\d+)$/.exec(action);
    if (w) {
      const id = w[1], idx = Number(w[2]), tier = CERT_TIERS[idx];
      const meta = await certSetGet(id); if (!meta) { panelPending.delete(userId); return false; }
      const doc = msg.document && (/^image\//i.test(msg.document.mime_type || '') || /\.(png|jpe?g|webp)$/i.test(msg.document.file_name || '')) ? msg.document : null;
      const media = msg.photo ? msg.photo[msg.photo.length - 1] : doc;
      if (!media) { await tgSendText(chatId, `⚠️ ${CERT_META[tier].label} card ki <b>image</b> bhejo (ya ⏭ Skip / ✅ Finish).`, { parse_mode: 'HTML', reply_markup: wizardKeyboard(id) }); return true; }
      const prep = await prepareTemplate(await downloadTelegramFile(media.file_id));
      await certSetStoreTemplate(id, tier, prep.buffer);
      await wizardAsk(chatId, userId, meta, idx + 1, `✅ ${CERT_META[tier].label} mil gaya (<code>${prep.width}×${prep.height}</code>).`);
      return true;
    }
  } catch (e) {
    console.error('[sets] input failed:', e.message);
    await tgSendText(chatId, `❌ ${esc(e.message)}`, { parse_mode: 'HTML' });
    return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// VERSION HISTORY (last 5 live versions per card) · DRAFT MODE · ANNOUNCE · BACKUP / RESTORE
//   certhist_idx:<tier> JSON [{id,ts,label,h}] newest first · certhist:<tier>:<id>:t (template b64) / :l (layout JSON or '')
//   certdraft_mode '1' · certdrafttpl:<tier> · certdraftlay:<tier>
// ---------------------------------------------------------------------------
const HIST_MAX = 5;
const TIER_ICON_LABEL = (t) => `${CERT_META[t].icon} ${CERT_META[t].label}`;
function fmtIstTime(ms) { const d = new Date(ms + IST_MS); return `${fmtIst(ms)} ${String(d.getUTCHours()).padStart(2, '0')}:${String(d.getUTCMinutes()).padStart(2, '0')}`; }
async function histIndex(tier) { try { const r = await redisCommand(['GET', 'certhist_idx:' + tier]); const a = r ? JSON.parse(r) : []; return Array.isArray(a) ? a : []; } catch (e) { return []; } }
// Saves the CURRENT live card as a history entry (skipped when identical to the newest entry).
async function histPush(tier, label) {
  try {
    const buf = await currentTemplateBuffer(tier); if (!buf) return;
    const small = buf.length <= 640 * 1024 ? buf : (await prepareTemplate(buf)).buffer;
    const h = crypto.createHash('sha1').update(small).digest('hex').slice(0, 12);
    const idx = await histIndex(tier);
    if (idx[0] && idx[0].h === h) return;
    const info = await templateInfo(tier);
    const id = Date.now().toString(36);
    await redisCommand(['SET', `certhist:${tier}:${id}:t`, small.toString('base64')]);
    await redisCommand(['SET', `certhist:${tier}:${id}:l`, info.layoutSource === 'custom' ? JSON.stringify(info.layout) : '']);
    idx.unshift({ id, ts: Date.now(), label: String(label || 'Update').slice(0, 30), h });
    while (idx.length > HIST_MAX) { const old = idx.pop(); await redisCommand(['DEL', `certhist:${tier}:${old.id}:t`]); await redisCommand(['DEL', `certhist:${tier}:${old.id}:l`]); }
    await redisCommand(['SET', 'certhist_idx:' + tier, JSON.stringify(idx)]);
  } catch (e) { console.warn('[cert] history push failed:', e.message); }
}
async function histRestore(tier, id) {
  const e = (await histIndex(tier)).find(x => x.id === id);
  const t = e ? await redisCommand(['GET', `certhist:${tier}:${id}:t`]) : null;
  if (!t) throw new Error('Ye version ab available nahi hai.');
  const l = await redisCommand(['GET', `certhist:${tier}:${id}:l`]);   // read first: the push below may trim the oldest entry
  await stashPrevious(tier, 'Restore se pehle');
  await redisCommand(['SET', 'certtpl:' + tier, t]);
  if (l) await redisCommand(['SET', 'certlayout:' + tier, l]); else await redisCommand(['DEL', 'certlayout:' + tier]);
  certCachesClear(tier);
  await syncActiveSet(tier);
}
async function handleHistCallback(cb, action) {
  const chatId = cb.message.chat.id;
  const [tier, op, id] = String(action).split(':');
  if (!CERT_TIERS.includes(tier)) return;
  const back = { text: '⬅️ Back to Card', callback_data: `panel:s:cert_${tier}` };
  if (op === 'pv') {
    const e = (await histIndex(tier)).find(x => x.id === id);
    const t = e ? await redisCommand(['GET', `certhist:${tier}:${id}:t`]) : null;
    if (!t) { await tgSendText(chatId, '⚠️ Ye version ab available nahi hai.'); return; }
    const l = await redisCommand(['GET', `certhist:${tier}:${id}:l`]);
    const c = CERT_META[tier].test;
    const img = await renderCertificate({ name: await certPreviewName(cb.from), totalDays: c.days, streak: c.streak, tier, issuedAt: Date.now(), templateBuffer: Buffer.from(t, 'base64'), layout: l ? JSON.parse(l) : null });
    await sendCertificatePhoto(chatId, img, `👁 <b>${TIER_ICON_LABEL(tier)}</b> — purana version (${fmtIstTime(e.ts)} · ${esc(e.label)})`);
    return;
  }
  if (op === 'rs') {
    try { await histRestore(tier, id); } catch (e) { await tgEdit(chatId, cb.message.message_id, `❌ ${esc(e.message)}`, { inline_keyboard: [[back]] }, 'HTML'); return; }
    await sendCardPreview(chatId, tier, cb.from, `↩️ <b>${TIER_ICON_LABEL(tier)}</b> purane version par wapas aa gaya.\n<i>Pehle wala card bhi history me save hai.</i>`,
      { inline_keyboard: [[{ text: '🕘 History', callback_data: `panel:hist:${tier}:list` }], [back]] });
    tgDeleteMsgIn(chatId, cb.message.message_id);
    return;
  }
  const idx = await histIndex(tier);
  const lines = [panelHeader('🕘', `${CERT_META[tier].label.toUpperCase()} HISTORY`, `Pichle ${HIST_MAX} live versions`)];
  const kb = [];
  if (!idx.length) lines.push('Abhi koi purana version nahi hai. Card badalne par yahan apne aap save hota hai.');
  idx.forEach((e, i) => {
    lines.push(`<b>${i + 1}.</b> ${fmtIstTime(e.ts)} — ${esc(e.label)}`);
    kb.push([{ text: `👁 #${i + 1}`, callback_data: `panel:hist:${tier}:pv:${e.id}` }, { text: `↩️ Restore #${i + 1}`, callback_data: `panel:hist:${tier}:rs:${e.id}` }]);
  });
  kb.push([back]);
  await tgEdit(chatId, cb.message.message_id, lines.join('\n'), { inline_keyboard: kb }, 'HTML');
}

// ---- Draft mode: new single-card uploads wait as a draft until Publish ----
async function certDraftOn() { return (await redisCommand(['GET', 'certdraft_mode']).catch(() => null)) === '1'; }
async function saveCertificateDraft(tier, imageBuffer) {
  const prep = await prepareTemplate(imageBuffer);
  const info = await templateInfo(tier);
  await redisCommand(['SET', 'certdrafttpl:' + tier, prep.buffer.toString('base64')]);
  if (info.layoutSource === 'custom') await redisCommand(['SET', 'certdraftlay:' + tier, JSON.stringify(info.layout)]);
  else await redisCommand(['DEL', 'certdraftlay:' + tier]);
  return prep;
}
async function certDraftInfo(tier) {
  const t = await redisCommand(['GET', 'certdrafttpl:' + tier]); if (!t) return null;
  const l = await redisCommand(['GET', 'certdraftlay:' + tier]);
  const buffer = Buffer.from(t, 'base64');
  const i = await inspectTemplate(buffer, l ? JSON.parse(l) : null, tier);
  return { buffer, width: i.width, height: i.height, layout: i.layout, layoutSource: l ? 'custom' : 'preset' };
}
async function sendDraftPreview(chatId, tier, fromUser, prefix) {
  const d = await certDraftInfo(tier); if (!d) return false;
  const c = CERT_META[tier].test;
  const img = await renderCertificate({ name: await certPreviewName(fromUser), totalDays: c.days, streak: c.streak, tier, issuedAt: Date.now(), templateBuffer: d.buffer, layout: d.layout });
  await sendCertificatePhoto(chatId, img,
    `${prefix ? prefix + '\n\n' : ''}📝 <b>DRAFT — ${TIER_ICON_LABEL(tier)}</b>\n📄 <code>${d.width}×${d.height}</code> · layout: <b>${d.layout.preset === 'festival' ? 'Festival' : 'Classic'}${d.layoutSource === 'custom' ? ' (custom)' : ''}</b>\n\n<i>Ye abhi LIVE nahi hai — sirf aapko dikh raha hai. Sahi lage to ✅ Publish dabao.</i>`,
    { inline_keyboard: [
      [{ text: '📐 Adjust Draft', callback_data: `panel:lay:${tier}:name:sel:1:d` }, { text: '✅ Publish', callback_data: `panel:draft:${tier}:pub` }],
      [{ text: '🎆 Festival style', callback_data: `panel:lay:${tier}:name:fest:1:d` }, { text: '🏛 Classic style', callback_data: `panel:lay:${tier}:name:classic:1:d` }],
      [{ text: '🗑 Discard', callback_data: `panel:draft:${tier}:del` }, { text: '⬅️ Back to Card', callback_data: `panel:s:cert_${tier}` }],
    ] });
  return true;
}
async function handleDraftCallback(cb, action) {
  const chatId = cb.message.chat.id, messageId = cb.message.message_id;
  const [tier, op] = String(action).split(':');
  if (!CERT_TIERS.includes(tier)) return;
  const back = { inline_keyboard: [[{ text: '⬅️ Back to Card', callback_data: `panel:s:cert_${tier}` }]] };
  if (op === 'open') {
    const ok = await sendDraftPreview(chatId, tier, cb.from);
    if (ok) tgDeleteMsgIn(chatId, messageId);
    else await tgEdit(chatId, messageId, `📝 <b>${TIER_ICON_LABEL(tier)}</b> ka koi draft nahi hai.\n\n<i>Draft Mode ON karke 📤 Update Template karo — naya card pehle draft me aayega.</i>`, back, 'HTML');
    return;
  }
  if (op === 'del') {
    await redisCommand(['DEL', 'certdrafttpl:' + tier]); await redisCommand(['DEL', 'certdraftlay:' + tier]);
    await tgEdit(chatId, messageId, `🗑 ${TIER_ICON_LABEL(tier)} draft discard ho gaya. Live card waisa hi hai.`, back, 'HTML');
    return;
  }
  if (op === 'pub') {
    const t = await redisCommand(['GET', 'certdrafttpl:' + tier]);
    if (!t) { await tgEdit(chatId, messageId, '⚠️ Draft nahi mila (pehle hi publish/discard ho gaya).', back, 'HTML'); return; }
    const l = await redisCommand(['GET', 'certdraftlay:' + tier]);
    await stashPrevious(tier, 'Publish se pehle');
    await redisCommand(['SET', 'certtpl:' + tier, t]);
    if (l) await redisCommand(['SET', 'certlayout:' + tier, l]); else await redisCommand(['DEL', 'certlayout:' + tier]);
    await redisCommand(['DEL', 'certdrafttpl:' + tier]); await redisCommand(['DEL', 'certdraftlay:' + tier]);
    certCachesClear(tier);
    await syncActiveSet(tier);
    await sendCardPreview(chatId, tier, cb.from, `✅ <b>${TIER_ICON_LABEL(tier)}</b> card ab <b>LIVE</b> hai!`,
      { inline_keyboard: [[{ text: '📣 Announce in Support Topic', callback_data: 'panel:do:cert_announce' }], [{ text: '↩️ Undo', callback_data: `panel:do:cert_undo:${tier}` }, { text: '⬅️ Back to Card', callback_data: `panel:s:cert_${tier}` }]] });
    tgDeleteMsgIn(chatId, messageId);
  }
}

// ---- Announce the live cards in the support topic ----
async function announceLiveCards(fromUser) {
  const target = await getNotifyTarget();
  if (!target.chatId) throw new Error('Support topic set nahi hai. Community ke support topic me /setsupporttopic likho.');
  const items = [];
  for (const tier of CERT_TIERS) {
    const c = CERT_META[tier].test;
    items.push({ buffer: await renderCertificate({ name: 'Aapka Naam', totalDays: c.days, streak: c.streak, tier, issuedAt: Date.now() }), caption: `${TIER_ICON_LABEL(tier)}` });
  }
  const url = (process.env.FRONTEND_URL || 'https://channel-support.pages.dev').replace(/\/$/, '');
  items[0].caption = `🎆 <b>Naye Certificate Cards LIVE!</b>\nSupport karo aur apna card pao 👉 ${esc(url)}\n\n${items[0].caption}`;
  const r = await sendPhotoGroup(target.chatId, items, target.threadId);
  if (!r || !r.ok) throw new Error((r && r.description) || 'Telegram ne announce reject kiya');
}

// ---- Backup / restore (admins can back up, only the Owner can restore) ----
async function buildCardsBackup() {
  const get = (k) => redisCommand(['GET', k]);
  const data = { format: 'csc-cards-backup', version: 1, createdAt: Date.now(), live: {}, sets: [], active: (await get('certset_active')) || null, base: (await get('certset_base')) || null };
  for (const t of CERT_TIERS) { const tpl = await get('certtpl:' + t); const lay = await get('certlayout:' + t); if (tpl || lay) data.live[t] = { tpl: tpl || null, layout: lay || null }; }
  for (const meta of await certSetList()) {
    const cards = {};
    for (const t of CERT_TIERS) { const tpl = await get(`certsettpl:${meta.id}:${t}`); if (tpl) cards[t] = { tpl, layout: (await get(`certsetlay:${meta.id}:${t}`)) || null }; }
    data.sets.push({ meta, cards });
  }
  return { gz: zlib.gzipSync(Buffer.from(JSON.stringify(data))), data };
}
async function sendCardsBackup(chatId) {
  const { gz, data } = await buildCardsBackup();
  if (gz.length > 18 * 1024 * 1024) throw new Error(`Backup ${Math.round(gz.length / 1048576)} MB ka hai — Telegram restore ki limit 20 MB hai. Kuch purane sets delete karo.`);
  const form = new FormData();
  form.append('chat_id', String(chatId));
  form.append('caption', `💾 <b>Cards Backup</b>\nLive overrides: ${Object.keys(data.live).length} · Sets: ${data.sets.length}\n<i>Restore: Panel → Certificates → 📥 Restore Backup (sirf Owner)</i>`);
  form.append('parse_mode', 'HTML');
  const d = new Date(Date.now() + IST_MS).toISOString().slice(0, 10);
  form.append('document', gz, { filename: `cards-backup-${d}.json.gz`, contentType: 'application/gzip' });
  const r = await fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendDocument`, { method: 'POST', body: form, headers: form.getHeaders() });
  const j = await r.json();
  if (!j.ok) throw new Error(j.description || 'Backup bhej nahi paya');
}
async function restoreCardsBackup(buffer) {
  let data;
  try { data = JSON.parse(zlib.gunzipSync(buffer).toString('utf8')); } catch (e) { throw new Error('Ye valid cards backup file (.json.gz) nahi hai.'); }
  if (!data || data.format !== 'csc-cards-backup' || data.version !== 1) throw new Error('Ye cards backup file nahi hai ya version alag hai.');
  const okTpl = (b64) => typeof b64 === 'string' && looksLikeImage(Buffer.from(b64, 'base64'));
  const okLay = (l) => { if (l == null || l === '') return true; try { return typeof JSON.parse(l) === 'object'; } catch (e) { return false; } };
  const sets = Array.isArray(data.sets) ? data.sets : [];
  if (sets.length > SET_MAX) throw new Error(`Backup me ${sets.length} sets hain, limit ${SET_MAX}.`);
  for (const [t, c] of Object.entries(data.live || {})) if (!CERT_TIERS.includes(t) || !(c.tpl == null || okTpl(c.tpl)) || !okLay(c.layout)) throw new Error('Backup me kharab live card mila — kuch bhi restore nahi kiya.');
  for (const s of sets) {
    if (!s.meta || !/^[a-z0-9]{3,8}$/.test(String(s.meta.id))) throw new Error('Backup me kharab set mila — kuch bhi restore nahi kiya.');
    for (const [t, c] of Object.entries(s.cards || {})) if (!CERT_TIERS.includes(t) || !okTpl(c.tpl) || !okLay(c.layout)) throw new Error('Backup me kharab set-card mila — kuch bhi restore nahi kiya.');
  }
  let nLive = 0;
  for (const [t, c] of Object.entries(data.live || {})) {
    if (c.tpl) { await stashPrevious(t, 'Restore se pehle'); await redisCommand(['SET', 'certtpl:' + t, c.tpl]); }
    if (c.layout) await redisCommand(['SET', 'certlayout:' + t, c.layout]); else await redisCommand(['DEL', 'certlayout:' + t]);
    nLive++;
  }
  const ids = new Set(await certSetIndex());
  for (const s of sets) {
    const meta = { id: String(s.meta.id), name: String(s.meta.name || 'Set').slice(0, 30), created: Number(s.meta.created) || Date.now(), from: s.meta.from || null, to: s.meta.to || null, tiers: {} };
    for (const t of CERT_TIERS) { await redisCommand(['DEL', `certsettpl:${meta.id}:${t}`]); await redisCommand(['DEL', `certsetlay:${meta.id}:${t}`]); }
    for (const [t, c] of Object.entries(s.cards || {})) {
      await redisCommand(['SET', `certsettpl:${meta.id}:${t}`, c.tpl]);
      if (c.layout) await redisCommand(['SET', `certsetlay:${meta.id}:${t}`, c.layout]);
      meta.tiers[t] = true;
    }
    await certSetPut(meta); ids.add(meta.id);
  }
  await redisCommand(['SET', 'certset_index', JSON.stringify([...ids])]);
  const known = (id) => id && ids.has(String(id));
  if (known(data.active)) await redisCommand(['SET', 'certset_active', String(data.active)]);
  if (known(data.base)) await redisCommand(['SET', 'certset_base', String(data.base)]);
  certCachesClear();
  return { live: nLive, sets: sets.length };
}

async function handlePanelDo(action, chatId, messageId, userId, fromUser) {
  if (action.startsWith('test_cert:')) {
    const tier = action.split(':')[1];
    if (!CERT_TIERS.includes(tier)) return;
    try {
      await sendCardPreview(chatId, tier, fromUser,
        `🧪 <b>Live Certificate Preview — ${tier.toUpperCase()} Card</b>\n\nTemplate render test OK! Supporters ke support karne par isi design me text render hoga.`,
        { inline_keyboard: [[{ text: '📐 Adjust Text', callback_data: `panel:lay:${tier}:name:sel:1` }], [{ text: '⬅️ Back to Card', callback_data: `panel:s:cert_${tier}` }]] });
    } catch (e) {
      await tgSendText(chatId, `❌ Certificate generate nahi ho paya: ${esc(e.message)}`, { parse_mode: 'HTML' });
    }
    return;
  }

  if (action === 'cert_status') {
    const lines = [panelHeader('ℹ️', 'CARDS STATUS', 'Live template + layout of every tier')];
    for (const t of CERT_TIERS) lines.push(await certTierStatusLine(t));
    lines.push('', '<i>Bot upload = Redis me saved (Render restart se safe). Default file = GitHub wali original.</i>');
    await tgEdit(chatId, messageId, lines.join('\n'), { inline_keyboard: [[{ text: '⬅️ Back to Cards', callback_data: 'panel:s:cert' }]] }, 'HTML');
    return;
  }

  if (action.startsWith('cert_undo:')) {
    const tier = action.split(':')[1];
    if (!CERT_TIERS.includes(tier)) return;
    let ok = false;
    try { ok = await undoCertificateTemplate(tier); } catch (e) { console.error('[cert] undo failed:', e.message); }
    if (!ok) {
      await tgEdit(chatId, messageId, `⚠️ <b>${CERT_META[tier].label}</b> ke liye koi purana template saved nahi hai.\n\n<i>Pehli baar template update karne ke baad hi Undo kaam karta hai.</i>`,
        { inline_keyboard: [[{ text: '⬅️ Back to Card', callback_data: `panel:s:cert_${tier}` }]] }, 'HTML');
      return;
    }
    try {
      await sendCardPreview(chatId, tier, fromUser, `↩️ <b>${CERT_META[tier].label} template wapas purane par aa gaya.</b>\n\nPhir se Undo dabane par naya wala wapas aa jayega.`,
        { inline_keyboard: [[{ text: '↩️ Undo / Redo', callback_data: `panel:do:cert_undo:${tier}` }], [{ text: '⬅️ Back to Card', callback_data: `panel:s:cert_${tier}` }]] });
      tgDeleteMsgIn(chatId, messageId);
    } catch (e) {
      await tgSendText(chatId, `✅ Undo ho gaya, par preview nahi ban paya: ${esc(e.message)}`, { parse_mode: 'HTML' });
    }
    return;
  }

  if (action.startsWith('cert_guide:')) {
    const tier = action.split(':')[1];
    if (!CERT_TIERS.includes(tier)) return;
    try {
      const t = CERT_META[tier].test;
      const img = await renderCertificate({ name: 'Name Here', totalDays: t.days, streak: t.streak, tier, issuedAt: Date.now(), highlight: 'all', guideOnly: true });
      await sendCertificatePhoto(chatId, img, `🧭 <b>Layout Guide — ${CERT_META[tier].label}</b>\nCyan boxes = jahan bot text likhega. Is image ko ChatGPT me reference ke taur par attach karo.`,
        { inline_keyboard: [[{ text: '⬅️ Back to Card', callback_data: `panel:s:cert_${tier}` }]] });
      await sendPromptMessage(chatId);
    } catch (e) { await tgSendText(chatId, `❌ Guide ban nahi paya: ${esc(e.message)}`, { parse_mode: 'HTML' }); }
    return;
  }

  if (action === 'cert_draft_toggle') {
    const on = !(await certDraftOn());
    if (on) await redisCommand(['SET', 'certdraft_mode', '1']); else await redisCommand(['DEL', 'certdraft_mode']);
    await tgEdit(chatId, messageId, on
      ? '📝 <b>Draft Mode ON</b>\n\nAb 📤 Update Template se bheja naya card pehle <b>draft</b> banega — sirf aapko dikhega. ✅ Publish dabane par hi sabke liye live hoga.\n<i>Festival Sets activate karne par hi live hote hain.</i>'
      : '📝 <b>Draft Mode OFF</b>\n\nAb naya upload ki gayi template seedha LIVE hogi.',
      { inline_keyboard: [[{ text: '⬅️ Back to Cards', callback_data: 'panel:s:cert' }]] }, 'HTML');
    return;
  }

  if (action === 'cert_announce') {
    try {
      await announceLiveCards(fromUser);
      await tgSendText(chatId, '📣 <b>Announce ho gaya!</b> Naye cards support topic me post ho gaye.', { parse_mode: 'HTML' });
    } catch (e) { await tgSendText(chatId, `❌ Announce nahi hua: ${esc(e.message)}`, { parse_mode: 'HTML' }); }
    return;
  }

  if (action === 'cert_backup') {
    try { await sendCardsBackup(chatId); }
    catch (e) { await tgSendText(chatId, `❌ Backup nahi ban paya: ${esc(e.message)}`, { parse_mode: 'HTML' }); }
    return;
  }

  if (action.startsWith('cert_pkg:')) {
    // Drops the bot-uploaded template + layout so the card goes back to the file shipped in GitHub (assets/cert/<tier>.png).
    const tier = action.split(':')[1];
    if (!CERT_TIERS.includes(tier)) return;
    try {
      for (const k of ['certtpl:', 'certlayout:', 'certtpl_prev:', 'certlayout_prev:']) await redisCommand(['DEL', k + tier]);
      await redisCommand(['DEL', 'certset_active']);
      certCachesClear(tier);
      await sendCardPreview(chatId, tier, fromUser, `🗂 <b>${CERT_META[tier].label} card ab GitHub wali file se chal raha hai.</b>\n\nBot se upload kiya hua template hata diya gaya.`,
        { inline_keyboard: [[{ text: '📐 Adjust Text', callback_data: `panel:lay:${tier}:name:sel:1` }], [{ text: '⬅️ Back to Card', callback_data: `panel:s:cert_${tier}` }]] });
      tgDeleteMsgIn(chatId, messageId);
    } catch (e) {
      await tgSendText(chatId, `❌ Fail hua: ${esc(e.message)}`, { parse_mode: 'HTML' });
    }
    return;
  }

  if (action === 'restore_default_certs') {
    let done = [];
    try { done = await restoreDefaultCertificates(); } catch (e) { console.error('[cert] restore failed:', e.message); }
    if (done.length) {
      await tgEdit(chatId, messageId, `✅ <b>Default Templates Restored!</b>\n\nOriginal ${done.map(t => CERT_META[t].label).join(', ')} card templates wapas restore ho gaye hain (text layout bhi default).`,
        { inline_keyboard: [[{ text: '🎖️ Cards Menu', callback_data: 'panel:s:cert' }]] }, 'HTML');
    } else {
      await tgEdit(chatId, messageId, '⚠️ Defaults backup folder nahi mila ya restore fail hua.', { inline_keyboard: [[{ text: '🎖️ Cards Menu', callback_data: 'panel:s:cert' }]] });
    }
    return;
  }

  if (action === 'comm_stats') {
    const all = await fetchAllSupporters();
    let active = 0, withDays = 0, totalDaysCount = 0;
    for (const s of all) {
      if (s.totalDays) {
        withDays++;
        totalDaysCount += (s.totalDays || 0);
      }
      if (isCurrentlyActive(s)) active++;
    }
    const text = [
      panelHeader('👥', 'COMMUNITY STATS', 'Real-time Supporter Progress'),
      `👥 <b>Total Supporters:</b> <code>${all.length}</code>`,
      `⚡ <b>Active Today (12h):</b> <code>${active}</code>`,
      `🎯 <b>With &gt;0 Support:</b> <code>${withDays}</code>`,
      `📅 <b>Total Support Days:</b> <code>${totalDaysCount}</code>`,
      `🔥 <b>Leaderboard Command:</b> <code>/top10</code>`
    ].join('\n');
    await tgEdit(chatId, messageId, text, {
      inline_keyboard: [[{ text: '🔄 Refresh', callback_data: 'panel:do:comm_stats' }], [{ text: '⬅️ Back', callback_data: 'panel:s:stats' }]]
    }, 'HTML');
    return;
  }

  if (action === 'vault_stats') {
    const all = await cbAllFiles();
    const tv = all.filter(f => f.category === 'tv').length;
    const phone = all.filter(f => f.category === 'phone').length;
    const liveTv = all.filter(f => f.category === 'live_tv').length;
    const stats = await cbGetStats();
    const text = [
      panelHeader('📦', 'VAULT STATS', 'Files & Delivery Overview'),
      `📦 <b>Total Files:</b> <code>${all.length}</code>`,
      `📺 <b>Android TV:</b> <code>${tv}</code>`,
      `📱 <b>Phone / Mobile:</b> <code>${phone}</code>`,
      `📡 <b>Live TV:</b> <code>${liveTv}</code>`,
      `📨 <b>Total Requests:</b> <code>${stats.total}</code>`,
      `✅ <b>Delivered:</b> <code>${stats.matched}</code>`
    ].join('\n');
    await tgEdit(chatId, messageId, text, {
      inline_keyboard: [[{ text: '🔄 Refresh', callback_data: 'panel:do:vault_stats' }], [{ text: '⬅️ Back', callback_data: 'panel:s:stats' }]]
    }, 'HTML');
    return;
  }

  if (action === 'shortlink_stats') {
    const cfg = await getShortlinkConfig();
    const custom = !cfg.provider || cfg.provider === 'custom';
    const text = [
      panelHeader('🔗', 'MONETIZATION & ADS', 'Active Configuration'),
      `🌐 <b>Provider:</b> <code>${esc(cfg.provider || 'custom')}</code>`,
      custom ? `🎯 <b>Task Portal:</b> <code>${esc(CUSTOM_TASK_BASE)}</code>` : `🔌 <b>API URL:</b> <code>${esc(cfg.apiUrl)}</code>`,
      `🔑 <b>API Key:</b> <code>${custom ? '(custom ads)' : maskKey(cfg.apiKey)}</code>`,
      custom ? '📡 <b>Mode:</b> <code>Adsterra task portal</code>' : '📡 <b>Fallback:</b> <code>Custom Ad Task (agar provider fail ho)</code>',
      '',
      '<i>Badalne ke liye Settings → "Set Shortlink Provider"; check karne ke liye "Test Shortlink".</i>'
    ].join('\n');
    await tgEdit(chatId, messageId, text, {
      inline_keyboard: [[{ text: '🧪 Test Shortlink', callback_data: 'panel:do:shortlink_test' }], [{ text: '⬅️ Back', callback_data: 'panel:s:stats' }]]
    }, 'HTML');
    return;
  }

  if (action === 'nudge_toggle') {
    if (!(await nudgeAllowed(userId))) { await tgSendText(chatId, '❌ Reminder on/off sirf Owner / panel-admin kar sakte hain.'); return; }
    const st = await nudgeSettings();
    const text = await nudgeApply([st.enabled ? 'off' : 'on']);
    await tgEdit(chatId, messageId, text, { inline_keyboard: [[{ text: st.enabled ? '✅ Turn ON' : '⛔ Turn OFF', callback_data: 'panel:do:nudge_toggle' }], [{ text: '⏱ Cooldown', callback_data: 'panel:ask:nudge_cooldown' }, { text: '🎨 Settings', callback_data: 'panel:s:settings' }]] }, 'HTML');
    return;
  }

  if (action === 'shortlink_test') {
    const cfg = await getShortlinkConfig();
    await tgEdit(chatId, messageId, await shortlinkTestText(cfg), { inline_keyboard: [[{ text: '🔗 Config', callback_data: 'panel:do:shortlink_stats' }, { text: '🎨 Settings', callback_data: 'panel:s:settings' }]] }, 'HTML');
    return;
  }

  if (action === 'top_supporters') {
    const all = await fetchAllSupporters();
    all.sort((a, b) => (b.totalDays || 0) - (a.totalDays || 0));
    const top = all.slice(0, 5);
    const lines = [panelHeader('🏆', 'TOP 5 SUPPORTERS', 'All-time Hall of Fame')];
    if (!top.length) lines.push('<i>Abhi koi supporter nahi hai.</i>');
    else top.forEach((s, i) => {
      lines.push(`${medal(i)} <b>${esc(s.name || 'Supporter')}</b> — <code>${s.totalDays || 0} din</code> (🔥 ${s.streak || 0})`);
    });
    await tgEdit(chatId, messageId, lines.join('\n'), {
      inline_keyboard: [[{ text: '⬅️ Back', callback_data: 'panel:s:stats' }]]
    }, 'HTML');
    return;
  }

  if (action === 'freepass_status') {
    const until = await getGlobalFreePassUntil();
    const active = until && Date.now() < until;
    const text = [
      panelHeader('🔓', 'FREE-PASS STATUS'),
      active
        ? `🟢 <b>Free-Pass Active Hai!</b>\n⏳ <b>Remaining:</b> <code>${formatRemaining(until - Date.now())}</code>\nAbhi sabhi users bina support kiye access kar sakte hain.`
        : `🔴 <b>Free-Pass Band Hai.</b>\nSupport requirement normal chal rahi hai.`
    ].join('\n');
    await tgEdit(chatId, messageId, text, {
      inline_keyboard: [[{ text: '⬅️ Back', callback_data: 'panel:s:access' }]]
    }, 'HTML');
    return;
  }

  if (action === 'freepass_off') {
    await redisCommand(['DEL', 'global_free_pass_until']);
    const text = [
      panelHeader('⛔', 'FREE-PASS STOPPED'),
      '✅ Free-pass band kar diya gaya hai. Ab sabhi users ke liye normal support verification required hai.'
    ].join('\n');
    await tgEdit(chatId, messageId, text, {
      inline_keyboard: [[{ text: '⬅️ Back', callback_data: 'panel:s:access' }]]
    }, 'HTML');
    return;
  }

  if (action === 'admin_list') {
    const dynamic = await cbGetDynamicAdmins();
    const owners = cbOwnerIds();
    const text = [
      panelHeader('👥', 'AUTHORIZED ADMINS'),
      '👑 <b>Permanent Owners:</b>\n' + owners.map(o => `• <code>${o}</code>`).join('\n'),
      '',
      '🛡️ <b>Dynamic Admins:</b>\n' + (dynamic.length ? dynamic.map(a => `• <code>${a}</code>`).join('\n') : '<i>(Koi extra admin nahi hai)</i>')
    ].join('\n');
    await tgEdit(chatId, messageId, text, {
      inline_keyboard: [[{ text: '⬅️ Back', callback_data: 'panel:s:admins' }]]
    }, 'HTML');
    return;
  }

  if (action === 'topic_status') {
    const t = await getNotifyTarget();
    const text = [
      panelHeader('📍', 'SUPPORT NOTIFICATION TARGET'),
      `💬 <b>Chat ID:</b> <code>${t.chatId || 'Not set'}</code>`,
      `🧵 <b>Thread / Topic ID:</b> <code>${t.threadId || 'Main General / None'}</code>`,
      `⚙️ <b>Config Source:</b> <code>${t.source}</code>`,
      '',
      '<i>Topic change karne ke liye group me us topic ke andar <code>/setsupporttopic</code> likho.</i>'
    ].join('\n');
    await tgEdit(chatId, messageId, text, {
      inline_keyboard: [[{ text: '⬅️ Back', callback_data: 'panel:s:settings' }]]
    }, 'HTML');
    return;
  }

  if (action === 'vault_summary') {
    const all = (await cbAllFiles()).slice(0, 10);
    const lines = [panelHeader('📋', 'RECENT VAULT FILES', 'Last 10 indexed items')];
    if (!all.length) lines.push('<i>Vault abhi khaali hai.</i>');
    else all.forEach((f, i) => lines.push(`${i + 1}. <b>${esc(f.fileName)}</b> [${f.category}]`));
    await tgEdit(chatId, messageId, lines.join('\n'), {
      inline_keyboard: [[{ text: '⬅️ Back', callback_data: 'panel:s:vault' }]]
    }, 'HTML');
    return;
  }
}

async function handlePanelCallback(cb) {
  const chatId = cb.message.chat.id;
  const messageId = cb.message.message_id;
  const userId = cb.from.id;
  const isOwner = cbOwnerIds().includes(String(userId));
  const parts = cb.data.split(':');
  const kind = parts[1] || 'home';
  const action = parts.slice(2).join(':');

  if (kind === 'home') {
    panelPending.delete(userId);
    await tgEdit(chatId, messageId, panelHomeText(cb.from.first_name, isOwner), panelHomeKeyboard(isOwner), 'HTML');
    return;
  }

  if (kind === 's') {
    panelPending.delete(userId);
    const sec = _PANEL_SECTIONS[action];
    if (!sec) return;
    if (sec.ownerOnly && !isOwner) {
      await fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/answerCallbackQuery`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ callback_query_id: cb.id, text: '❌ Ye section sirf Owner ke liye hai.', show_alert: true })
      }).catch(() => {});
      return;
    }
    let text = panelSectionText(sec.title, sec.sub);
    if (action.startsWith('cert_') && CERT_TIERS.includes(action.slice(5))) {
      const tr = action.slice(5);
      const waiting = await redisCommand(['GET', 'certdrafttpl:' + tr]).catch(() => null);
      text = text.replace('\n👇 Ek action chuno:', '\n' + await certTierStatusLine(tr) + (waiting ? '\n📝 <b>Draft waiting</b> — 📝 Draft button se dekho' : '') + '\n\n👇 Ek action chuno:');
    } else if (action === 'cert') {
      text = text.replace('\n👇 Ek action chuno:', '\n📝 Draft mode: <b>' + (await certDraftOn() ? 'ON' : 'OFF') + '</b>\n\n👇 Ek action chuno:');
    }
    await tgEdit(chatId, messageId, text, panelSectionKeyboard(action), 'HTML');
    return;
  }

  if (kind === 'set') {
    try { await handleSetCallback(cb, action); }
    catch (e) { console.error('[sets] failed:', e.message); await tgSendText(chatId, `❌ ${esc(e.message)}`, { parse_mode: 'HTML' }); }
    return;
  }

  if (kind === 'draft' || kind === 'hist') {
    panelPending.delete(userId);
    try { await (kind === 'draft' ? handleDraftCallback : handleHistCallback)(cb, action); }
    catch (e) { console.error(`[${kind}] failed:`, e.message); await tgSendText(chatId, `❌ ${esc(e.message)}`, { parse_mode: 'HTML' }); }
    return;
  }

  if (kind === 'lay') {
    panelPending.delete(userId);
    try { await handleLayoutCallback(cb, action); }
    catch (e) { console.error('[layout] failed:', e.message); await tgSendText(chatId, `❌ Layout update fail hua: ${esc(e.message)}`, { parse_mode: 'HTML' }); }
    return;
  }

  if (kind === 'do') {
    await handlePanelDo(action, chatId, messageId, userId, cb.from);
    return;
  }

  if (kind === 'ask') {
    const askDef = _PANEL_ASK[action];
    if (!askDef) return;
    if (askDef.ownerOnly && !isOwner) {
      await fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/answerCallbackQuery`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ callback_query_id: cb.id, text: '❌ Ye action sirf Owner ke liye hai.', show_alert: true })
      }).catch(() => {});
      return;
    }
    panelPending.set(userId, { action, ts: Date.now(), section: askDef.section });
    await tgEdit(chatId, messageId, panelPromptText(askDef.title, askDef.instruction), panelPromptKeyboard(askDef.section), 'HTML');
    return;
  }
}

async function handlePanelPendingInput(msg) {
  const userId = msg.from && msg.from.id;
  if (!userId) return false;
  const pending = panelPending.get(userId);
  if (!pending) return false;

  // TTL check
  if (Date.now() - pending.ts > PANEL_PENDING_TTL) {
    panelPending.delete(userId);
    return false;
  }

  const action = pending.action;
  const isOwner = cbOwnerIds().includes(String(userId));

  // A slash command (/panel, /start, ...) always cancels the waiting prompt instead of being swallowed as its answer.
  if (typeof msg.text === 'string' && msg.text.trim().startsWith('/')) { panelPending.delete(userId); return false; }

  // Restore a cards backup (.json.gz) — owner only
  if (action === 'restore_backup') {
    if (!isOwner) { panelPending.delete(userId); return false; }
    if (!msg.document) { await tgSendText(msg.chat.id, '⚠️ Backup <b>file</b> (.json.gz) bhejo. Cancel ke liye koi /command bhejo.', { parse_mode: 'HTML' }); return true; }
    panelPending.delete(userId);
    try {
      const r = await restoreCardsBackup(await downloadTelegramFile(msg.document.file_id));
      await tgSendText(msg.chat.id, `✅ <b>Backup restore ho gaya!</b>\nLive cards: ${r.live} · Sets: ${r.sets}`, { parse_mode: 'HTML', reply_markup: { inline_keyboard: [[{ text: '🎖️ Cards Menu', callback_data: 'panel:s:cert' }]] } });
    } catch (e) { await tgSendText(msg.chat.id, `❌ ${esc(e.message)}`, { parse_mode: 'HTML' }); }
    return true;
  }

  // Festival Sets prompts (new set name, schedule dates, 3-card wizard)
  // (exact names only: other prompts such as set_season / set_shortlink also start with "set_" and must reach their own handlers below)
  if (action === 'set_new' || action === 'set_snap' || action.startsWith('set_sched:') || action.startsWith('set_wiz:')) return handleSetPending(msg, action, userId);

  // Case 1: Certificate Template Upload
  if (action.startsWith('upload_cert:')) {
    const tier = action.split(':')[1];
    if (!CERT_TIERS.includes(tier)) { panelPending.delete(userId); return false; }
    const doc = msg.document && (/^image\//i.test(msg.document.mime_type || '') || /\.(png|jpe?g|webp)$/i.test(msg.document.file_name || '')) ? msg.document : null;
    const media = msg.photo ? msg.photo[msg.photo.length - 1] : doc;
    if (!media) {
      await tgSendText(msg.chat.id, `⚠️ <b>Photo ya Image bhejo!</b>\n\nNaye ${tier.toUpperCase()} card ka template image attach karke bhejo.\n<i>Cancel karna ho to koi bhi /command (jaise /panel) bhej do.</i>`, { parse_mode: 'HTML' });
      return true;
    }
    panelPending.delete(userId);
    const waitMsg = await tgSendText(msg.chat.id, `⏳ <b>${tier.toUpperCase()} Card download & save ho raha hai...</b>`, { parse_mode: 'HTML' });
    try {
      const imgBuf = await downloadTelegramFile(media.file_id);
      if (await certDraftOn()) {                                   // Draft Mode: wait for Publish instead of going live
        await saveCertificateDraft(tier, imgBuf);
        if (waitMsg && waitMsg.result) tgDeleteMsgIn(msg.chat.id, waitMsg.result.message_id);
        await sendDraftPreview(msg.chat.id, tier, msg.from, msg.photo ? 'ℹ️ Photo ki tarah bheji gayi, isliye Telegram ne compress kiya. Best quality ke liye agli baar <b>File/Document</b> ki tarah bhejo.' : '');
        return true;
      }
      const prep = await saveCertificateTemplate(tier, imgBuf);
      if (waitMsg && waitMsg.result) tgDeleteMsgIn(msg.chat.id, waitMsg.result.message_id);
      const info = await templateInfo(tier);
      const notes = [];
      if (msg.photo) notes.push('ℹ️ Photo ki tarah bheji gayi, isliye Telegram ne compress kiya. Best quality ke liye agli baar <b>File/Document</b> ki tarah bhejo.');
      if (Math.abs(prep.aspect - 16 / 9) > 0.06) notes.push('⚠️ Image 16:9 nahi hai — text thoda idhar-udhar ho sakta hai, 📐 Adjust Text se theek kar lo.');
      await sendCardPreview(msg.chat.id, tier, msg.from,
        `✅ <b>${tier.toUpperCase()} Card Template Updated!</b>\n\n📄 <code>${prep.width}×${prep.height}</code> · layout: <b>${certLayoutLabel(info)}</b>\nYe raha live rendered preview 👆 — site aur bot dono jagah ab yahi chalega (Render restart se bhi safe).\n\n<i>Text sahi jagah na ho to neeche se 🎆 Festival / 🏛 Classic style chuno ya 📐 Adjust Text karo.</i>` + (notes.length ? '\n\n' + notes.join('\n') : ''),
        { inline_keyboard: [
          [{ text: '📐 Adjust Text', callback_data: `panel:lay:${tier}:name:sel:1` }, { text: '↩️ Undo', callback_data: `panel:do:cert_undo:${tier}` }],
          [{ text: '🎆 Festival style', callback_data: `panel:lay:${tier}:name:fest:1` }, { text: '🏛 Classic style', callback_data: `panel:lay:${tier}:name:classic:1` }],
          [{ text: '📣 Announce', callback_data: 'panel:do:cert_announce' }],
          [{ text: '🎖️ Cards Menu', callback_data: 'panel:s:cert' }, { text: '🏠 Panel Home', callback_data: 'panel:home' }]
        ] });
    } catch (err) {
      if (waitMsg && waitMsg.result) tgDeleteMsgIn(msg.chat.id, waitMsg.result.message_id);
      await tgSendText(msg.chat.id, `❌ Template update fail hua: ${esc(err.message)}`, { parse_mode: 'HTML', reply_markup: { inline_keyboard: [[{ text: '🎖️ Cards Menu', callback_data: 'panel:s:cert' }]] } });
    }
    return true;
  }

  // Text inputs
  const rawText = (msg.text || '').trim();
  if (!rawText) return false;
  panelPending.delete(userId);

  if (action === 'broadcast') {
    const userIds = await cbGetAllUserIds();
    let sent = 0, failed = 0;
    await tgSendText(msg.chat.id, `📢 Broadcast bhej raha hu ${userIds.length} users ko...`, { parse_mode: 'HTML' });
    for (const uid of userIds) {
      try {
        let r = await tgSendText(uid, rawText, { parse_mode: 'HTML' });
        if (r && !r.ok && /parse entities|unsupported start tag|can't find end/i.test(r.description || '')) r = await tgSendText(uid, rawText); // not valid HTML -> send as plain text
        if (r && r.ok) sent++;
        else failed++;
      } catch (e) { failed++; }
      await new Promise(r => setTimeout(r, 60));
    }
    await tgSendText(msg.chat.id, `✅ <b>Broadcast Complete!</b>\n\nBheja: <b>${sent}</b>\nFail hua: <b>${failed}</b>`, {
      parse_mode: 'HTML',
      reply_markup: { inline_keyboard: [[{ text: '🏠 Panel Home', callback_data: 'panel:home' }]] }
    });
    return true;
  }

  if (action === 'freepass_set') {
    if (rawText.toLowerCase() === 'off') {
      await redisCommand(['DEL', 'global_free_pass_until']);
      await tgSendText(msg.chat.id, `✅ Free-pass band kar diya.`, {
        reply_markup: { inline_keyboard: [[{ text: '🔑 Access Menu', callback_data: 'panel:s:access' }]] }
      });
      return true;
    }
    const durationMs = parseDuration(rawText);
    if (!durationMs) {
      await tgSendText(msg.chat.id, `❌ Format samajh nahi aaya. Example: <code>1d</code>, <code>12h</code>, <code>30m</code>`, { parse_mode: 'HTML' });
      return true;
    }
    const until = Date.now() + durationMs;
    await redisCommand(['SET', 'global_free_pass_until', String(until)]);
    await tgSendText(msg.chat.id, `✅ <b>Free-pass ON ho gaya!</b>\nAgle <b>${formatRemaining(durationMs)}</b> tak sabhi users ke liye support free hai.`, {
      parse_mode: 'HTML',
      reply_markup: { inline_keyboard: [[{ text: '🔑 Access Menu', callback_data: 'panel:s:access' }]] }
    });
    return true;
  }

  if (action === 'check_user') {
    const target = rawText.replace(/^@/, '').trim();
    let supporter = null;
    let targetId = target;
    if (!/^\d+$/.test(target)) {
      const keys = await redisCommand(['KEYS', 'supporter:tg_*']);
      for (const k of (keys || [])) {
        const raw = await redisCommand(['GET', k]);
        if (!raw) continue;
        const rec = JSON.parse(raw);
        if (rec.username && rec.username.toLowerCase() === target.toLowerCase()) {
          targetId = k.replace('supporter:tg_', '');
          supporter = rec;
          break;
        }
      }
    } else {
      const raw = await redisCommand(['GET', 'supporter:tg_' + targetId]);
      if (raw) supporter = JSON.parse(raw);
    }
    if (!supporter) {
      await tgSendText(msg.chat.id, `❌ User <b>${esc(target)}</b> ka koi support record nahi mila.`, { parse_mode: 'HTML' });
    } else {
      const active = isCurrentlyActive(supporter);
      const text = [
        panelHeader('🩺', 'USER STATUS REPORT', esc(supporter.name || target)),
        `👤 <b>Name:</b> ${esc(supporter.name || '-')}`,
        `🆔 <b>Telegram ID:</b> <code>${targetId}</code>`,
        `🌐 <b>Username:</b> ${supporter.username ? '@' + esc(supporter.username) : 'None'}`,
        `🟢 <b>Current Status:</b> ${active ? 'Active ✅' : 'Expired ⏳'}`,
        `📅 <b>Total Days:</b> <code>${supporter.totalDays || 0}</code>`,
        `🔥 <b>Streak:</b> <code>${supporter.streak || 0} din</code>`,
        `👑 <b>Premium:</b> ${isPremiumSupporter(supporter) ? 'Yes 👑' : 'No 🔒'}`
      ].join('\n');
      await tgSendText(msg.chat.id, text, {
        parse_mode: 'HTML',
        reply_markup: { inline_keyboard: [[{ text: '🔑 Access Menu', callback_data: 'panel:s:access' }]] }
      });
    }
    return true;
  }

  if (action === 'test_cooldown') {
    const key = 'supporter:tg_' + userId;
    if (rawText.toLowerCase() === 'off') {
      try {
        const raw = await redisCommand(['GET', key]);
        if (raw) {
          const rec = JSON.parse(raw);
          delete rec.testCooldownMs;
          await redisCommand(['SET', key, JSON.stringify(rec)]);
          invalidateSupportersCache();
        }
      } catch (e) {}
      await tgSendText(msg.chat.id, `✅ Test cooldown off! Normal 12 hours restore ho gaya.`, {
        reply_markup: { inline_keyboard: [[{ text: '🔑 Access Menu', callback_data: 'panel:s:access' }]] }
      });
      return true;
    }
    const durationMs = parseDuration(rawText);
    if (!durationMs) {
      await tgSendText(msg.chat.id, `❌ Format invalid. Try: <code>2m</code> ya <code>1h</code>`, { parse_mode: 'HTML' });
      return true;
    }
    try {
      const raw = await redisCommand(['GET', key]);
      const rec = raw ? JSON.parse(raw) : { name: 'Admin', streak: 0, totalDays: 0, supportDates: [], lastSupportAt: null, firstSupportAt: null };
      rec.testCooldownMs = durationMs;
      await redisCommand(['SET', key, JSON.stringify(rec)]);
      invalidateSupportersCache();
      await tgSendText(msg.chat.id, `✅ Tumhare liye cooldown <b>${formatRemaining(durationMs)}</b> set ho gaya!`, {
        parse_mode: 'HTML',
        reply_markup: { inline_keyboard: [[{ text: '🔑 Access Menu', callback_data: 'panel:s:access' }]] }
      });
    } catch (e) {
      await tgSendText(msg.chat.id, `❌ Save nahi ho paya.`);
    }
    return true;
  }

  if (action === 'add_admin') {
    if (!isOwner) {
      await tgSendText(msg.chat.id, `❌ Sirf Owner hi admin add kar sakte hain.`);
      return true;
    }
    if (!/^\d+$/.test(rawText)) {
      await tgSendText(msg.chat.id, `❌ Numeric Telegram ID bhejo (e.g. 123456789).`);
      return true;
    }
    await cbAddAdmin(rawText);
    setAdminCommands(rawText, true).catch(() => {});
    await tgSendText(msg.chat.id, `✅ User ID <code>${rawText}</code> ko admin bana diya gaya!`, {
      parse_mode: 'HTML',
      reply_markup: { inline_keyboard: [[{ text: '👥 Admin List', callback_data: 'panel:do:admin_list' }]] }
    });
    return true;
  }

  if (action === 'remove_admin') {
    if (!isOwner) {
      await tgSendText(msg.chat.id, `❌ Sirf Owner hi admin hata sakte hain.`);
      return true;
    }
    if (cbOwnerIds().includes(rawText)) {
      await tgSendText(msg.chat.id, `⚠️ Owner ko remove nahi kiya ja sakta.`);
      return true;
    }
    await cbRemoveAdmin(rawText);
    setAdminCommands(rawText, false).catch(() => {});
    await tgSendText(msg.chat.id, `🗑️ User ID <code>${rawText}</code> ki admin power hata di gayi.`, {
      parse_mode: 'HTML',
      reply_markup: { inline_keyboard: [[{ text: '👥 Admin List', callback_data: 'panel:do:admin_list' }]] }
    });
    return true;
  }

  if (action === 'set_season') {
    const theme = rawText.toLowerCase();
    if (!['normal', 'navratri', 'diwali'].includes(theme)) {
      await tgSendText(msg.chat.id, `⚠️ Valid options: <code>normal</code> | <code>navratri</code> | <code>diwali</code>`, { parse_mode: 'HTML' });
      return true;
    }
    let s = {};
    try {
      const raw = await redisCommand(['GET', 'settings']);
      if (raw) s = JSON.parse(raw);
    } catch (e) {}
    s.seasonTheme = theme;
    await redisCommand(['SET', 'settings', JSON.stringify(s)]);
    await tgSendText(msg.chat.id, `✅ Season theme updated to: <b>${theme.toUpperCase()}</b>!`, {
      parse_mode: 'HTML',
      reply_markup: { inline_keyboard: [[{ text: '🎨 Settings Menu', callback_data: 'panel:s:settings' }]] }
    });
    return true;
  }

  if (action === 'nudge_cooldown') {
    if (!(await nudgeAllowed(userId))) { await tgSendText(msg.chat.id, '❌ Ye setting sirf Owner / panel-admin badal sakte hain.'); return true; }
    const reply = await nudgeApply(['cooldown', rawText]);
    if (/^⚠️/.test(reply)) panelPending.set(userId, { action: 'nudge_cooldown', ts: Date.now(), section: 'settings' }); // let them retype
    await tgSendText(msg.chat.id, reply, { parse_mode: 'HTML', reply_markup: { inline_keyboard: [[{ text: '💬 Reminder On/Off', callback_data: 'panel:do:nudge_toggle' }, { text: '🎨 Settings', callback_data: 'panel:s:settings' }]] } });
    return true;
  }

  if (action === 'set_shortlink') {
    const words = rawText.split(/\s+/);
    const r = await applyShortlinkSetting(words);
    if (r.ok && words.length > 1 && msg.message_id) tgDeleteMsgIn(msg.chat.id, msg.message_id); // the message contains the API key
    await tgSendText(msg.chat.id, r.text, {
      parse_mode: 'HTML',
      reply_markup: { inline_keyboard: [[{ text: '🧪 Test Again', callback_data: 'panel:do:shortlink_test' }, { text: '🎨 Settings Menu', callback_data: 'panel:s:settings' }]] }
    });
    return true;
  }

  if (action === 'search_vault') {
    const results = await cbSearchFilesAll(rawText);
    if (!results.length) {
      await tgSendText(msg.chat.id, `❌ '${rawText}' ke liye Vault me koi file nahi mili.`);
      return true;
    }
    const buttons = results.slice(0, 15).map(f => [{ text: f.fileName.length > 40 ? f.fileName.slice(0, 37) + '…' : f.fileName, callback_data: `get:F${f.id}` }]);
    buttons.push([{ text: '🗄️ Vault Menu', callback_data: 'panel:s:vault' }]);
    await tgSendText(msg.chat.id, `🔎 <b>${results.length} results mile '${rawText}' ke liye:</b>\nTap karo deliver karne ke liye:`, {
      parse_mode: 'HTML',
      reply_markup: { inline_keyboard: buttons }
    });
    return true;
  }

  if (action === 'remove_file') {
    const count = await cbDeleteFilesByName(rawText);
    await tgSendText(msg.chat.id, count ? `🗑️ '${rawText}' se match hone wali <b>${count}</b> file(s) delete ho gayi.` : `❌ Koi file match nahi hui.`, {
      parse_mode: 'HTML',
      reply_markup: { inline_keyboard: [[{ text: '🗄️ Vault Menu', callback_data: 'panel:s:vault' }]] }
    });
    return true;
  }

  return false;
}

app.post('/api/telegram/webhook', async (req, res) => {
  res.sendStatus(200); // ack immediately — Telegram needs a fast response
  try {
    // ---- Inline menu button taps — everything happens in ONE message,
    // edited in place, with a Back button to return to the main menu ----
    const cb = req.body && req.body.callback_query;
    if (cb && process.env.TELEGRAM_BOT_TOKEN) {
      fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/answerCallbackQuery`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ callback_query_id: cb.id })
      }).catch(() => {});

      const chatId = cb.message.chat.id;
      const messageId = cb.message.message_id;
      const userId = cb.from.id;
      const isAdmin = await checkIsAdmin(userId);

      if (cb.data.startsWith('panel:')) {
        if (!isAdmin) {
          fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/answerCallbackQuery`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ callback_query_id: cb.id, text: '❌ Admins only.', show_alert: true })
          }).catch(() => {});
          return;
        }
        await handlePanelCallback(cb);
        return;
      }

      if (cb.data === 'menu') {
        const text = await buildWelcomeText(userId);
        await tgEdit(chatId, messageId, text, mainMenuKeyboard(isAdmin));
      } else if (cb.data === 'my_stats') {
        const { text, keyboard } = await buildMyStatsCard(userId);
        await tgEdit(chatId, messageId, text, keyboard, 'HTML');
      } else if (cb.data === 'leaderboard' || cb.data.startsWith('leaderboard:')) {
        const period = cb.data.includes(':') ? cb.data.split(':')[1] : 'all';
        const { text, keyboard } = await buildLeaderboardCard(period);
        await tgEdit(chatId, messageId, text, keyboard, 'HTML');
      } else if (cb.data === 'community_stats') {
        let totalUsers = 0, supportedCount = 0, activeCount = 0;
        try {
          const all = await fetchAllSupporters();
          totalUsers = all.length;
          const now = Date.now();
          for (const rec of all) {
            if (rec.totalDays) supportedCount++;
            if (rec.lastSupportAt && (now - rec.lastSupportAt) < 24 * 60 * 60 * 1000) activeCount++;
          }
        } catch (e) {}
        const text = `👥 Community Stats\n\n🔗 Total Logged In: ${totalUsers}\n✅ Total Supported: ${supportedCount}\n⚡ Active (last 24h): ${activeCount}`;
        await tgEdit(chatId, messageId, text, backKeyboard());
      } else if (cb.data === 'check_help' && isAdmin) {
        const text = `🔍 /check command\n\nKisi user ke message ko REPLY karke sirf /check likho, ya seedha /check username ya /check numeric-ID type karo.\n\nBot bata dega us insaan ne support kiya hai ya nahi — sirf admins hi use kar sakte hai.`;
        await tgEdit(chatId, messageId, text, backKeyboard());
      } else if (cb.data.startsWith('send:') || cb.data.startsWith('get:')) {
        // Search-result / browse-list button tap — deliver that exact file.
        const tag = cb.data.split(':', 2)[1];
        const result = await deliverSpecific(userId, tag);
        await cbLogRequest(result.success);
        await fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/answerCallbackQuery`, {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            callback_query_id: cb.id,
            text: result.success ? '✅ Sent to your Private Chat!' : `❌ ${result.error || 'Nahi bhej paya.'}`,
            show_alert: !result.success,
          })
        }).catch(() => {});
      } else if (cb.data === 'browse_menu') {
        const text = `🗂️ Browse by Category\n\nKis category ke items dekhne hai?`;
        await tgEdit(chatId, messageId, text, {
          inline_keyboard: [
            [{ text: '📱 Phone', callback_data: 'browse:phone:0' }, { text: '📡 Live TV', callback_data: 'browse:live_tv:0' }],
            [{ text: '📺 Android TV', callback_data: 'browse:tv:0' }],
            [{ text: '🔙 Back to Menu', callback_data: 'menu' }],
          ]
        });
      } else if (cb.data.startsWith('browse:')) {
        const [, category, pageStr] = cb.data.split(':');
        const page = parseInt(pageStr, 10) || 0;
        const { page: items, total } = await cbListItemsByCategories([category], page * CONTENT_PAGE_SIZE, CONTENT_PAGE_SIZE);
        const totalPages = Math.max(1, Math.ceil(total / CONTENT_PAGE_SIZE));
        const text = items.length
          ? `${CATEGORY_LABELS[category] || category} — Page ${page + 1}/${totalPages} (${total} items)\n\nTap karo jo bhejwana hai:`
          : `${CATEGORY_LABELS[category] || category} me abhi kuch nahi hai.`;
        await tgEdit(chatId, messageId, text, cbBrowseKeyboard(items, category, page, totalPages));
      }
      return;
    }

    // ---- CHANNEL POST — auto-index new files posted/reposted to the Vault ----
    // (this is also how the one-time migration of your old 76 files works —
    // see migrate_to_new_bot.py)
    const chpost = req.body && req.body.channel_post;
    if (chpost && String(chpost.chat.id) === String(process.env.VAULT_CHANNEL_ID)) {
      const media = chpost.document || chpost.photo?.[chpost.photo.length - 1] || chpost.video || chpost.animation;
      if (media) {
        const fileType = chpost.document ? 'document' : chpost.photo ? 'photo' : chpost.video ? 'video' : 'animation';
        const fileName = media.file_name || (chpost.caption || '').split('\n')[0] || 'file';
        const category = categorize(fileName, chpost.caption);
        try {
          await cbAddFile(media.file_unique_id, media.file_id, fileName, fileType, chpost.caption || '', category);
        } catch (e) { console.error('vault auto-index failed:', e.message); }
      }
      return;
    }

    const msg = req.body && req.body.message;
    if (!msg || !process.env.TELEGRAM_BOT_TOKEN) return;

    // ---- CONTENT COMMANDS (/tv /phone /filter /search /vault etc.) — DISABLED ----
    // Forward Bot owns /tv, /phone, /vault, /grantaccess etc. exclusively now.
    // Channel Support Bot must never intercept these — it was double-replying
    // and using its own separate admin-check that didn't recognize real
    // community admins, causing unwanted "please support" nudges for them.
    // if (msg.text && await handleContentCommand(msg)) return;

    // ---- CONTENT ADMIN UPLOAD — disabled for the same reason as above ----
    const uploadedMedia = false && (msg.document || msg.photo?.[msg.photo?.length - 1] || msg.video || msg.animation);
    if (msg.chat.type === 'private' && uploadedMedia && await cbIsAdmin(msg.from.id)) {
      const fileType = msg.document ? 'document' : msg.photo ? 'photo' : msg.video ? 'video' : 'animation';
      const fileName = uploadedMedia.file_name || (msg.caption || '').split('\n')[0] || 'file';
      const category = categorize(fileName, msg.caption);
      const rec = await cbAddFile(uploadedMedia.file_unique_id, uploadedMedia.file_id, fileName, fileType, msg.caption || '', category);
      if (rec && process.env.VAULT_CHANNEL_ID) {
        // Keep a backup copy in the Vault channel too
        tgSendFile(process.env.VAULT_CHANNEL_ID, rec).catch(() => {});
      }
      const sent = await tgSendText(msg.chat.id, rec
        ? `✅ Indexed as ${CATEGORY_LABELS[category]}!\n📄 ${fileName}`
        : `ℹ️ Yeh file pehle se Vault me hai.`);
      if (sent && sent.ok) cbScheduleDelete(msg.chat.id, sent.result.message_id);
      return;
    }

    // ---- CASE 1: Private DM to the bot (e.g. /start) ----
    if (msg.chat.type === 'private') {
      const userId = msg.from.id;
      const isAdmin = await checkIsAdmin(userId);

      // ---- Check pending panel inputs (image upload, broadcast text, etc.) ----
      if (isAdmin && await handlePanelPendingInput(msg)) return;

      // ---- Owner/admin-only bot commands: shortlink provider + free-pass ----
      if (isAdmin && msg.text && await handleOwnerCommand(msg.text.trim(), userId, msg.message_id)) return;

      // ---- /backupcards: send a backup file of all live cards + festival sets ----
      if (isAdmin && msg.text && /^\/backupcards(@\S+)?(\s|$)/i.test(msg.text.trim())) {
        try { await sendCardsBackup(userId); } catch (e) { await tgSendText(userId, `❌ Backup nahi ban paya: ${esc(e.message)}`, { parse_mode: 'HTML' }); }
        return;
      }

      // ---- /panel interactive control panel ----
      if (isAdmin && msg.text && /^\/panel(@\S+)?(\s|$)/i.test(msg.text.trim())) {
        panelPending.delete(userId);
        const isOwner = cbOwnerIds().includes(String(userId));
        await tgSend(userId, panelHomeText(msg.from.first_name, isOwner), panelHomeKeyboard(isOwner), 'HTML');
        return;
      }

      // ---- Direct slash-command shortcuts for the same cards the menu buttons show ----
      const cmd = msg.text ? msg.text.trim().toLowerCase() : '';
      if (/^\/mystatus(@\S+)?$/.test(cmd)) {
        const { text, keyboard } = await buildMyStatsCard(userId);
        await tgSend(userId, text, keyboard, 'HTML');
        return;
      }
      if (/^\/top10(@\S+)?$/.test(cmd)) {
        const { text, keyboard } = await buildLeaderboardCard();
        await tgSend(userId, text, keyboard, 'HTML');
        return;
      }

      // Admin commands that live in the blocks below (/preview, /supporttopic ...) must not be swallowed by the welcome card.
      if (!(isAdmin && /^\/(preview|testcard|testcert|supporttopic|setsupporttopic|resetsupporttopic)(@\S+)?(\s|$)/i.test(cmd))) {
        const text = await buildWelcomeText(userId);
        await tgSend(userId, text, mainMenuKeyboard(isAdmin));
        return;
      }
    }

    // ---- CASE 1.3: /setsupporttopic, /resetsupporttopic, /supporttopic — admin-only ----
    // Run /setsupporttopic INSIDE the topic where support cards should be posted.
    if (msg.text && /^\/(setsupporttopic|resetsupporttopic|supporttopic)(@\S+)?(\s|$)/i.test(msg.text.trim())) {
      const userId = msg.from ? msg.from.id : null;
      let allowed = false;
      if (msg.chat.type !== 'private' && msg.sender_chat && msg.sender_chat.id === msg.chat.id) allowed = true;
      if (!allowed && userId) allowed = await checkIsAdmin(userId, msg.chat.id);
      if (allowed) {
        const which = msg.text.trim().split(/\s+/)[0].toLowerCase().replace(/@\S+$/, '');
        const reply = (t) => tgSendText(msg.chat.id, t, {
          parse_mode: 'HTML',
          ...(msg.is_topic_message && msg.message_thread_id ? { message_thread_id: msg.message_thread_id } : {})
        });
        if (which === '/setsupporttopic') {
          if (msg.chat.type === 'private' || !msg.is_topic_message || !msg.message_thread_id) {
            await reply('⚠️ Yeh command community group ke <b>support topic ke andar</b> likho (General me nahi, DM me nahi).');
            return;
          }
          await redisCommand(['SET', 'notify_target', JSON.stringify({ chatId: msg.chat.id, threadId: msg.message_thread_id })]);
          await reply('✅ <b>Support topic set ho gaya!</b>\nAb saare support cards / certificates isi topic me aayenge.\nTest karne ke liye <code>/preview</code> likho.');
        } else if (which === '/resetsupporttopic') {
          await redisCommand(['DEL', 'notify_target']);
          await reply('♻️ Support topic hata diya. Ab cards wapas .env wale chat me jayenge.');
        } else {
          const t = await getNotifyTarget();
          await reply(`📍 <b>Support card target</b>\nChat: <code>${t.chatId || '-'}</code>\nTopic ID: <code>${t.threadId || '-'}</code>\nSource: ${t.source === 'bot' ? 'bot command' : '.env'}`);
        }
        return;
      }
    }

    // ---- CASE 1.4: /setseason <navratri|diwali|normal> — admin command to switch active festival season ----
    if (msg.text && /^\/setseason(@\S+)?(\s+|$)/i.test(msg.text.trim())) {
      const isPriv = msg.chat.type === 'private';
      const userId = msg.from ? msg.from.id : null;
      let allowed = false;
      if (!isPriv && msg.sender_chat && msg.sender_chat.id === msg.chat.id) {
        allowed = true;
      }
      if (!allowed && userId) {
        allowed = await checkIsAdmin(userId, msg.chat.id);
      }

      if (allowed) {
        const parts = msg.text.trim().split(/\s+/);
        const newTheme = (parts[1] || '').toLowerCase();
        if (!['navratri', 'diwali', 'normal'].includes(newTheme)) {
          await tgSendText(msg.chat.id, `⚠️ Valid options: <code>/setseason navratri</code>, <code>/setseason diwali</code>, <code>/setseason normal</code>`, {}, 'HTML');
          return;
        }

        let s = {};
        try {
          const raw = await redisCommand(['GET', 'settings']);
          if (raw) s = JSON.parse(raw);
        } catch (e) {}
        s.seasonTheme = newTheme;
        await redisCommand(['SET', 'settings', JSON.stringify(s)]);
        await tgSendText(msg.chat.id, `✅ <b>Season Theme Updated!</b>\n\nAb active season: <b>${newTheme.toUpperCase()}</b> ho gaya hai!\nGroup me <code>/preview</code> likh kar test kar sakte ho!`, {}, 'HTML');
        return;
      }
    }

    // ---- CASE 1.35: /nudge on|off|status|cooldown <min> — owner / panel-admin (anonymous group admins too), in any group topic ----
    if (msg.text && /^\/nudge(@\S+)?(\s|$)/i.test(msg.text.trim()) && msg.chat.type !== 'private') {
      const anonAdmin = !!(msg.sender_chat && msg.sender_chat.id === msg.chat.id);
      if (anonAdmin || (msg.from && await nudgeAllowed(msg.from.id))) {
        const reply = await nudgeApply(msg.text.trim().split(/\s+/).slice(1));
        await fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ chat_id: msg.chat.id, ...(msg.is_topic_message && msg.message_thread_id ? { message_thread_id: msg.message_thread_id } : {}), reply_to_message_id: msg.message_id, text: reply, parse_mode: 'HTML' })
        }).catch(() => {});
        return;
      }
      // anyone else: ignore the command here and let the normal group rules below apply
    }

    // ---- CASE 1.5: /preview (or /testcard) [silver|gold|diamond] — admin-only: posts a sample certificate ----
    if (msg.text && /^\/(testcard|preview|testcert)(@\S+)?(\s|$)/i.test(msg.text.trim())) {
      const isPriv = msg.chat.type === 'private';
      const userId = msg.from ? msg.from.id : null;
      let allowed = false;
      if (!isPriv && msg.sender_chat && msg.sender_chat.id === msg.chat.id) {
        allowed = true;
      }
      if (!allowed && userId) {
        allowed = await checkIsAdmin(userId, msg.chat.id);
      }

      if (allowed) {
        const nt = isPriv ? await getNotifyTarget() : null;
        const targetChat = isPriv ? (nt.chatId || msg.chat.id) : msg.chat.id;
        // DM preview -> goes to the configured support topic; preview typed inside a topic -> stays in that topic
        const targetThread = isPriv ? (nt.chatId ? nt.threadId : null) : (msg.is_topic_message ? msg.message_thread_id : null);
        const arg = (msg.text.trim().split(/\s+/)[1] || '').toLowerCase();
        let rec = null;
        if (userId) {
          try { const raw = await redisCommand(['GET', 'supporter:tg_' + userId]); rec = raw ? JSON.parse(raw) : null; } catch (e) {}
        }
        const fromName = [msg.from && msg.from.first_name, msg.from && msg.from.last_name].filter(Boolean).join(' ');
        const name = (rec && rec.name) || fromName || 'Test Supporter';
        const totalDays = (rec && rec.totalDays) || 49;
        const streak = (rec && rec.streak) || 21;
        const argTier = arg === 'diamond' ? 'platinum' : arg;            // the platinum slot is the Diamond card
        const tier = ['silver', 'gold', 'platinum'].includes(argTier) ? argTier : tierForDays(totalDays);
        try {
          const img = await renderCertificate({ name, totalDays, streak, tier, issuedAt: Date.now(), firstSupportAt: rec && rec.firstSupportAt });
          const out = await sendCertificatePhoto(targetChat, img, `🧪 <b>Admin Test Preview</b> — ${(tier === 'platinum' ? 'diamond' : tier).toUpperCase()} certificate`, null, targetThread);
          if (!out.ok) throw new Error(out.description || 'Telegram error');
          if (isPriv && String(targetChat) !== String(msg.chat.id)) {
            await tgSendText(msg.chat.id, `✅ Test certificate support topic me bhej diya gaya hai! Wahan check karo.`);
          }
        } catch (e) {
          console.error('[cert] preview failed:', e.message);
          await tgSendText(msg.chat.id, `❌ Certificate nahi ban paya: ${e.message}`);
        }
        return;
      }
    }

    // ---- CASE 1.5: /check — admin-only, works in ANY group/supergroup/topic ----
    // Reply to someone's message with /check, or type /check <username or ID>.
    if ((msg.chat.type === 'group' || msg.chat.type === 'supergroup') && msg.text && /^\/check(@\S+)?(\s|$)/i.test(msg.text.trim())) {
      const chatId = msg.chat.id;
      let isAdmin = false;
      try {
        const r = await fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/getChatMember?chat_id=${encodeURIComponent(chatId)}&user_id=${msg.from.id}`);
        const d = await r.json();
        if (d.ok) isAdmin = (d.result.status === 'administrator' || d.result.status === 'creator');
      } catch (e) { /* not admin on failure */ }
      if (!isAdmin) return; // silently ignore for non-admins

      const argMatch = msg.text.trim().match(/^\/check(?:@\S+)?\s*(.*)$/i);
      const arg = ((argMatch && argMatch[1]) || '').trim().replace(/^@/, '');

      let targetId = null, targetName = null, targetUsername = null;

      if (arg) {
        if (/^\d+$/.test(arg)) {
          targetId = arg;
        } else {
          // No numeric ID given — scan supporter records for a matching username.
          // Fine at small/medium scale; if the community grows very large this
          // could be swapped for a maintained username→id index.
          try {
            const keys = await redisCommand(['KEYS', 'supporter:tg_*']);
            for (const k of (keys || [])) {
              const raw = await redisCommand(['GET', k]);
              if (!raw) continue;
              const rec = JSON.parse(raw);
              if (rec.username && rec.username.toLowerCase() === arg.toLowerCase()) {
                targetId = k.replace('supporter:tg_', '');
                targetName = rec.name;
                targetUsername = rec.username;
                break;
              }
            }
          } catch (e) { /* ignore */ }
        }
      } else if (msg.reply_to_message) {
        const u = msg.reply_to_message.from;
        targetId = u.id;
        targetName = [u.first_name, u.last_name].filter(Boolean).join(' ');
        targetUsername = u.username || '';
      }

      if (!targetId) {
        await fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ chat_id: chatId, reply_to_message_id: msg.message_id,
            text: 'Kisi message ko reply karke /check likho, ya /check username / numeric ID daalo.' })
        }).catch(() => {});
        return;
      }

      let supporter = null;
      try {
        const raw = await redisCommand(['GET', 'supporter:tg_' + targetId]);
        supporter = raw ? JSON.parse(raw) : null;
      } catch (e) { /* ignore */ }

      const label = targetUsername ? '@' + targetUsername : (targetName || ('ID ' + targetId));
      let text;
      if (!supporter || !supporter.totalDays) {
        text = `❌ ${label} ne abhi tak KABHI support nahi kiya hai.`;
      } else if (isCurrentlyActive(supporter)) {
        text = `✅ ${label} abhi ACTIVE hai (recently supported)!\n📅 Lifetime Total: ${supporter.totalDays} din\n🔥 Streak: ${supporter.streak} din`;
      } else {
        text = `⚠️ ${label} ka support EXPIRE ho chuka hai (${hoursAgo(supporter.lastSupportAt)} ghante pehle) — abhi active nahi hai.\n📅 Lifetime Total: ${supporter.totalDays} din (streak toot chuki hogi agli baar)`;
      }

      await fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: chatId, reply_to_message_id: msg.message_id, text })
      }).catch(() => {});
      return;
    }

    // ---- CASE 2: Message in the COMMUNITY group's MAIN/General topic ----
    // (sub-topics are left alone — only the General topic is gated).
    // Requires the bot to have "Delete messages" admin permission there.
    const communityChatId = process.env.COMMUNITY_CHAT_ID;
    if (communityChatId && String(msg.chat.id) === String(communityChatId) && !msg.is_topic_message) {
      // Anonymous admins (posting as the group itself), channel posts / auto-forwards and
      // bots are never regular members — they must never get the "please support" nudge.
      // (Anonymous admin arrives as from = GroupAnonymousBot + sender_chat = this group.)
      if (!msg.from || msg.sender_chat || msg.from.is_bot ||
          [1087968824, 136817688, 777000].includes(Number(msg.from.id))) return;
      const nudgeCfg = await nudgeSettings();
      if (!nudgeCfg.enabled) return;                                   // reminder switched OFF with /nudge off
      const userId = msg.from.id;
      const tgDeleteMsg = (msgId) => fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/deleteMessage`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: msg.chat.id, message_id: msgId })
      }).catch(() => {});
      const tgSendMsg = (body) => fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: msg.chat.id, ...body })
      }).then(r => r.json()).catch(() => null);

      // Admins/creator are fully exempt from this gate — always free to
      // message, no /pass needed, no restriction at all.
      let isAdmin = false;
      try {
        const r = await fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/getChatMember?chat_id=${encodeURIComponent(communityChatId)}&user_id=${userId}`);
        const d = await r.json();
        if (d.ok) isAdmin = (d.result.status === 'administrator' || d.result.status === 'creator');
      } catch (e) { /* assume not admin on failure */ }
      if (isAdmin) return;
      if (await isGlobalFreePassActive()) return;

      let supporter = null;
      try {
        const raw = await redisCommand(['GET', 'supporter:tg_' + userId]);
        supporter = raw ? JSON.parse(raw) : null;
      } catch (e) { /* fail open-ish: treat as not-supported below */ }

      if (!isCurrentlyActive(supporter)) {
        // One reminder per user per cooldown window (atomic SET NX EX). If Redis is unavailable stay silent rather than spam.
        let canRemind = false;
        try { canRemind = (await redisCommand(['SET', 'nudge_cd:' + userId, '1', 'EX', String(nudgeCfg.cooldownMin * 60), 'NX'])) === 'OK'; } catch (e) { canRemind = false; }
        if (!canRemind) return;
        const joke = NUDGE_JOKES[Math.floor(Math.random() * NUDGE_JOKES.length)];
        const siteUrl = process.env.FRONTEND_URL || process.env.PUBLIC_BASE_URL;
        const tag = msg.from.username ? '@' + msg.from.username : msg.from.first_name;
        try {
          // Just a friendly nudge reply — their own message stays untouched.
          const data = await tgSendMsg({
            reply_to_message_id: msg.message_id,
            text: `${tag} 😄 ${joke}\n\nPehle support karo, phir yahan baat kar sakte ho! 👇`,
            reply_markup: { inline_keyboard: [[{ text: '🚀 Support Now', url: siteUrl }]] }
          });
          // Auto-clean our own nudge reply after 2 minutes so the chat stays tidy.
          if (data && data.ok && data.result) {
            setTimeout(() => tgDeleteMsg(data.result.message_id), 2 * 60 * 1000);
          }
        } catch (e) { console.error('community gate failed:', e.message); }
      }
      return;
    }
  } catch (err) {
    console.error('Webhook handling failed:', err.message);
  }
});

// One-time (or after each redeploy with a new URL) — registers the webhook above with Telegram.
app.get('/api/telegram/setup-webhook', async (req, res) => {
  if (!process.env.TELEGRAM_BOT_TOKEN) return res.status(500).json({ ok: false, error: 'Bot token not configured' });
  try {
    const webhookUrl = `${PUBLIC_BASE_URL}/api/telegram/webhook`;
    const r = await fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/setWebhook?url=${encodeURIComponent(webhookUrl)}`);
    const data = await r.json();
    res.json(data);
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ---------------------------------------------------------------------------
// PUBLIC STATUS-CHECK API — for connecting a SEPARATE bot (e.g. your content
// bot) to this system. Before sending content, that bot calls this endpoint
// with the user's Telegram ID; we tell it whether that person is currently
// an active supporter. Protected by a shared secret key (SUPPORT_API_KEY)
// so random people can't probe it.
// ---------------------------------------------------------------------------
app.get('/api/support/status-check', async (req, res) => {
  if (process.env.SUPPORT_API_KEY && req.query.key !== process.env.SUPPORT_API_KEY) {
    return res.status(401).json({ error: 'Invalid or missing API key' });
  }
  const telegramId = req.query.telegramId;
  if (!telegramId) return res.status(400).json({ error: 'telegramId query param required' });

  let supporter = null;
  try {
    const raw = await redisCommand(['GET', 'supporter:tg_' + telegramId]);
    supporter = raw ? JSON.parse(raw) : null;
  } catch (e) {
    return res.status(500).json({ error: 'storage error' });
  }

  let adminPass = false;
  try {
    adminPass = !!(await redisCommand(['GET', 'admin_pass:tg_' + telegramId]));
  } catch (e) { /* ignore */ }

  const globalFreePass = await isGlobalFreePassActive();

  res.json({
    active: isCurrentlyActive(supporter) || globalFreePass,
    adminPass, // true if this admin currently has an active /pass (from the community chat)
    globalFreePass, // true if the owner has temporarily suspended the support requirement for everyone
    totalDays: supporter ? (supporter.totalDays || 0) : 0,
    streak: supporter ? (supporter.streak || 0) : 0,
    lastSupportAt: supporter ? supporter.lastSupportAt : null
  });
});

// Minimum consecutive-day streak needed to unlock "premium" — today's new
// reward tier. Kept as one constant so the bot message, this endpoint, and
// the dashboard badge can never drift out of sync with each other.
const PREMIUM_STREAK_DAYS = 7;

function isPremiumSupporter(supporter) {
  if (!supporter) return false;
  const streakPremium = (supporter.streak || 0) >= PREMIUM_STREAK_DAYS && isCurrentlyActive(supporter);
  // Set by the Forward Bot — either a weekly-leaderboard reward or a manual
  // /grantaccess — independent of streak, so a granted person shows Premium
  // everywhere (site badge, bot crown, Forward Bot content) even if their
  // daily streak lapses, and it self-expires with no extra cleanup needed.
  const grantedPremium = supporter.premiumGrantUntil && supporter.premiumGrantUntil > Date.now();
  return !!(streakPremium || grantedPremium);
}

// ---------------------------------------------------------------------------
// PREMIUM CHECK — same shape/auth as /api/support/status-check above, but for
// the Forward Bot to ask "has this person earned premium?" (7-day streak,
// still currently active) before handing out premium-only content. A missed
// day breaks the streak via the normal support flow, so premium status here
// always self-corrects — no separate flag to keep in sync.
// ---------------------------------------------------------------------------
app.get('/api/support/premium-check', async (req, res) => {
  if (process.env.SUPPORT_API_KEY && req.query.key !== process.env.SUPPORT_API_KEY) {
    return res.status(401).json({ error: 'Invalid or missing API key' });
  }
  const telegramId = req.query.telegramId;
  if (!telegramId) return res.status(400).json({ error: 'telegramId query param required' });

  let supporter = null;
  try {
    const raw = await redisCommand(['GET', 'supporter:tg_' + telegramId]);
    supporter = raw ? JSON.parse(raw) : null;
  } catch (e) {
    return res.status(500).json({ error: 'storage error' });
  }

  const globalFreePass = await isGlobalFreePassActive();

  res.json({
    premium: isPremiumSupporter(supporter) || globalFreePass,
    globalFreePass,
    streak: supporter ? (supporter.streak || 0) : 0,
    totalDays: supporter ? (supporter.totalDays || 0) : 0,
    daysToGo: supporter ? Math.max(0, PREMIUM_STREAK_DAYS - (supporter.streak || 0)) : PREMIUM_STREAK_DAYS
  });
});

// ---------------------------------------------------------------------------
// WEEKLY WINNER — read-only, same SUPPORT_API_KEY auth as the checks above.
// The Forward Bot polls this once a week (it runs on its own machine, so our
// backend can't "push" to it — this is what it pulls instead) to find out
// who most supported the channel in the week that JUST ended, then grants
// them its own reward locally (e.g. temporary premium access) however it
// likes. We only report the result; the Forward Bot owns what "the prize" is.
// ---------------------------------------------------------------------------
app.get('/api/support/weekly-winner', async (req, res) => {
  if (process.env.SUPPORT_API_KEY && req.query.key !== process.env.SUPPORT_API_KEY) {
    return res.status(401).json({ error: 'Invalid or missing API key' });
  }
  try {
    const week = previousWeekKey();
    const winnerCount = Math.max(1, Math.min(10, parseInt(req.query.count || '1', 10) || 1));

    const all = await fetchAllSupporters();
    const scored = all
      .map(s => ({
        telegramId: (s._key || '').replace('supporter:tg_', ''),
        name: s.name || 'Supporter',
        username: s.username || '',
        score: (s.supportDates || []).filter(ds => weekKeyOf(ds) === week).length
      }))
      .filter(x => x.telegramId && x.score > 0)
      .sort((a, b) => b.score - a.score)
      .slice(0, winnerCount);

    res.json({ week, winners: scored });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---------------------------------------------------------------------------
// GRANT WEEKLY PREMIUM — the write-side companion to weekly-winner above.
// The Forward Bot calls this once per winner right after it grants them
// local access, so the site (dashboard badge, leaderboard crown, admin
// table) shows the same Premium status instead of only the Forward Bot
// knowing about it. Same shared-secret trust as the other SUPPORT_API_KEY
// endpoints — this is bot-to-bot, not owner-to-panel, so it's keyed the
// same way as premium-check/status-check rather than the owner-telegramId
// checks used by the Danger Zone actions.
// ---------------------------------------------------------------------------

// Same admin_audit_log the site's own Admin panel already renders (Settings
// tab actions push here too) — reusing it means grant/expiry events show up
// in the existing "Admin activity log" UI with zero frontend changes.
async function appendAuditLog(action, by) {
  try {
    const raw = await redisCommand(['GET', 'admin_audit_log']);
    const log = Array.isArray(JSON.parse(raw || '[]')) ? JSON.parse(raw || '[]') : [];
    log.unshift({ action, by, at: Date.now() });
    await redisCommand(['SET', 'admin_audit_log', JSON.stringify(log.slice(0, 40))]);
  } catch (e) { /* best-effort — a missed log entry shouldn't break the grant itself */ }
}

// ---------------------------------------------------------------------------
// GRANT PREMIUM — the write-side companion to weekly-winner above. The
// Forward Bot calls this right after ANY premium grant — a weekly-leaderboard
// reward OR a manual /grantaccess — so the site (dashboard badge, leaderboard
// crown, admin table) shows the same Premium status, and the admin panel's
// activity log immediately shows who got it and why. Same shared-secret
// trust as the other SUPPORT_API_KEY endpoints — this is bot-to-bot, not
// owner-to-panel, so it's keyed the same way as premium-check/status-check
// rather than the owner-telegramId checks used by the Danger Zone actions.
// ---------------------------------------------------------------------------
app.post('/api/admin/grant-premium', async (req, res) => {
  const { telegramId, days, key, source, name } = req.body || {};
  if (process.env.SUPPORT_API_KEY && key !== process.env.SUPPORT_API_KEY) {
    return res.status(401).json({ error: 'Invalid or missing API key' });
  }
  const grantDays = Number(days);
  if (!telegramId || !grantDays || grantDays <= 0) {
    return res.status(400).json({ error: 'telegramId and a positive days value are required' });
  }
  try {
    const recKey = 'supporter:tg_' + telegramId;
    let rec;
    const raw = await redisCommand(['GET', recKey]);
    if (raw) {
      rec = JSON.parse(raw);
    } else {
      // Manual /grantaccess can target someone who's never connected on the
      // site yet — make a minimal record so the grant still shows up (name,
      // streak/history fill in normally once they do connect).
      rec = { name: name || 'Supporter', streak: 0, totalDays: 0, supportDates: [], lastSupportAt: null, firstSupportAt: null };
    }
    rec.premiumGrantUntil = Date.now() + grantDays * 86400000;
    await redisCommand(['SET', recKey, JSON.stringify(rec)]);
    invalidateSupportersCache();

    const who = rec.name || name || ('Telegram ID ' + telegramId);
    const via = source === 'weekly' ? 'weekly-reward' : 'Forward Bot /grantaccess';
    await appendAuditLog(`🎁 ${who} got ${grantDays} day(s) of Premium (${via})`, 'Forward Bot');

    res.json({ ok: true, until: rec.premiumGrantUntil });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---------------------------------------------------------------------------
// LOG PREMIUM EXPIRED — the Forward Bot schedules an exact one-off job for
// the moment each grant expires (see weekly_premium_job / grantaccess_command)
// and calls this right then, so the admin activity log shows the expiry as
// close to real-time as Telegram's job scheduler allows. No data mutation
// needed here — the badge already disappears on its own the instant
// premiumGrantUntil is in the past (isPremiumSupporter checks it live) —
// this is purely for the admin-facing notification trail.
// ---------------------------------------------------------------------------
app.post('/api/admin/log-premium-expired', async (req, res) => {
  const { telegramId, name, key } = req.body || {};
  if (process.env.SUPPORT_API_KEY && key !== process.env.SUPPORT_API_KEY) {
    return res.status(401).json({ error: 'Invalid or missing API key' });
  }
  const who = name || ('Telegram ID ' + telegramId);
  await appendAuditLog(`⏳ ${who}'s Premium expired`, 'System');
  res.json({ ok: true });
});

// True only for the one Telegram ID recorded as owner in the 'admins' key.
// Used to gate the two destructive/broad actions below — resetting every
// supporter and force-signing-out every open browser session — so they
// can't be triggered by anyone who merely knows the API shape.
async function isOwnerId(telegramId) {
  if (!telegramId) return false;
  try {
    const raw = await redisCommand(['GET', 'admins']);
    if (!raw) return false;
    const admins = JSON.parse(raw);
    return String(admins.ownerId) === String(telegramId);
  } catch (e) {
    return false;
  }
}

// ---------------------------------------------------------------------------
// RESET ALL SUPPORTERS — for launching a new season/system fairly: zeroes
// every supporter's streak/total-days/support-history in one server-side
// pass (not 200 individual client requests). Identity (name, username,
// referral count) is left untouched — only support progress resets.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// RESET ALL SUPPORTERS — for launching a new season/system fairly.
//
// Two different things happen depending on the key:
//  - supporter:tg_<id>  → a real, Telegram-verified account. RESET (streak/
//    totalDays/history back to zero) but keep the record — name, username,
//    referral count survive, and the person doesn't need to reconnect.
//  - anything else (e.g. supporter:u_xxxxx) → left over from the old
//    "just type your name" system, before Telegram verification existed.
//    These aren't tied to a real re-connectable account (which is also how
//    the same person ended up with several of them — a new one was created
//    every time local storage was cleared or they used a different
//    browser/device). DELETE these outright rather than reset them.
// ---------------------------------------------------------------------------
app.post('/api/admin/reset-all-supporters', async (req, res) => {
  const { telegramId } = req.body || {};
  if (!(await isOwnerId(telegramId))) return res.status(403).json({ error: 'Owner only' });

  try {
    const keys = await redisCommand(['KEYS', 'supporter:*']);
    let reset = 0, purged = 0;
    for (const k of (keys || [])) {
      if (!/^supporter:tg_\d+$/.test(k)) {
        await redisCommand(['DEL', k]);
        purged++;
        continue;
      }
      const raw = await redisCommand(['GET', k]);
      if (!raw) continue;
      const rec = JSON.parse(raw);
      rec.streak = 0;
      rec.totalDays = 0;
      rec.supportDates = [];
      rec.lastSupportAt = null;
      rec.firstSupportAt = null;
      rec.premiumGrantUntil = null;
      await redisCommand(['SET', k, JSON.stringify(rec)]);
      reset++;
    }
    invalidateSupportersCache();
    res.json({ ok: true, reset, purged });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---------------------------------------------------------------------------
// FORCE LOGOUT ALL — bumps a global counter every open tab compares itself
// against on load/poll. A mismatch means "sign out and reconnect" — used
// right after a reset so everyone's dashboard reflects the fresh state
// instead of a stale cached streak from before the reset.
// ---------------------------------------------------------------------------
app.post('/api/admin/force-logout-all', async (req, res) => {
  const { telegramId } = req.body || {};
  if (!(await isOwnerId(telegramId))) return res.status(403).json({ error: 'Owner only' });

  try {
    const next = String(Date.now());
    await redisCommand(['SET', 'auth_epoch', next]);
    res.json({ ok: true, epoch: next });
  } catch (err) {
    res.status(500).json({ error: err.message });
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
// SUPPORT CERTIFICATE — Silver / Gold / Platinum image drawn by certificate.js
// (replaces the old animated GIF/video card system).
// ---------------------------------------------------------------------------
// Where support cards get posted. Priority:
//   1) the topic saved by an admin running /setsupporttopic inside the topic (Redis 'notify_target')
//   2) env: TELEGRAM_NOTIFY_CHAT_ID (or TELEGRAM_CHAT_ID) + optional TELEGRAM_NOTIFY_TOPIC_ID
async function getNotifyTarget() {
  try {
    const raw = await redisCommand(['GET', 'notify_target']);
    if (raw) {
      const t = JSON.parse(raw);
      if (t && t.chatId) return { chatId: t.chatId, threadId: t.threadId || null, source: 'bot' };
    }
  } catch (e) { /* fall back to env below */ }
  const chatId = process.env.TELEGRAM_NOTIFY_CHAT_ID || process.env.TELEGRAM_CHAT_ID || null;
  const threadId = process.env.TELEGRAM_NOTIFY_TOPIC_ID ? Number(process.env.TELEGRAM_NOTIFY_TOPIC_ID) : null;
  return { chatId, threadId: threadId || null, source: 'env' };
}

async function sendCertificatePhoto(chatId, buffer, caption, replyMarkup, threadId) {
  const form = new FormData();
  form.append('chat_id', String(chatId));
  if (threadId) form.append('message_thread_id', String(threadId));
  form.append('caption', caption);
  form.append('parse_mode', 'HTML');
  if (replyMarkup) form.append('reply_markup', JSON.stringify(replyMarkup));
  form.append('photo', buffer, { filename: 'certificate.jpg', contentType: 'image/jpeg' });
  const r = await fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendPhoto`, {
    method: 'POST', body: form, headers: form.getHeaders()
  });
  return await r.json();
}

// GET /api/certificate/<telegramId>.png — always the latest data (website download / share).
const _certCache = new Map(); // cache key -> png buffer
app.get('/api/certificate/:id.png', async (req, res) => {
  try {
    const id = String(req.params.id || '').replace(/[^0-9]/g, '');
    if (!id) return res.status(400).send('bad id');
    const raw = await redisCommand(['GET', 'supporter:tg_' + id]);
    if (!raw) return res.status(404).send('not found');
    const rec = JSON.parse(raw);
    if (!rec.totalDays) return res.status(404).send('no support yet');
    const key = [id, rec.totalDays, rec.streak, rec.name, rec.lastSupportAt].join('|');
    let buf = _certCache.get(key);
    if (!buf) {
      buf = await renderCertificate({
        name: rec.name, totalDays: rec.totalDays, streak: rec.streak,
        issuedAt: rec.lastSupportAt || Date.now(), firstSupportAt: rec.firstSupportAt, format: 'png'
      });
      if (_certCache.size > 100) _certCache.clear();
      _certCache.set(key, buf);
    }
    res.set('Cache-Control', 'public, max-age=60');
    res.type('png').send(buf);
  } catch (e) {
    console.error('[cert] endpoint failed:', e.message);
    res.status(500).send('error');
  }
});

// ---------------------------------------------------------------------------
// 7) GROUP NOTIFICATION — bot posts a message whenever a supporter completes
//    support (only called by the frontend when the owner has this toggled
//    ON in the admin panel). Optionally point this at a different chat
//    (e.g. your discussion group) via TELEGRAM_NOTIFY_CHAT_ID; otherwise it
//    falls back to TELEGRAM_CHAT_ID.
// ---------------------------------------------------------------------------
app.post('/api/notify/support', async (req, res) => {
  const target = await getNotifyTarget();
  const targetChat = target.chatId;
  const targetThread = target.threadId;
  if (!process.env.TELEGRAM_BOT_TOKEN || !targetChat) {
    return res.status(500).json({ sent: false, error: 'Bot token / chat id not configured' });
  }
  const { id, test, name, username, totalDays, streak, xp } = req.body || {};

  // Real numbers come from the saved supporter record, not from whatever the browser claims.
  const devId = (typeof id === 'string' && /^tg_\d+$/.test(id)) ? id : null;
  let rec = null;
  if (devId) {
    try { const raw = await redisCommand(['GET', 'supporter:' + devId]); rec = raw ? JSON.parse(raw) : null; } catch (e) {}
  }
  const certName = (rec && rec.name) || name || 'Supporter';
  const d = (rec && rec.totalDays) || totalDays || 1;
  const s = (rec && rec.streak) || streak || 1;
  const who = esc(username ? '@' + username : (certName || 'Someone'));
  const userXp = xp || (d * 100);

  // Duplicate guard: one post per supporter per total-days value (retried if Telegram failed).
  let lockKey = null;
  if (devId) {
    try {
      if (test) {
        const ok = await redisCommand(['SET', 'cert_test:' + devId, '1', 'NX', 'EX', 15]);
        if (!ok) return res.json({ sent: false, error: 'Thoda ruko — test 15 second me ek hi baar' });
      } else {
        lockKey = `cert_posted:${devId}:${d}`;
        const ok = await redisCommand(['SET', lockKey, '1', 'NX', 'EX', 120]);
        if (!ok) return res.json({ sent: false, error: 'Is support ka certificate pehle hi post ho chuka hai' });
      }
    } catch (e) { lockKey = null; /* Redis hiccup: better to post than to stay silent */ }
  }

  // Caption matches the certificate image (same tier, days and streak) — no festival editions.
  const tierKey = tierForDays(d);
  const tierLabel = tierKey === 'platinum' ? 'Diamond' : tierKey.charAt(0).toUpperCase() + tierKey.slice(1);
  const tierIcon = tierKey === 'platinum' ? '💎' : tierKey === 'gold' ? '🥇' : '🥈';
  const buttonText = '🏅 Claim your Certificate';
  const caption =
    `${tierIcon} <b>CERTIFICATE OF SUPPORT</b> ${tierIcon}\n\n` +
    `⚡ <b>${who}</b> ne aaj support complete kiya!\n\n` +
    `🎖️ <b>Tier:</b> ${tierLabel}\n` +
    `📅 <b>Total Days:</b> ${d}\n` +
    `🔥 <b>Streak:</b> ${s} din\n` +
    `💠 <b>Supporter XP:</b> ${userXp.toLocaleString()}\n\n` +
    `👇 <i>Tum bhi apna Certificate of Support claim karo:</i>`;

  const siteUrl = process.env.FRONTEND_URL || process.env.PUBLIC_BASE_URL;
  const replyMarkup = { inline_keyboard: [[{ text: buttonText, url: siteUrl }]] };

  try {
    let data = null;
    try {
      const img = await renderCertificate({
        name: certName, totalDays: d, streak: s, tier: tierForDays(d),
        issuedAt: (rec && rec.lastSupportAt) || Date.now(), firstSupportAt: rec && rec.firstSupportAt
      });
      data = await sendCertificatePhoto(targetChat, img, caption, replyMarkup, targetThread);
    } catch (e) {
      console.error('[cert] image post failed, falling back to text:', e.message);
    }
    if (!data || !data.ok) {
      // Never stay silent: if the image could not be made/sent, at least post the text card.
      const r = await fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: targetChat, ...(targetThread ? { message_thread_id: targetThread } : {}), text: caption, parse_mode: 'HTML', reply_markup: replyMarkup })
      });
      data = await r.json();
    }
    const okSent = !!(data && data.ok);
    if (lockKey) {
      if (okSent) redisCommand(['SET', lockKey, '1', 'EX', 172800]).catch(() => {});
      else redisCommand(['DEL', lockKey]).catch(() => {});
    }
    res.json({ sent: okSent, error: okSent ? null : (data ? data.description : 'Failed to send') });

    // ---- Also unlock them in the Community's main topic (best-effort) ----
    if (process.env.COMMUNITY_CHAT_ID && !test) {
      const mention = username ? '@' + username : (name || 'Someone');
      fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id: process.env.COMMUNITY_CHAT_ID,
          text: `✅ ${mention}, ab tum message kar sakte ho! Support karne ke liye shukriya 🙌`
        })
      }).then(r => r.json()).then(data => {
        // Auto-delete this unlock announcement after 2 minutes so the chat stays clean.
        if (data && data.ok && data.result && data.result.message_id) {
          setTimeout(() => {
            fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/deleteMessage`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ chat_id: process.env.COMMUNITY_CHAT_ID, message_id: data.result.message_id })
            }).catch(() => {});
          }, 2 * 60 * 1000);
        }
      }).catch(() => {});
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ sent: false, error: 'Server error contacting Telegram' });
  }
});

// ---------------------------------------------------------------------------
// "/" COMMAND MENU (like the Forward Bot): everyone sees the user commands, admins/owners also get /panel.
// Best-effort: an admin who never opened the bot yet simply gets it after their first /start + next restart.
// ---------------------------------------------------------------------------
const BOT_USER_COMMANDS = [
  { command: 'start', description: '🏠 Main menu' },
  { command: 'mystatus', description: '📊 My support stats' },
  { command: 'top10', description: '🏆 Leaderboard' },
  { command: 'check', description: '🔍 Check my support' },
];
async function tgApiPost(method, body) {
  return fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/${method}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
  }).then(r => r.json()).catch(() => null);
}
async function setAdminCommands(userId, isAdmin) {
  if (!process.env.TELEGRAM_BOT_TOKEN || !/^\d+$/.test(String(userId))) return;
  const scope = { type: 'chat', chat_id: Number(userId) };
  if (isAdmin) await tgApiPost('setMyCommands', { commands: [...BOT_USER_COMMANDS, { command: 'panel', description: '🛠 Control panel' }, { command: 'backupcards', description: '💾 Backup cards' }, { command: 'preview', description: '🧪 Test certificate' }, { command: 'nudge', description: '💬 Group reminder on/off' }], scope });
  else await tgApiPost('deleteMyCommands', { scope });
}
async function setupBotCommands() {
  if (!process.env.TELEGRAM_BOT_TOKEN) return;
  await tgApiPost('setMyCommands', { commands: BOT_USER_COMMANDS, scope: { type: 'default' } });
  const ids = new Set(cbOwnerIds());
  try { (await cbGetDynamicAdmins()).forEach(i => ids.add(String(i))); } catch (e) {}
  try {
    const raw = await redisCommand(['GET', 'admins']);
    const a = raw ? JSON.parse(raw) : null;
    if (a) { if (a.ownerId) ids.add(String(a.ownerId)); (a.list || []).forEach(x => ids.add(String(x.id || x))); }
  } catch (e) {}
  for (const id of ids) await setAdminCommands(id, true);
}

app.listen(PORT, () => {
  console.log(`Support backend listening on port ${PORT}`);
  setTimeout(() => setupBotCommands().catch(e => console.warn('[commands] setup skipped:', e.message)), 4000);
  setTimeout(() => runCertScheduler().catch(e => console.warn('[sets] scheduler:', e.message)), 8000);
  setInterval(() => runCertScheduler().catch(e => console.warn('[sets] scheduler:', e.message)), 10 * 60 * 1000).unref();
});


module.exports = Object.assign(module.exports || {}, { runCertScheduler, parseSchedule });
