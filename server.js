require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const fetch = require('node-fetch');
const FormData = require('form-data');

const app = express();
app.use(express.json({ limit: '5mb' })); // 5mb so an uploaded channel-logo (base64) fits

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

  try {
    const cfg = await getShortlinkConfig();
    if (!cfg.apiKey || !cfg.apiUrl) {
      console.error('Shortlink provider not configured (no env vars, no /setshortlink config).');
      return res.status(500).json({ error: 'Shortlink service configured nahi hai. Owner ko /setshortlink use karne bolo.' });
    }
    const apiUrl = `${cfg.apiUrl}?api=${cfg.apiKey}&url=${encodeURIComponent(callbackUrl)}`;
    const r = await fetch(apiUrl);
    const data = await r.json();
    console.log('Shortlink API response:', JSON.stringify(data));

    const finalLink = data && (data.shortenedUrl || data.short_url);
    if (!finalLink) {
      // IMPORTANT: never silently fall back to the raw internal callback
      // URL here — that would let anyone skip the shortlink/ads entirely
      // (zero-second "support complete" for free). Fail loudly instead.
      console.error('Shortlink provider did not return a shortened URL:', JSON.stringify(data));
      return res.status(502).json({ error: 'Shortlink generate nahi ho paya. Provider key/URL check karo (Render logs me detail hai).' });
    }
    res.json({ sessionId, shortlink: finalLink });
  } catch (err) {
    console.error('Shortlink API call failed:', err.message);
    return res.status(502).json({ error: 'Shortlink service se connect nahi ho paya. Thodi der baad try karo.' });
  }
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
  // The session ID + signed token + minimum-dwell-time checks above already
  // defeat generic bypass tools (they'd need to know this exact, one-time
  // URL ahead of time, which they can't). This extra check only screens out
  // scripts/bots by their User-Agent.
  //
  // A previous version also required the Referer header to contain
  // "gplinks", on the theory that a real completion always arrives as a
  // browser redirect from GPLinks' own domain. In practice this blocked
  // most REAL supporters, not bypass tools: Telegram's in-app browser, iOS
  // Safari, and most ad-blockers now strip or omit the Referer header by
  // default as a privacy measure, GPLinks' final "Get Link" step, and any
  // ad-interstitial GPLinks shows along the way can change what Referer (if
  // any) arrives here. So the referer requirement is intentionally NOT
  // enforced — it was the actual cause of "sab support nahi kar pa rahe".
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
    rows.push([{ text: '🛠 Admin Panel', url: siteUrl + '/admin' }]);
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

    text =
      `📊  <b>Your Supporter Card</b>\n` +
      `────────────────────\n` +
      `${statusLine}\n\n` +
      `🔥  Streak       <b>${supporter.streak || 0} din</b>\n` +
      `📅  Lifetime      <b>${supporter.totalDays || 0} din</b>\n` +
      `🏆  Rank          <b>#${rank}</b> of ${total}\n\n` +
      `${premiumLine}`;
  } else {
    showSupportBtn = true;
    text =
      `📊  <b>Your Supporter Card</b>\n` +
      `────────────────────\n` +
      `Tumne abhi tak support nahi kiya hai.\n\n` +
      `Support karke apna naam yahan dekho, streak banao, aur ${PREMIUM_STREAK_DAYS} din lagataar support karke 👑 <b>Premium</b> unlock karo!`;
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

async function checkIsAdmin(userId) {
  const chatId = process.env.COMMUNITY_CHAT_ID || process.env.TELEGRAM_CHAT_ID;
  if (!chatId || !process.env.TELEGRAM_BOT_TOKEN) return false;
  try {
    const r = await fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/getChatMember?chat_id=${encodeURIComponent(chatId)}&user_id=${userId}`);
    const d = await r.json();
    return d.ok && (d.result.status === 'administrator' || d.result.status === 'creator');
  } catch (e) { return false; }
}

// ---------------------------------------------------------------------------
// SHORTLINK PROVIDER — configurable live via bot DM (no redeploy needed).
// Works with any GPLinks-style provider: GET {apiUrl}?api={key}&url={target}
// returning JSON with a "shortenedUrl" or "short_url" field.
// ---------------------------------------------------------------------------
const KNOWN_PROVIDERS = {
  gplinks: 'https://api.gplinks.com/api',
};

async function getShortlinkConfig() {
  try {
    const raw = await redisCommand(['GET', 'shortlink_config']);
    if (raw) return JSON.parse(raw);
  } catch (e) { /* fall through to env-based default below */ }
  return {
    provider: 'gplinks',
    apiKey: process.env.GPLINKS_API_KEY || '',
    apiUrl: process.env.GPLINKS_API_URL || KNOWN_PROVIDERS.gplinks,
  };
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
async function handleOwnerCommand(text, userId) {
  const lower = text.toLowerCase();

  if (lower === '/shortlinkstatus') {
    const cfg = await getShortlinkConfig();
    const maskedKey = cfg.apiKey ? cfg.apiKey.slice(0, 4) + '••••' + cfg.apiKey.slice(-3) : '(not set)';
    await tgSendText(userId, `🔗 Current Shortlink Provider\n\nProvider: ${cfg.provider}\nAPI URL: ${cfg.apiUrl}\nAPI Key: ${maskedKey}`);
    return true;
  }

  if (lower.startsWith('/setshortlink')) {
    // /setshortlink <provider> <apiKey> [apiUrl]
    const parts = text.split(/\s+/).slice(1);
    if (parts.length < 2) {
      await tgSendText(userId, `Usage: /setshortlink <provider> <apiKey> [apiUrl]\n\nExample (GPLinks): /setshortlink gplinks YOUR_API_KEY\nExample (any other provider): /setshortlink vplink YOUR_API_KEY https://api.vplink.in/api`);
      return true;
    }
    const [provider, apiKey, customUrl] = parts;
    const apiUrl = customUrl || KNOWN_PROVIDERS[provider.toLowerCase()];
    if (!apiUrl) {
      await tgSendText(userId, `❌ '${provider}' ka API URL pata nahi hai — poora URL bhi daalo: /setshortlink ${provider} ${apiKey} https://api.example.com/api`);
      return true;
    }
    await setShortlinkConfig({ provider: provider.toLowerCase(), apiKey, apiUrl });
    await tgSendText(userId, `✅ Shortlink provider update ho gaya!\n\nProvider: ${provider}\nAPI URL: ${apiUrl}\n\nAgle support-attempt se yahi use hoga — koi redeploy nahi chahiye.`);
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

  return false;
}

// Cooldown window — must match the frontend's COOLDOWN_MS (12 hours in production).
const SUPPORT_WINDOW_MS = 12 * 60 * 60 * 1000;

function isCurrentlyActive(supporter) {
  return !!(supporter && supporter.lastSupportAt && (Date.now() - supporter.lastSupportAt) < SUPPORT_WINDOW_MS);
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

function tgEdit(chatId, messageId, text, replyMarkup, parseMode) {
  return fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/editMessageText`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ chat_id: chatId, message_id: messageId, text, reply_markup: replyMarkup, parse_mode: parseMode })
  }).catch(() => {});
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
  return (process.env.CONTENT_OWNER_IDS || '').split(',').map(s => s.trim()).filter(Boolean);
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

      // ---- Owner/admin-only bot commands: shortlink provider + free-pass ----
      if (isAdmin && msg.text && await handleOwnerCommand(msg.text.trim(), userId)) return;

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

      const text = await buildWelcomeText(userId);
      await tgSend(userId, text, mainMenuKeyboard(isAdmin));
      return;
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
  // Set by the Forward Bot's weekly-winner reward (POST /api/admin/grant-weekly-premium)
  // — independent of streak, so a winner shows Premium everywhere (site badge,
  // bot crown, Forward Bot content) even if their daily streak lapses.
  const weeklyPremium = supporter.weeklyPremiumUntil && supporter.weeklyPremiumUntil > Date.now();
  return !!(streakPremium || weeklyPremium);
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
app.post('/api/admin/grant-weekly-premium', async (req, res) => {
  const { telegramId, days, key } = req.body || {};
  if (process.env.SUPPORT_API_KEY && key !== process.env.SUPPORT_API_KEY) {
    return res.status(401).json({ error: 'Invalid or missing API key' });
  }
  const grantDays = Number(days);
  if (!telegramId || !grantDays || grantDays <= 0) {
    return res.status(400).json({ error: 'telegramId and a positive days value are required' });
  }
  try {
    const recKey = 'supporter:tg_' + telegramId;
    const raw = await redisCommand(['GET', recKey]);
    if (!raw) return res.status(404).json({ error: 'supporter not found' });
    const rec = JSON.parse(raw);
    rec.weeklyPremiumUntil = Date.now() + grantDays * 86400000;
    await redisCommand(['SET', recKey, JSON.stringify(rec)]);
    invalidateSupportersCache();
    res.json({ ok: true, until: rec.weeklyPremiumUntil });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
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
      rec.weeklyPremiumUntil = null;
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
  const { name, username, totalDays, streak, certImage } = req.body || {};
  const who = username ? '@' + username : (name || 'Someone');
  const caption = `🎉 ${who} ne channel ko support kiya!\n📅 Total support: ${totalDays} din\n🔥 Current streak: ${streak} din\n\n👇 Tum bhi support karo:`;
  const siteUrl = process.env.FRONTEND_URL || process.env.PUBLIC_BASE_URL;
  const replyMarkup = { inline_keyboard: [[{ text: '🚀 Support Now', url: siteUrl }]] };

  try {
    // Prefer the supporter's actual certificate image (sent by the frontend
    // right after they complete support). Fall back to the channel logo,
    // then to a plain text message, if that's ever unavailable.
    let imageBuffer = null;
    if (certImage && certImage.includes(',')) {
      try { imageBuffer = Buffer.from(certImage.split(',')[1], 'base64'); } catch (e) { /* ignore, fall through */ }
    }
    if (!imageBuffer) {
      try {
        const brandingRaw = await redisCommand(['GET', 'branding']);
        if (brandingRaw) {
          const branding = JSON.parse(brandingRaw);
          if (branding.logoData && branding.logoData.includes(',')) {
            imageBuffer = Buffer.from(branding.logoData.split(',')[1], 'base64');
          }
        }
      } catch (e) { /* no logo set yet — fall back to text-only below */ }
    }

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

    // ---- Also unlock them in the Community's main topic (best-effort) ----
    if (process.env.COMMUNITY_CHAT_ID) {
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

app.listen(PORT, () => console.log(`Support backend listening on port ${PORT}`));
