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
const ADMIN_JOKES = [
  "Arre boss, khud hi rules banate ho aur khud hi todte ho? 😄 Pehle support karo!",
  "Admin ho toh support nahi karoge kya? Power ke sath thoda support bhi chalta hai boss 😎",
  "Crown pehna hai toh zimmedari bhi nibhao — 3 minute nikaalo bhai 👑",
  "Sabko bolte ho support karo, khud bhool gaye? 😂 Chalo, misaal banao!",
  "Admin panel se toh dikha diya, ab yahan bhi dikha do — support kar do 💪",
];

function mainMenuKeyboard(isAdmin) {
  const siteUrl = process.env.FRONTEND_URL || process.env.PUBLIC_BASE_URL;
  const rows = [
    [{ text: '📊 My Stats', callback_data: 'my_stats' }, { text: '🏆 Leaderboard', callback_data: 'leaderboard' }],
    [{ text: '👥 Community Stats', callback_data: 'community_stats' }],
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

async function fetchAllSupporters() {
  const keys = await redisCommand(['KEYS', 'supporter:tg_*']);
  let all = [];
  for (const k of (keys || [])) {
    const raw = await redisCommand(['GET', k]);
    if (raw) all.push(JSON.parse(raw));
  }
  return all;
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

  if (!isCurrentlyActive(supporter)) {
    const joke = NUDGE_JOKES[Math.floor(Math.random() * NUDGE_JOKES.length)];
    const staleNote = (supporter && supporter.totalDays)
      ? `\n\n(Pichla support ${hoursAgo(supporter.lastSupportAt)} ghante pehle tha — ab dobara karna hoga)`
      : '';
    return `👋 Abhi support active nahi hai!${staleNote}\n\n${joke}\n\nBas 3 minute ki baat hai — neeche se dekho 👇`;
  }
  return `✅ Tumhara support abhi active hai!\n🔥 Streak: ${supporter.streak} din\n📅 Total: ${supporter.totalDays} din\n\nThanks for the support! 🙌`;
}

function tgSend(chatId, text, replyMarkup) {
  return fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ chat_id: chatId, text, reply_markup: replyMarkup })
  }).catch(() => {});
}

function tgEdit(chatId, messageId, text, replyMarkup) {
  return fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/editMessageText`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ chat_id: chatId, message_id: messageId, text, reply_markup: replyMarkup })
  }).catch(() => {});
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
        let supporter = null;
        try { const raw = await redisCommand(['GET', 'supporter:tg_' + userId]); supporter = raw ? JSON.parse(raw) : null; } catch (e) {}
        let text;
        if (supporter && supporter.totalDays) {
          let rank = '-', total = 0;
          try {
            const all = await fetchAllSupporters();
            all.sort((a, b) => (b.totalDays || 0) - (a.totalDays || 0));
            total = all.length;
            const idx = all.findIndex(s => s.name === supporter.name && s.totalDays === supporter.totalDays && s.streak === supporter.streak);
            rank = idx >= 0 ? idx + 1 : '-';
          } catch (e) {}
          const statusLine = isCurrentlyActive(supporter)
            ? '✅ Status: Active abhi'
            : `⚠️ Status: Expired (${hoursAgo(supporter.lastSupportAt)} ghante pehle support kiya tha) — dobara karo!`;
          text = `📊 Tumhare Stats\n\n${statusLine}\n🔥 Streak: ${supporter.streak} din\n📅 Lifetime Total: ${supporter.totalDays} din\n🏆 Rank: #${rank} of ${total}`;
        } else {
          text = `📊 Tumne abhi tak support nahi kiya hai!\n\nSupport karke apna naam yahan dekho 👇`;
        }
        await tgEdit(chatId, messageId, text, backKeyboard());
      } else if (cb.data === 'leaderboard') {
        let text = '🏆 Top 10 Supporters\n\n';
        try {
          const all = await fetchAllSupporters();
          all.sort((a, b) => (b.totalDays || 0) - (a.totalDays || 0));
          if (!all.length) text += 'Abhi koi supporter nahi hai.';
          else all.slice(0, 10).forEach((s, i) => { text += `${i + 1}. ${s.name} — ${s.totalDays || 0}d 🔥${s.streak || 0}\n`; });
        } catch (e) { text += 'Data load nahi ho paya, dobara try karo.'; }
        await tgEdit(chatId, messageId, text, backKeyboard());
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
      }
      return;
    }

    const msg = req.body && req.body.message;
    if (!msg || !process.env.TELEGRAM_BOT_TOKEN) return;

    // ---- CASE 1: Private DM to the bot (e.g. /start) ----
    if (msg.chat.type === 'private') {
      const userId = msg.from.id;
      const isAdmin = await checkIsAdmin(userId);
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

      // Is this sender an admin/creator of the community?
      let isAdmin = false;
      try {
        const r = await fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/getChatMember?chat_id=${encodeURIComponent(communityChatId)}&user_id=${userId}`);
        const d = await r.json();
        if (d.ok) isAdmin = (d.result.status === 'administrator' || d.result.status === 'creator');
      } catch (e) { /* assume not admin on failure */ }

      // ---- /pass — admin-only 12-hour bypass of this gate (no streak credit) ----
      if (isAdmin && (msg.text || '').trim().toLowerCase() === '/pass') {
        await tgDeleteMsg(msg.message_id); // remove the command itself immediately
        try {
          await redisCommand(['SET', 'admin_pass:tg_' + userId, '1', 'EX', String(12 * 60 * 60)]);
        } catch (e) { console.error('admin_pass set failed:', e.message); }

        const data = await tgSendMsg({ text: `🫡 Jo hukum, mere aaka! Agle 12 ghante ke liye tumhe support maangunga nahi — bina rok-tok baat karo.` });
        if (data && data.ok && data.result) {
          setTimeout(() => tgDeleteMsg(data.result.message_id), 60 * 1000); // self-cleans after 1 min
        }
        return;
      }

      // ---- /end — admin-only, manually ends YOUR OWN active /pass early ----
      if (isAdmin && (msg.text || '').trim().toLowerCase() === '/end') {
        await tgDeleteMsg(msg.message_id); // remove the command itself immediately
        let hadPass = false;
        try {
          hadPass = !!(await redisCommand(['GET', 'admin_pass:tg_' + userId]));
          await redisCommand(['DEL', 'admin_pass:tg_' + userId]);
        } catch (e) { console.error('admin_pass end failed:', e.message); }

        const replyText = hadPass
          ? `🫡 Jo hukum! Ab aap bhi bina support kiye message nahi kar sakte.`
          : `ℹ️ Koi active pass tha hi nahi.`;
        const data = await tgSendMsg({ text: replyText });
        if (data && data.ok && data.result) {
          setTimeout(() => tgDeleteMsg(data.result.message_id), 60 * 1000); // self-cleans after 1 min
        }
        return;
      }

      // ---- Active /pass exemption? Let them chat freely, no streak needed ----
      let hasPass = false;
      try {
        hasPass = !!(await redisCommand(['GET', 'admin_pass:tg_' + userId]));
      } catch (e) { /* ignore */ }
      if (hasPass) return;

      let supporter = null;
      try {
        const raw = await redisCommand(['GET', 'supporter:tg_' + userId]);
        supporter = raw ? JSON.parse(raw) : null;
      } catch (e) { /* fail open-ish: treat as not-supported below */ }

      if (!isCurrentlyActive(supporter)) {
        const jokePool = isAdmin ? ADMIN_JOKES : NUDGE_JOKES;
        const joke = jokePool[Math.floor(Math.random() * jokePool.length)];
        const siteUrl = process.env.FRONTEND_URL || process.env.PUBLIC_BASE_URL;
        const tag = msg.from.username ? '@' + msg.from.username : msg.from.first_name;
        const extra = isAdmin ? `\n\n(Ya /pass likho agar abhi zaroori kaam hai — 12 ghante ki chhoot mil jayegi 🫡)` : '';
        try {
          // Reply first (so the joke references their message)...
          await tgSendMsg({
            reply_to_message_id: msg.message_id,
            text: `${tag} 😄 ${joke}\n\nPehle support karo, phir yahan baat kar sakte ho! 👇${extra}`,
            reply_markup: { inline_keyboard: [[{ text: '🚀 Support Now', url: siteUrl }]] }
          });
          // ...then delete their message, so they can't keep chatting unsupported.
          await tgDeleteMsg(msg.message_id);
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

  res.json({
    active: isCurrentlyActive(supporter),
    totalDays: supporter ? (supporter.totalDays || 0) : 0,
    streak: supporter ? (supporter.streak || 0) : 0,
    lastSupportAt: supporter ? supporter.lastSupportAt : null
  });
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
