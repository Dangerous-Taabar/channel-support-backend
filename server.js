require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const fetch = require('node-fetch');

const app = express();
app.use(express.json());

const allowedOrigins = (process.env.ALLOWED_ORIGINS || '*').split(',').map(s => s.trim());
app.use(cors({
  origin: allowedOrigins.includes('*') ? true : allowedOrigins
}));

const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev_secret_change_me';
const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL || `http://localhost:${PORT}`;
const MIN_DWELL_SECONDS = parseInt(process.env.MIN_DWELL_SECONDS || '15', 10);

// ---------------------------------------------------------------------------
// In-memory session store.
// NOTE: This resets if the server restarts. For real production use, swap
// this for a small database (SQLite/Postgres/Redis) — the interface below
// (get/set/delete) is the only thing you'd need to change.
// ---------------------------------------------------------------------------
const sessions = new Map(); // sessionId -> { deviceId, createdAt, verified, verifiedAt }

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
  sessions.set(sessionId, { deviceId, createdAt: Date.now(), verified: false, verifiedAt: null });

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
//    user didn't jump straight here).
// ---------------------------------------------------------------------------
app.get('/api/support/callback', (req, res) => {
  const { session, token } = req.query;
  const record = sessions.get(session);

  if (!record || !verifyTokenSignature(session, token)) {
    return res.status(400).send('<h2>Invalid or expired support link.</h2>');
  }

  const elapsedSeconds = (Date.now() - record.createdAt) / 1000;
  if (elapsedSeconds < MIN_DWELL_SECONDS) {
    return res.status(400).send('<h2>Steps completed too quickly — please try again.</h2>');
  }

  record.verified = true;
  record.verifiedAt = Date.now();
  sessions.set(session, record);

  // Redirect back into your frontend. Adjust this URL to your deployed page.
  res.send(`
    <html><body style="background:#08050f;color:#fff;font-family:sans-serif;text-align:center;padding-top:60px;">
      <h2>✅ Support verified!</h2>
      <p>You can close this tab and return to the app.</p>
    </body></html>
  `);
});

// ---------------------------------------------------------------------------
// 3) STATUS — frontend polls this after opening the shortlink to know when
//    the callback above has fired.
// ---------------------------------------------------------------------------
app.get('/api/support/status', (req, res) => {
  const { sessionId } = req.query;
  const record = sessions.get(sessionId);
  if (!record) return res.status(404).json({ verified: false });
  res.json({ verified: !!record.verified });
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

app.listen(PORT, () => console.log(`Support backend listening on port ${PORT}`));
