# Channel Support — Backend

Small Express API that does the two things a static frontend can't do safely:

1. **Shortlink verification** — creates a signed, single-use session per user, wraps it through your shortlink provider (GPLinks by default), and only marks support "verified" when that exact callback is hit *and* a minimum time has passed. This stops generic shortlink-bypass tools, which only know how to skip to a fixed final URL — here the final URL is unique per attempt and doesn't exist until the session is created.
2. **Real Telegram admin check** — calls Telegram's Bot API (`getChatMember`) so only actual admins/owner of your channel can get into the admin panel. This requires a bot token, which must never be exposed in frontend code — that's why it lives here.

## 1. Local setup

```bash
cd support-backend
npm install
cp .env.example .env
# edit .env with your real values (see below)
npm start
```

Server runs on `http://localhost:3000` by default.

## 2. Environment variables (`.env`)

| Variable | What it is |
|---|---|
| `PORT` | Port to run on (Render/Railway set this automatically — leave default) |
| `ALLOWED_ORIGINS` | Your frontend's origin, e.g. `https://your-site.pages.dev`. Use `*` while testing. |
| `SESSION_SECRET` | Any long random string — used to sign session tokens |
| `PUBLIC_BASE_URL` | The public URL this backend will be deployed at (Render gives you this) |
| `GPLINKS_API_KEY` | From your GPLinks dashboard |
| `GPLINKS_API_URL` | Usually `https://gplinks.in/api` — check GPLinks docs for the current endpoint |
| `TELEGRAM_BOT_TOKEN` | From [@BotFather](https://t.me/BotFather) |
| `TELEGRAM_CHAT_ID` | Your channel/group's `@username` or numeric `-100...` id |
| `MIN_DWELL_SECONDS` | Minimum seconds between opening the link and completing it |

**Important:** add your bot as an **admin** of the channel/group, otherwise `getChatMember` won't return reliable data for other members.

## 3. Deploy for free (Render example)

1. Push this `support-backend` folder to a GitHub repo.
2. Go to [render.com](https://render.com) → New → Web Service → connect the repo.
3. Build command: `npm install` — Start command: `npm start`.
4. Add all the variables from `.env` in Render's Environment tab.
5. Once deployed, copy the live URL (e.g. `https://your-app.onrender.com`) and set it as `PUBLIC_BASE_URL` in the same env settings, then redeploy.

Railway, Fly.io, or Cyclic work the same way.

## 4. API reference

### `POST /api/support/start`
Body: `{ "deviceId": "u_abc123" }`
Returns: `{ "sessionId": "...", "shortlink": "https://gplinks.in/xxxx" }`
Frontend opens `shortlink` in a new tab.

### `GET /api/support/status?sessionId=...`
Returns: `{ "verified": true|false }`
Frontend polls this every few seconds after opening the shortlink.

### `POST /api/admin/verify`
Body: `{ "telegramId": "123456789" }`
Returns: `{ "isAdmin": true|false, "status": "administrator", "isOwner": false }`

## 5. Connecting the frontend

In `support-page.html`, set:

```js
const API_BASE_URL = "https://your-app.onrender.com";
```

at the top of the `<script>` block. When this is set, the page calls the real backend instead of the built-in simulated timer/whitelist.
