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

## 6. Bot control panel (Certificates, Festival Sets, Backup)

Open the bot in a private chat and send `/panel` (owners and admins only).

**Certificates** (`/panel` → 🎖️ Certificates) — Silver, Gold and Diamond (the `platinum` slot) cards:
- 📤 *Update Template*: send a blank 16:9 image (best as **File/Document**). Templates and text layouts are stored in **Redis**, not on disk, so they survive Render restarts. `assets/cert/<tier>.png` is only the fallback.
- 📐 *Adjust Text Position*, 🧭 *Layout Guide* (empty template with labelled boxes + a ready ChatGPT prompt), 📋 *Copy ← other card*.
- 📝 *Draft Mode*: uploads wait as a draft until ✅ Publish. 🕘 *History*: last 5 live versions. ↩️ *Undo*.
- 🎆 *Festival Sets*: a named set of the 3 cards + layouts. Activate in one tap, or give it a date range (`01-11-2026 to 10-11-2026`); the bot switches on the start date and back to the ⭐ *Normal* set (or the GitHub default) when it ends, and DMs the owners.
- 📣 *Announce*: posts the live cards in the support topic (set it once with `/setsupporttopic` inside that topic).
- 💾 *Backup / 📥 Restore*: `/backupcards` sends a `.json.gz` with live cards, layouts and all sets. Restore is owner-only and must be under 20 MB (Telegram's bot download limit).

**Commands** — everyone: `/start /mystatus /top10 /check`. Admins also: `/panel /backupcards /preview [silver|gold|diamond] /setsupporttopic /supporttopic /resetsupporttopic`.

**Redis keys used by the cards system** (none are readable through the public storage API):
`certtpl:<tier>`, `certlayout:<tier>`, `certtpl_prev:<tier>`, `certhist*`, `certdraft*`, `certset*`, `notify_target`.

## 7. Shortlink provider (GPLinks or any other)

Switch the provider from the bot, no redeploy: `/setshortlink <provider> <apiKey> [apiUrl]` or Panel → Settings → 🔗 Set Shortlink Provider.

- Presets (name only): `gplinks, vplink, shrinkme, shrinkearn, droplink, arolinks, linkshortify` — e.g. `/setshortlink vplink YOUR_KEY`
- Any other GPLinks-style provider: `/setshortlink myprov YOUR_KEY https://api.myprov.com/api` (the API is called as `GET {apiUrl}?api={key}&url={callback}` and may reply JSON with `shortenedUrl` / `short_url` / `url`, or a plain URL)
- Back to the built-in ad task portal: `/setshortlink custom`
- `/testshortlink` (or Panel → 🧪 Test Shortlink) makes a real short link to prove the key works; `/shortlinkstatus` shows the config with the key masked. The message that contains your key is deleted automatically.
- If the provider fails (wrong key, down, no domain approval) users are NOT blocked: they get the Custom Ad Task and the owners get one DM (max every 30 min).
- Env (optional): `GPLINKS_API_KEY` makes GPLinks the default before anything is saved; `CUSTOM_TASK_URL` changes the ad task portal (default `https://raysfinvidya.pages.dev/?step=1`).
