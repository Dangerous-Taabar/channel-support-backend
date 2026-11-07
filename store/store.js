"use strict";
/**
 * ASTRA STORE - backend router, mounted into the Channel Support backend at /api/store (see server.js).
 *
 *   Mini App (Cloudflare Pages /store) ---> /api/store/...  <--- ASTRA bot      (takes the coins)
 *                                                           <--- Forward Bot    (owns the APK files, sends them)
 *
 * Both bots only call OUT (long polling), so neither needs an open port. This server is the post office:
 *   - Mini App users prove who they are with Telegram's signed initData (checked with the ASTRA bot token).
 *   - The bots prove themselves with the shared secret STORE_SECRET (header X-Bot-Secret).
 *
 * Order life:  pending --(ASTRA takes coins)--> paid --(Forward Bot sends APK)--> delivered
 *                 |                                |-> needs_start (user never started the Forward Bot) -> retry / deep link
 *                 '--> failed (not enough coins / no wallet)         '-> delivery_failed (3 errors) -> retry
 *
 * Upstash command budget: everything hot (catalog, queues, balances, libraries) lives in memory; Redis is only
 * written when something CHANGES and read once at boot. An idle bot poll costs zero Redis commands.
 */
const express = require("express");
const crypto = require("crypto");

module.exports = function createStoreRouter(redis) {
  const router = express.Router();

  const BOT_TOKEN = process.env.STORE_BOT_TOKEN || process.env.LUDO_BOT_TOKEN || ""; // the ASTRA bot token (signs Mini App initData)
  const SECRET = process.env.STORE_SECRET || "";
  const ORDER_TTL = 7 * 86400;
  const LOCK_MS = 60_000;
  const MAX_WAIT = 25;

  // ---------------------------------------------------------------------------------------------
  // State (memory first, Redis behind it)
  // ---------------------------------------------------------------------------------------------
  const apps = new Map(); //      id -> app record
  const downloads = new Map(); // id -> count
  const libs = new Map(); //      uid -> Set(appId)
  const orders = new Map(); //    id -> order
  const balances = new Map(); //  uid -> { coins, wallet, at }
  const balReq = new Map(); //    uid -> { at, sentAt }
  const reqs = new Map(); //      id -> request
  const imgs = new Map(); //      id -> { mime, buf }
  const rate = new Map(); //      key -> [timestamps]
  let meta = { forwardBot: "" };
  let ready = false;

  const now = () => Date.now();
  const rid = (n = 8) => crypto.randomBytes(n).toString("hex");
  const R = async (...cmd) => {
    try { return await redis(cmd); } catch (e) { console.warn("[store] redis:", cmd[0], e.message); return null; }
  };

  async function init() {
    try {
      const ids = (await redis(["SMEMBERS", "store:apps"])) || [];
      if (ids.length) {
        const vals = (await redis(["MGET", ...ids.map((i) => "store:app:" + i)])) || [];
        vals.forEach((v) => { try { const a = JSON.parse(v); if (a && a.id) apps.set(a.id, a); } catch {} });
      }
      const m = await redis(["GET", "store:meta"]);
      if (m) meta = { ...meta, ...JSON.parse(m) };
      const dl = (await redis(["HGETALL", "store:dl"])) || [];
      for (let i = 0; i + 1 < dl.length; i += 2) downloads.set(dl[i], Number(dl[i + 1]) || 0);
      const open = (await redis(["SMEMBERS", "store:orders:open"])) || [];
      if (open.length) {
        const vals = (await redis(["MGET", ...open.map((i) => "store:order:" + i)])) || [];
        vals.forEach((v, i) => {
          if (!v) { R("SREM", "store:orders:open", open[i]); return; }
          try { const o = JSON.parse(v); orders.set(o.id, o); } catch {}
        });
      }
      const rq = (await redis(["SMEMBERS", "store:reqs"])) || [];
      if (rq.length) {
        const vals = (await redis(["MGET", ...rq.map((i) => "store:req:" + i)])) || [];
        vals.forEach((v) => { try { const r = JSON.parse(v); reqs.set(r.id, { ...r, votes: new Set(r.votes || []) }); } catch {} });
      }
      console.log(`[store] loaded ${apps.size} apps, ${orders.size} open orders, ${reqs.size} requests`);
    } catch (e) {
      console.warn("[store] running without saved data:", e.message);
    }
    ready = true;
  }
  const booting = init();

  async function lib(uid) {
    let s = libs.get(uid);
    if (!s) {
      const m = (await R("SMEMBERS", "store:lib:" + uid)) || [];
      s = libs.get(uid) || new Set(m);
      libs.set(uid, s);
    }
    return s;
  }

  const OPEN = new Set(["pending", "paid", "needs_start"]);
  function saveOrder(o) {
    o.updatedAt = now();
    R("SET", "store:order:" + o.id, JSON.stringify(o), "EX", ORDER_TTL);
    R(OPEN.has(o.status) ? "SADD" : "SREM", "store:orders:open", o.id);
  }
  function saveApp(a) { R("SET", "store:app:" + a.id, JSON.stringify(a)); R("SADD", "store:apps", a.id); }
  function saveReq(r) { R("SET", "store:req:" + r.id, JSON.stringify({ ...r, votes: [...r.votes] })); R("SADD", "store:reqs", r.id); }

  // an order nobody (ASTRA) ever picked up within 3 minutes is cancelled - nothing was charged for it
  setInterval(() => {
    for (const o of orders.values()) {
      if (o.status === "pending" && !o.lockUntil && now() - o.createdAt > 180_000) { o.status = "failed"; o.reason = "timeout"; saveOrder(o); }
    }
  }, 30_000).unref();

  // old finished orders leave memory after an hour
  setInterval(() => {
    const cut = now() - 3600_000;
    for (const [id, o] of orders) if (!OPEN.has(o.status) && o.updatedAt < cut) orders.delete(id);
    for (const [k, a] of rate) { const f = a.filter((t) => t > now() - 3600_000); f.length ? rate.set(k, f) : rate.delete(k); }
  }, 10 * 60_000).unref();

  // ---------------------------------------------------------------------------------------------
  // Auth
  // ---------------------------------------------------------------------------------------------
  function verifyInitData(raw, maxAgeSec = 2 * 86400) {
    if (!raw || !BOT_TOKEN) return null;
    const params = new URLSearchParams(raw);
    const hash = params.get("hash");
    if (!hash) return null;
    params.delete("hash");
    const dcs = [...params.entries()].map(([k, v]) => `${k}=${v}`).sort().join("\n");
    const secret = crypto.createHmac("sha256", "WebAppData").update(BOT_TOKEN).digest();
    const calc = crypto.createHmac("sha256", secret).update(dcs).digest("hex");
    const a = Buffer.from(calc), b = Buffer.from(hash);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    const age = Date.now() / 1000 - Number(params.get("auth_date") || 0);
    if (!(age >= -60 && age <= maxAgeSec)) return null;
    try {
      const u = JSON.parse(params.get("user") || "null");
      if (!u || typeof u.id !== "number") return null;
      return { id: u.id, name: [u.first_name, u.last_name].filter(Boolean).join(" ") || u.username || String(u.id), username: u.username || null };
    } catch { return null; }
  }
  const sameSecret = (a, b) => {
    const x = crypto.createHash("sha256").update(String(a)).digest();
    const y = crypto.createHash("sha256").update(String(b)).digest();
    return crypto.timingSafeEqual(x, y);
  };
  function botAuth(req, res, next) {
    if (!SECRET) return res.status(503).json({ error: "STORE_SECRET is not set on the server" });
    if (!sameSecret(req.get("x-bot-secret") || "", SECRET)) return res.status(401).json({ error: "bad secret" });
    next();
  }
  async function userAuth(req, res, next) {
    const u = verifyInitData(req.get("x-init-data") || "");
    if (!u) return res.status(401).json({ error: "Open the store from the Telegram bot" });
    await booting;
    req.user = u;
    next();
  }
  function limit(req, res, key, max, perMs) {
    const k = key + ":" + req.user.id;
    const arr = (rate.get(k) || []).filter((t) => t > now() - perMs);
    if (arr.length >= max) { res.status(429).json({ error: "Too fast - thoda ruko." }); return false; }
    arr.push(now()); rate.set(k, arr);
    return true;
  }
  const wrap = (fn) => (req, res) => Promise.resolve(fn(req, res)).catch((e) => { console.error("[store]", e); res.status(e.status || 500).json({ error: e.status ? e.message : "Server error" }); });
  const bad = (status, message) => Object.assign(new Error(message), { status });

  // ---------------------------------------------------------------------------------------------
  // Long-poll plumbing
  // ---------------------------------------------------------------------------------------------
  const waiters = { bot: [], fwd: [] };
  const wake = (k) => waiters[k].splice(0).forEach((f) => f());
  async function longPoll(req, res, kind, take) {
    let out = take();
    const waitSec = Math.min(MAX_WAIT, Math.max(0, Number(req.query.wait) || 0));
    if (!out && waitSec) {
      await new Promise((resolve) => {
        const t = setTimeout(done, waitSec * 1000);
        function done() { clearTimeout(t); const i = waiters[kind].indexOf(done); if (i >= 0) waiters[kind].splice(i, 1); resolve(); }
        waiters[kind].push(done);
        res.on("close", done); // (res, not req: on modern Node req "close" fires as soon as the request body is read)
      });
      out = take();
    }
    if (res.writableEnded || res.destroyed) return;
    res.json(out || { empty: true });
  }

  // ---------------------------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------------------------
  const pub = (a) => ({ id: a.id, name: a.name, category: a.category, version: a.version || "", desc: a.desc || "", price: a.price, added: a.added || "", dl: downloads.get(a.id) || 0, img: a.imgv ? a.imgv : 0 });
  const pubOrder = (o) => ({ id: o.id, status: o.status, reason: o.reason || null, appId: o.appId, appName: o.appName, price: o.price, kind: o.kind, forwardBot: meta.forwardBot || "" });
  const cleanDesc = (s, max) => String(s ?? "").replace(/[\u0000-\u0009\u000b-\u001f\u007f<>]/g, " ").replace(/[ \t]+/g, " ").replace(/\n\s*\n+/g, "\n").trim().slice(0, max);
  const cleanText = (s, max) => String(s ?? "").replace(/[\u0000-\u001f\u007f<>]/g, " ").replace(/\s+/g, " ").trim().slice(0, max);

  function onPaid(o) {
    o.paidAt = now(); o.lockUntil = 0; // the pending-phase lock must not delay delivery
    if (o.kind !== "redownload") {
      downloads.set(o.appId, (downloads.get(o.appId) || 0) + 1);
      R("HINCRBY", "store:dl", o.appId, 1);
      lib(o.uid).then((s) => { s.add(o.appId); R("SADD", "store:lib:" + o.uid, o.appId); });
    }
    wake("fwd");
  }

  // ---------------------------------------------------------------------------------------------
  // Mini App endpoints
  // ---------------------------------------------------------------------------------------------
  router.get("/health", (req, res) => res.json({ ok: true, ready, apps: apps.size, openOrders: [...orders.values()].filter((o) => OPEN.has(o.status)).length, configured: !!(BOT_TOKEN && SECRET) }));

  router.get("/bootstrap", userAuth, wrap(async (req, res) => {
    const u = req.user;
    const owned = [...(await lib(u.id))];
    res.json({
      user: { id: u.id, name: u.name },
      apps: [...apps.values()].filter((a) => !a.hidden).map(pub),
      owned,
      balance: balances.get(u.id) || null,
      forwardBot: meta.forwardBot || "",
      now: now(),
    });
  }));

  router.get("/me", userAuth, wrap(async (req, res) => {
    res.json({ owned: [...(await lib(req.user.id))], balance: balances.get(req.user.id) || null, now: now() });
  }));

  // posters (no auth: an <img> tag cannot send headers; the id is not a secret)
  router.get("/img/:id", wrap(async (req, res) => {
    const id = String(req.params.id);
    if (!/^[PF]\d{1,9}$/.test(id)) return res.status(404).end();
    let im = imgs.get(id);
    if (!im) {
      const raw = await R("GET", "store:img:" + id);
      if (!raw) return res.status(404).end();
      const i = raw.indexOf(",");
      im = { mime: raw.slice(0, i) || "image/jpeg", buf: Buffer.from(raw.slice(i + 1), "base64") };
      imgs.set(id, im);
    }
    res.set({ "Content-Type": im.mime, "Cache-Control": "public, max-age=604800, immutable", "Access-Control-Allow-Origin": "*", "Cross-Origin-Resource-Policy": "cross-origin" });
    res.send(im.buf);
  }));

  router.post("/balance/refresh", userAuth, wrap(async (req, res) => {
    const uid = req.user.id;
    if (limit(req, res, "bal", 6, 60_000)) {
      const cur = balReq.get(uid);
      if (!cur || now() - cur.at > 3000) balReq.set(uid, { at: now(), sentAt: 0 });
      wake("bot");
      res.json({ balance: balances.get(uid) || null, asked: now() });
    }
  }));

  router.post("/order", userAuth, wrap(async (req, res) => {
    const u = req.user;
    const app = apps.get(String(req.body?.appId || ""));
    if (!app || app.hidden) throw bad(404, "This app is not in the store any more.");
    // the same person tapping twice gets the same order back
    for (const o of orders.values()) if (o.uid === u.id && o.appId === app.id && (OPEN.has(o.status))) return res.json(pubOrder(o));
    if (!limit(req, res, "order", 15, 3600_000)) return;
    const owned = (await lib(u.id)).has(app.id);
    const free = app.price === 0;
    const o = {
      id: rid(8), uid: u.id, name: u.name, username: u.username, appId: app.id, appName: app.name,
      price: owned || free ? 0 : app.price, kind: owned ? "redownload" : free ? "free" : "buy",
      status: owned || free ? "paid" : "pending", attempts: 0, createdAt: now(), updatedAt: now(), lockUntil: 0,
    };
    orders.set(o.id, o);
    if (o.status === "paid") onPaid(o); else wake("bot");
    saveOrder(o);
    res.json(pubOrder(o));
  }));

  router.get("/order/:id", userAuth, wrap(async (req, res) => {
    let o = orders.get(String(req.params.id));
    if (!o) {
      const raw = await R("GET", "store:order:" + String(req.params.id).replace(/[^\w]/g, ""));
      if (raw) { try { o = JSON.parse(raw); } catch {} }
    }
    if (!o || o.uid !== req.user.id) throw bad(404, "Order not found");
    res.json(pubOrder(o));
  }));

  router.post("/order/:id/retry", userAuth, wrap(async (req, res) => {
    const o = orders.get(String(req.params.id));
    if (!o || o.uid !== req.user.id) throw bad(404, "Order not found");
    if (o.status === "needs_start" || o.status === "delivery_failed") {
      o.status = "paid"; o.attempts = 0; o.lockUntil = 0; saveOrder(o); wake("fwd");
    }
    res.json(pubOrder(o));
  }));

  // ---- requests
  const pubReq = (r, uid) => ({ id: r.id, name: r.name, note: r.note, votes: r.votes.size, voted: r.votes.has(uid), mine: r.uid === uid, createdAt: r.createdAt });
  router.get("/requests", userAuth, wrap(async (req, res) => {
    const list = [...reqs.values()].filter((r) => r.status === "open").sort((a, b) => b.votes.size - a.votes.size || b.createdAt - a.createdAt).slice(0, 60);
    res.json({ requests: list.map((r) => pubReq(r, req.user.id)) });
  }));
  router.post("/request", userAuth, wrap(async (req, res) => {
    const u = req.user;
    const name = cleanText(req.body?.name, 60), note = cleanText(req.body?.note, 200);
    if (name.length < 2) throw bad(400, "App ka naam likho.");
    const lower = name.toLowerCase();
    const same = [...reqs.values()].find((r) => r.status === "open" && r.name.toLowerCase() === lower);
    if (same) { same.votes.add(u.id); saveReq(same); return res.json({ merged: true, request: pubReq(same, u.id) }); }
    const day = new Date().toISOString().slice(0, 10);
    const mine = [...reqs.values()].filter((r) => r.uid === u.id && new Date(r.createdAt).toISOString().slice(0, 10) === day).length;
    if (mine >= 3) throw bad(429, "Aaj ki 3 requests ho chuki hain. Kal phir try karo.");
    const r = { id: rid(5), uid: u.id, uname: u.name, name, note, votes: new Set([u.id]), status: "open", createdAt: now() };
    reqs.set(r.id, r); saveReq(r);
    res.json({ merged: false, request: pubReq(r, u.id) });
  }));
  router.post("/request/:id/vote", userAuth, wrap(async (req, res) => {
    const r = reqs.get(String(req.params.id));
    if (!r || r.status !== "open") throw bad(404, "Request not found");
    if (!limit(req, res, "vote", 30, 60_000)) return;
    if (r.votes.has(req.user.id)) { if (r.uid !== req.user.id) r.votes.delete(req.user.id); } else r.votes.add(req.user.id);
    saveReq(r);
    res.json({ request: pubReq(r, req.user.id) });
  }));

  // ---------------------------------------------------------------------------------------------
  // Forward Bot: catalog sync
  // ---------------------------------------------------------------------------------------------
  const CATS = new Set(["phone", "tv", "live_tv"]);
  router.post("/bot/apps/sync", botAuth, wrap(async (req, res) => {
    await booting;
    const b = req.body || {};
    if (b.meta && typeof b.meta.forwardBot === "string") {
      const fb = b.meta.forwardBot.replace(/^@/, "").slice(0, 64);
      if (fb && fb !== meta.forwardBot) { meta = { ...meta, forwardBot: fb }; R("SET", "store:meta", JSON.stringify(meta)); }
    }
    let n = 0;
    for (const x of Array.isArray(b.apps) ? b.apps : []) {
      if (!/^[PF]\d{1,9}$/.test(String(x.id))) continue;
      const old = apps.get(x.id) || {};
      const a = {
        ...old, id: x.id,
        name: cleanText(x.name, 80) || x.id,
        category: CATS.has(x.category) ? x.category : "phone",
        version: cleanText(x.version, 20),
        desc: cleanDesc(x.desc, 600),
        price: Math.min(100000, Math.max(0, Math.floor(Number(x.price) || 0))),
        added: cleanText(x.added, 30),
        hidden: false,
      };
      apps.set(a.id, a); saveApp(a); n++;
    }
    if (Array.isArray(b.allIds)) {
      const keep = new Set(b.allIds.map(String));
      for (const a of apps.values()) {
        const shouldHide = !keep.has(a.id);
        if (a.hidden !== shouldHide) { a.hidden = shouldHide; saveApp(a); }
      }
    }
    res.json({ ok: true, upserted: n, total: apps.size });
  }));

  router.post("/bot/apps/:id/img", botAuth, wrap(async (req, res) => {
    await booting;
    const id = String(req.params.id);
    const a = apps.get(id);
    if (!a) throw bad(404, "Unknown app - sync the app first");
    const b64 = String(req.body?.b64 || "");
    const mime = /^image\/(jpeg|png|webp)$/.test(req.body?.mime) ? req.body.mime : "image/jpeg";
    const buf = Buffer.from(b64, "base64");
    if (!buf.length || buf.length > 900_000) throw bad(413, "Poster must be under 900 KB");
    imgs.set(id, { mime, buf });
    await R("SET", "store:img:" + id, mime + "," + b64);
    a.imgv = now(); saveApp(a);
    res.json({ ok: true, bytes: buf.length });
  }));

  // ---------------------------------------------------------------------------------------------
  // ASTRA bot: takes coins
  // ---------------------------------------------------------------------------------------------
  router.get("/bot/poll", botAuth, wrap(async (req, res) => {
    await booting;
    await longPoll(req, res, "bot", () => {
      const t = now();
      const todo = [...orders.values()].filter((o) => o.status === "pending" && (o.lockUntil || 0) < t);
      todo.forEach((o) => { o.lockUntil = t + LOCK_MS; });
      const bal = [];
      for (const [uid, r] of balReq) if (!r.sentAt || t - r.sentAt > 15_000) { r.sentAt = t; bal.push(uid); }
      if (!todo.length && !bal.length) return null;
      return { orders: todo.map((o) => ({ id: o.id, uid: o.uid, name: o.name, username: o.username, appId: o.appId, appName: o.appName, price: o.price })), balance: bal };
    });
  }));

  router.post("/bot/report", botAuth, wrap(async (req, res) => {
    await booting;
    for (const r of Array.isArray(req.body?.results) ? req.body.results : []) {
      const o = orders.get(String(r.id));
      if (!o || o.status !== "pending") continue;
      if (r.ok) { o.status = "paid"; o.price = Math.max(0, Math.floor(Number(r.charged) || 0)); onPaid(o); }
      else { o.status = "failed"; o.reason = r.reason === "funds" || r.reason === "nowallet" ? r.reason : "error"; }
      saveOrder(o);
    }
    const bs = req.body?.balances && typeof req.body.balances === "object" ? req.body.balances : {};
    for (const [uid, v] of Object.entries(bs)) {
      balances.set(Number(uid), { coins: Math.max(0, Math.floor(Number(v.coins) || 0)), wallet: v.wallet !== false, at: now() });
      balReq.delete(Number(uid));
    }
    res.json({ ok: true });
  }));

  // ---------------------------------------------------------------------------------------------
  // Forward Bot: sends the APK
  // ---------------------------------------------------------------------------------------------
  router.get("/bot/deliveries", botAuth, wrap(async (req, res) => {
    await booting;
    await longPoll(req, res, "fwd", () => {
      const t = now();
      const todo = [...orders.values()].filter((o) => o.status === "paid" && (o.lockUntil || 0) < t);
      if (!todo.length) return null;
      todo.forEach((o) => { o.lockUntil = t + LOCK_MS; });
      return { orders: todo.map((o) => ({ id: o.id, uid: o.uid, appId: o.appId, appName: o.appName })) };
    });
  }));

  router.post("/bot/delivery-result", botAuth, wrap(async (req, res) => {
    await booting;
    const o = orders.get(String(req.body?.id));
    if (!o) return res.json({ ok: true, ignored: true });
    const st = req.body?.status;
    if (st === "delivered") { o.status = "delivered"; o.deliveredAt = now(); }
    else if (st === "needs_start") { o.status = "needs_start"; }
    else { o.attempts = (o.attempts || 0) + 1; if (o.attempts >= 3) o.status = "delivery_failed"; else { o.status = "paid"; o.lockUntil = now() + 5000; setTimeout(() => wake("fwd"), 5200).unref(); } }
    saveOrder(o);
    res.json({ ok: true });
  }));

  // deep link  t.me/<forwardBot>?start=get_<orderId>  - the Forward Bot asks "is this person allowed this app?"
  router.get("/bot/order/:id", botAuth, wrap(async (req, res) => {
    await booting;
    const o = orders.get(String(req.params.id));
    const uid = Number(req.query.uid);
    if (!o || o.uid !== uid || !["paid", "needs_start", "delivered"].includes(o.status)) return res.status(404).json({ error: "not found" });
    res.json({ id: o.id, uid: o.uid, appId: o.appId, appName: o.appName, status: o.status });
  }));

  // ---- requests, owner side (Forward Bot /storerequests, /storedone)
  router.get("/bot/requests", botAuth, wrap(async (req, res) => {
    await booting;
    const list = [...reqs.values()].filter((r) => r.status === "open").sort((a, b) => b.votes.size - a.votes.size || b.createdAt - a.createdAt).slice(0, 40);
    res.json({ requests: list.map((r) => ({ id: r.id, name: r.name, note: r.note, votes: r.votes.size, by: r.uname })) });
  }));
  router.post("/bot/requests/:id/done", botAuth, wrap(async (req, res) => {
    await booting;
    const r = reqs.get(String(req.params.id));
    if (!r) throw bad(404, "Request not found");
    r.status = "done"; r.doneAt = now(); saveReq(r);
    res.json({ ok: true, name: r.name, voters: [...r.votes] });
  }));

  return router;
};
