"use strict";
/**
 * ASTRA Ludo — game router, mounted into the Channel Support backend at /api/ludo (see server.js).
 *
 *   Mini App (Cloudflare Pages /ludo)  ──►  /api/ludo/...  ◄──  ASTRA bot (creates rooms, seats players, pays coins)
 *
 * The server is the referee: it rolls the dice, checks every move, runs the turn timers and decides the winner.
 * Players prove who they are with Telegram's signed `initData` (checked with the bot token); the bot proves itself
 * with a shared secret. Rooms live in memory (a restart ends running games — the bot notices and refunds the coins).
 */
const crypto = require("crypto");
const express = require("express");
const E = require("./engine");

const BOT_TOKEN = process.env.LUDO_BOT_TOKEN || ""; // the ASTRA bot (@AstraControlBot) - NOT the channel-support bot
const BOT_SECRET = process.env.LUDO_BOT_SECRET || "";
const TURN_MS = Math.max(10, Number(process.env.LUDO_TURN_SECONDS) || 30) * 1000;
const MAX_ROOMS = 300;
const LOBBY_TTL_MS = 20 * 60_000; // a room nobody started disappears
const KEEP_FINISHED_MS = 30 * 60_000;
const MAX_TIMEOUTS = 3; // missed turns in a row before a player is out
const EPOCH = crypto.randomBytes(4).toString("hex"); // changes on every restart

const rooms = new Map();

// ---------------------------------------------------------------------------------------------
// Telegram initData check (https://core.telegram.org/bots/webapps#validating-data-received-via-the-mini-app)
// ---------------------------------------------------------------------------------------------
function verifyInitData(raw, token = BOT_TOKEN, maxAgeSec = 86400) {
    if (!raw || !token) return null;
    const params = new URLSearchParams(raw);
    const hash = params.get("hash");
    if (!hash) return null;
    params.delete("hash");
    const dcs = [...params.entries()].map(([k, v]) => `${k}=${v}`).sort().join("\n");
    const secret = crypto.createHmac("sha256", "WebAppData").update(token).digest();
    const calc = crypto.createHmac("sha256", secret).update(dcs).digest("hex");
    const a = Buffer.from(calc), b = Buffer.from(hash);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    const age = Date.now() / 1000 - Number(params.get("auth_date") || 0);
    if (!(age >= -60 && age <= maxAgeSec)) return null;
    try {
        const u = JSON.parse(params.get("user") || "null");
        if (!u || typeof u.id !== "number") return null;
        return { id: u.id, name: [u.first_name, u.last_name].filter(Boolean).join(" ") || u.username || String(u.id), username: u.username || null };
    } catch {
        return null;
    }
}

// ---------------------------------------------------------------------------------------------
// Rooms
// ---------------------------------------------------------------------------------------------
function newRoom({ chatId, maxPlayers, bet }) {
    if (rooms.size >= MAX_ROOMS) cleanup(true);
    if (rooms.size >= MAX_ROOMS) throw httpError(503, "Too many games right now");
    let id;
    do id = crypto.randomBytes(5).toString("hex"); while (rooms.has(id));
    const room = { id, chatId: chatId ?? null, maxPlayers: Math.min(4, Math.max(2, maxPlayers | 0 || 2)), bet: Math.max(0, bet | 0), status: "lobby", seats: [], game: null, version: 1, createdAt: Date.now(), finishedAt: null, deadline: null, winnerId: null, reason: null };
    rooms.set(id, room);
    return room;
}
const bump = (room) => void room.version++;
function httpError(status, message) {
    const e = new Error(message);
    e.status = status;
    return e;
}
function seatUser(room, user) {
    if (room.status !== "lobby") throw httpError(409, "The game already started");
    const have = room.seats.find((s) => s.id === user.id);
    if (have) return have;
    if (room.seats.length >= room.maxPlayers) throw httpError(409, "The room is full");
    const seat = { id: user.id, name: String(user.name || user.id).slice(0, 40), username: user.username || null };
    room.seats.push(seat);
    bump(room);
    return seat;
}
function startRoom(room) {
    if (room.status !== "lobby") throw httpError(409, "Already started");
    if (room.seats.length < 2) throw httpError(409, "Need at least 2 players");
    room.game = E.newGame(room.seats.length);
    room.status = "playing";
    room.deadline = Date.now() + TURN_MS;
    bump(room);
}
function finish(room, winnerIdx, reason) {
    room.status = "finished";
    room.finishedAt = Date.now();
    room.winnerId = winnerIdx === null || winnerIdx === undefined ? null : room.seats[winnerIdx].id;
    room.reason = reason;
    room.deadline = null;
    bump(room);
}
function afterAction(room, reason = "finished") {
    const g = room.game;
    if (g.winner !== null) return finish(room, g.winner, reason);
    room.deadline = Date.now() + TURN_MS;
    bump(room);
}

/** The server plays for a player who ran out of time. */
function handleTimeout(room) {
    const g = room.game;
    const pi = g.turn;
    const p = g.players[pi];
    p.timeouts++;
    if (p.timeouts >= MAX_TIMEOUTS) {
        const w = E.forfeit(g, pi);
        if (g.phase === "over") return finish(room, w, w === null ? "abandoned" : "forfeit");
        room.deadline = Date.now() + TURN_MS;
        return bump(room);
    }
    if (g.phase === "roll") {
        E.roll(g);
        if (g.phase === "move") E.applyMove(g, E.bestToken(g));
    } else if (g.phase === "move") {
        E.applyMove(g, E.bestToken(g));
    }
    afterAction(room);
}

function cleanup(force = false) {
    const now = Date.now();
    for (const [id, r] of rooms) {
        if (r.status === "lobby" && now - r.createdAt > LOBBY_TTL_MS) rooms.delete(id);
        else if (r.status === "cancelled" && now - (r.finishedAt || r.createdAt) > 10 * 60_000) rooms.delete(id);
        else if (r.status === "finished" && now - r.finishedAt > KEEP_FINISHED_MS) rooms.delete(id);
        else if (force && r.status === "finished") rooms.delete(id);
    }
}
function tick(now = Date.now()) {
    for (const r of rooms.values()) {
        if (r.status === "playing" && r.deadline && now >= r.deadline) {
            try { handleTimeout(r); } catch (e) { console.error("tick error", e); }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// What a client gets to see
// ---------------------------------------------------------------------------------------------
function publicRoom(room, userId) {
    const g = room.game;
    const you = room.seats.findIndex((s) => s.id === userId);
    return {
        id: room.id,
        status: room.status,
        version: room.version,
        serverTime: Date.now(),
        bet: room.bet,
        maxPlayers: room.maxPlayers,
        winnerId: room.winnerId,
        reason: room.reason,
        you: you >= 0 ? you : null,
        seats: room.seats.map((s, i) => ({ id: s.id, name: s.name, username: s.username, colour: g ? g.players[i].colour : null, active: g ? g.players[i].active : true })),
        game: g && {
            turn: g.turn,
            phase: g.phase,
            dice: g.dice,
            legal: g.phase === "move" ? g.legal : [],
            lastMove: g.lastMove,
            deadline: room.deadline,
            players: g.players.map((p) => ({ colour: p.colour, tokens: p.tokens, finished: p.finished, active: p.active, timeouts: p.timeouts })),
        },
    };
}
const statusForBot = (room) => (room ? { state: room.status, version: room.version, seats: room.seats.map((s) => s.id), winnerId: room.winnerId, reason: room.reason, bet: room.bet } : { state: "missing" });

// ---------------------------------------------------------------------------------------------
// HTTP (an express Router: CORS comes from the backend's own cors() which is mounted before this)
// ---------------------------------------------------------------------------------------------
const router = express.Router();
router.use((req, res, next) => {
    res.setHeader("Cache-Control", "no-store");
    next();
});

// Own, gentler limits: the backend's global 60/min per IP would break live polling, so /api/ludo is exempt from it.
const ipFails = new Map(); // failed logins per IP
const userHits = new Map(); // requests per verified Telegram user
setInterval(() => { ipFails.clear(); userHits.clear(); }, 60_000).unref?.();
const hit = (map, key, max) => {
    const n = (map.get(key) || 0) + 1;
    map.set(key, n);
    if (n > max) throw httpError(429, "Too many requests - slow down");
};
const ipOf = (req) => String(req.headers["x-forwarded-for"] || "").split(",")[0].trim() || req.socket.remoteAddress || "unknown";

const wrap = (fn) => (req, res) => {
    try {
        const out = fn(req, res);
        if (out !== undefined) res.json(out);
    } catch (e) {
        res.status(e.status || 500).json({ error: e.status ? e.message : "Server error" });
        if (!e.status) console.error("[ludo]", e);
    }
};
const botOnly = (req) => {
    const given = Buffer.from(String(req.headers["x-bot-secret"] || ""));
    const want = Buffer.from(BOT_SECRET);
    if (!BOT_SECRET || given.length !== want.length || !crypto.timingSafeEqual(given, want)) {
        hit(ipFails, ipOf(req), 40);
        throw httpError(401, "Not allowed");
    }
};
const player = (req) => {
    const u = verifyInitData(String(req.headers["x-init-data"] || ""));
    if (!u) {
        hit(ipFails, ipOf(req), 40);
        throw httpError(401, "Open this game from Telegram");
    }
    hit(userHits, u.id, 200);
    return u;
};
const getRoom = (id) => {
    const r = rooms.get(String(id));
    if (!r) throw httpError(404, "This game no longer exists");
    return r;
};

router.get("/health", (req, res) => res.json({ ok: true, game: "astra-ludo", epoch: EPOCH, rooms: rooms.size, configured: !!(BOT_TOKEN && BOT_SECRET) }));

// ----- bot -> server
router.post("/bot/rooms", wrap((req) => {
    botOnly(req);
    const { chatId, maxPlayers, bet, creator } = req.body || {};
    const room = newRoom({ chatId, maxPlayers, bet });
    if (creator?.id) seatUser(room, creator);
    return { roomId: room.id, epoch: EPOCH };
}));
router.post("/bot/rooms/:id/seat", wrap((req) => {
    botOnly(req);
    const room = getRoom(req.params.id);
    const u = req.body?.user;
    if (!u?.id) throw httpError(400, "user missing");
    seatUser(room, u);
    return { ok: true, seats: room.seats.length };
}));
router.post("/bot/rooms/:id/start", wrap((req) => {
    botOnly(req);
    startRoom(getRoom(req.params.id));
    return { ok: true };
}));
router.post("/bot/rooms/:id/cancel", wrap((req) => {
    botOnly(req);
    const room = getRoom(req.params.id);
    if (room.status === "lobby") {
        room.status = "cancelled";
        room.finishedAt = Date.now();
        bump(room);
    }
    return { ok: true, state: room.status };
}));
router.post("/bot/status", wrap((req) => {
    botOnly(req);
    const ids = Array.isArray(req.body?.ids) ? req.body.ids.slice(0, 100) : [];
    const out = {};
    for (const id of ids) out[id] = statusForBot(rooms.get(String(id)));
    return { epoch: EPOCH, rooms: out };
}));

// ----- Mini App -> server
router.get("/rooms/:id", wrap((req) => {
    const u = player(req);
    const room = getRoom(req.params.id);
    if (Number(req.query.v) === room.version) return { unchanged: true, version: room.version, serverTime: Date.now() };
    return publicRoom(room, u.id);
}));
function seatIndexOf(room, user) {
    const i = room.seats.findIndex((s) => s.id === user.id);
    if (i < 0) throw httpError(403, "You are watching this game");
    return i;
}
router.post("/rooms/:id/roll", wrap((req) => {
    const u = player(req);
    const room = getRoom(req.params.id);
    if (room.status !== "playing") throw httpError(409, "The game is not running");
    const i = seatIndexOf(room, u);
    const g = room.game;
    if (g.turn !== i) throw httpError(409, "Not your turn");
    if (g.phase !== "roll") throw httpError(409, "Pick a token to move");
    g.players[i].timeouts = 0;
    E.roll(g);
    afterAction(room);
    return publicRoom(room, u.id);
}));
router.post("/rooms/:id/move", wrap((req) => {
    const u = player(req);
    const room = getRoom(req.params.id);
    if (room.status !== "playing") throw httpError(409, "The game is not running");
    const i = seatIndexOf(room, u);
    const g = room.game;
    if (g.turn !== i) throw httpError(409, "Not your turn");
    if (g.phase !== "move") throw httpError(409, "Roll the dice first");
    const token = Number(req.body?.token);
    if (![0, 1, 2, 3].includes(token)) throw httpError(400, "Bad token");
    try { E.applyMove(g, token); } catch { throw httpError(409, "That token cannot move"); }
    g.players[i].timeouts = 0;
    afterAction(room);
    return publicRoom(room, u.id);
}));
router.post("/rooms/:id/leave", wrap((req) => {
    const u = player(req);
    const room = getRoom(req.params.id);
    if (room.status !== "playing") throw httpError(409, "The game is not running");
    const i = seatIndexOf(room, u);
    const g = room.game;
    if (!g.players[i].active) return publicRoom(room, u.id);
    const w = E.forfeit(g, i);
    if (g.phase === "over") finish(room, w, w === null ? "abandoned" : "forfeit");
    else { room.deadline = Date.now() + TURN_MS; bump(room); }
    return publicRoom(room, u.id);
}));

// background work (unref'd so it never keeps the process alive on its own)
setInterval(() => tick(), 1000).unref?.();
setInterval(() => cleanup(), 60_000).unref?.();
if (!BOT_TOKEN || !BOT_SECRET) console.warn("[ludo] LUDO_BOT_TOKEN / LUDO_BOT_SECRET not set - Ludo is disabled until you add them (see .env.example)");

module.exports = { router, rooms, verifyInitData, tick, newRoom, seatUser, startRoom, handleTimeout, TURN_MS, ipFails, userHits };
