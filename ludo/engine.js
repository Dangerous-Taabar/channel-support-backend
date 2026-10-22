"use strict";
/**
 * Ludo rules engine — pure functions, no network, no timers. The server owns one of these per room.
 *
 * Board: a ring of 52 track cells. Colours 0..3 (red, green, yellow, blue) start on cells 0, 13, 26, 39.
 * A token's position `pos` (from its owner's point of view):
 *   -1        in the base (needs a 6 to come out)
 *   0..50     on the main track (0 = the owner's start cell); absolute cell = (START[colour] + pos) % 52
 *   51..55    in the owner's home column (nobody can be captured there)
 *   56        finished (needs the EXACT number to land here)
 * Safe cells (no captures): the 4 start cells and the 4 star cells (8 steps after each start).
 * Rolling a 6, capturing, or finishing a token gives another roll. Three 6s in a row cancels the turn.
 * The first player with all 4 tokens home wins.
 */
const crypto = require("crypto");

const START = [0, 13, 26, 39];
const SAFE = new Set([0, 13, 26, 39, 8, 21, 34, 47]);
const FINISH = 56;
const COLOR_SETS = { 2: [0, 2], 3: [0, 1, 2], 4: [0, 1, 2, 3] };
const defaultRng = () => crypto.randomInt(1, 7);

const absCell = (colour, pos) => (pos >= 0 && pos <= 50 ? (START[colour] + pos) % 52 : null);

function newGame(playerCount, rng = defaultRng, firstPlayer = null) {
    const colours = COLOR_SETS[playerCount];
    if (!colours) throw new Error("Ludo needs 2 to 4 players");
    return {
        players: colours.map((colour) => ({ colour, tokens: [-1, -1, -1, -1], finished: 0, active: true, timeouts: 0 })),
        turn: firstPlayer ?? crypto.randomInt(0, playerCount),
        phase: "roll", // "roll" = current player must roll, "move" = must pick a token
        dice: null, // { value, by (player index), seq }
        sixes: 0, // consecutive sixes in this turn chain
        seq: 0,
        lastMove: null, // { by, token, from, to, captured:[{by,token}], seq }
        winner: null,
        legal: [],
    };
}

/** Which tokens of player `pi` may move with `dice`? -> [{ token, to }] */
function legalMoves(game, pi, dice) {
    const p = game.players[pi];
    const out = [];
    const seen = new Set(); // tokens standing on the same spot are interchangeable: offer one
    p.tokens.forEach((pos, token) => {
        if (pos === FINISH || seen.has(pos)) return;
        seen.add(pos);
        if (pos === -1) {
            if (dice === 6) out.push({ token, to: 0 });
        } else if (pos < FINISH && pos + dice <= FINISH) {
            out.push({ token, to: pos + dice });
        }
    });
    return out;
}

function nextActive(game, from) {
    const n = game.players.length;
    for (let i = 1; i <= n; i++) {
        const idx = (from + i) % n;
        if (game.players[idx].active) return idx;
    }
    return from;
}

function endTurnTo(game, idx) {
    game.turn = idx;
    game.phase = "roll";
    game.sixes = 0;
    game.legal = [];
}

/** Roll the dice for the current player. Returns { value, moves, auto?: move result, passed?: bool }. */
function roll(game, rng = defaultRng) {
    if (game.winner !== null) throw new Error("Game is over");
    if (game.phase !== "roll") throw new Error("Not time to roll");
    const pi = game.turn;
    const value = rng();
    game.seq++;
    game.dice = { value, by: pi, seq: game.seq };
    const res = { value, by: pi, moves: [], passed: false, auto: null, threeSixes: false };

    if (value === 6) game.sixes++;
    if (game.sixes >= 3) {
        // third six in a row: the turn is lost, nothing moves
        res.threeSixes = true;
        res.passed = true;
        endTurnTo(game, nextActive(game, pi));
        return res;
    }
    const moves = legalMoves(game, pi, value);
    res.moves = moves;
    if (moves.length === 0) {
        res.passed = true;
        endTurnTo(game, nextActive(game, pi));
        return res;
    }
    if (moves.length === 1) {
        res.auto = applyMove(game, moves[0].token); // only one choice: play it
        return res;
    }
    game.phase = "move";
    game.legal = moves.map((m) => m.token);
    return res;
}

/** Move token `token` of the current player by the rolled value. */
function applyMove(game, token) {
    if (game.phase !== "roll" && game.phase !== "move") throw new Error("Bad phase");
    const pi = game.turn;
    const value = game.dice?.value;
    if (!value) throw new Error("Roll first");
    token = game.players[pi].tokens.indexOf(game.players[pi].tokens[token]); // identical tokens: use the first one
    const move = legalMoves(game, pi, value).find((m) => m.token === token);
    if (!move) throw new Error("That token cannot move");
    const p = game.players[pi];
    const from = p.tokens[token];
    const to = move.to;
    p.tokens[token] = to;
    const captured = [];
    const cell = absCell(p.colour, to);
    if (cell !== null && !SAFE.has(cell)) {
        game.players.forEach((q, qi) => {
            if (qi === pi) return;
            q.tokens.forEach((qpos, qt) => {
                if (absCell(q.colour, qpos) === cell) {
                    q.tokens[qt] = -1;
                    captured.push({ by: qi, token: qt });
                }
            });
        });
    }
    let finishedNow = false;
    if (to === FINISH) {
        p.finished++;
        finishedNow = true;
    }
    game.seq++;
    game.lastMove = { by: pi, token, from, to, captured, finished: finishedNow, seq: game.seq };
    game.legal = [];
    if (p.finished === 4) {
        game.winner = pi;
        game.phase = "over";
        return { token, from, to, captured, finished: finishedNow, bonus: false, won: true };
    }
    const bonus = value === 6 || captured.length > 0 || finishedNow;
    if (bonus) {
        game.phase = "roll"; // same player rolls again (the six-counter keeps running)
        if (value !== 6) game.sixes = 0;
    } else {
        endTurnTo(game, nextActive(game, pi));
    }
    return { token, from, to, captured, finished: finishedNow, bonus, won: false };
}

/** Sensible automatic choice (used on timeouts and by tests): finish > capture > leave base > furthest token. */
function bestToken(game) {
    const pi = game.turn;
    const p = game.players[pi];
    const value = game.dice.value;
    const moves = legalMoves(game, pi, value);
    let best = null;
    let bestScore = -1;
    for (const m of moves) {
        let score = p.tokens[m.token] + value; // progress
        if (m.to === FINISH) score += 1000;
        const cell = absCell(p.colour, m.to);
        if (cell !== null && !SAFE.has(cell)) {
            const hits = game.players.some((q, qi) => qi !== pi && q.tokens.some((pos) => absCell(q.colour, pos) === cell));
            if (hits) score += 500;
        }
        if (p.tokens[m.token] === -1) score += 300;
        if (score > bestScore) {
            bestScore = score;
            best = m.token;
        }
    }
    return best;
}

/** A player stops taking part (left / timed out too often). Returns the winner index if only one is left. */
function forfeit(game, pi) {
    const p = game.players[pi];
    p.active = false;
    p.tokens = p.tokens.map(() => -1);
    const alive = game.players.map((x, i) => (x.active ? i : -1)).filter((i) => i >= 0);
    if (alive.length === 1) {
        game.winner = alive[0];
        game.phase = "over";
        return alive[0];
    }
    if (alive.length === 0) {
        game.phase = "over";
        return null;
    }
    if (game.turn === pi) endTurnTo(game, nextActive(game, pi));
    return null;
}

module.exports = { START, SAFE, FINISH, COLOR_SETS, absCell, newGame, legalMoves, roll, applyMove, bestToken, forfeit };
