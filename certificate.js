// certificate.js — renders the "Certificate of Support" image (Silver / Gold / Platinum)
// by writing the supporter's live data on top of the blank templates in assets/cert/.
// Needs:  npm install @napi-rs/canvas
const path = require('path');
const fs = require('fs');
const { createCanvas, loadImage, GlobalFonts } = require('@napi-rs/canvas');

const ASSETS = path.join(__dirname, 'assets');
const GOLD_DAYS = parseInt(process.env.CERT_GOLD_DAYS || '30', 10);
const PLATINUM_DAYS = parseInt(process.env.CERT_PLATINUM_DAYS || '75', 10);

// ---- Fonts -----------------------------------------------------------------
// Want a fancier look? Drop any bold serif .ttf at assets/fonts/display.ttf
// (e.g. Playfair Display Bold) and it is used for name + numbers automatically.
const displayFile = fs.existsSync(path.join(ASSETS, 'fonts', 'display.ttf'))
  ? 'display.ttf' : 'LiberationSerif-Bold.ttf';
GlobalFonts.registerFromPath(path.join(ASSETS, 'fonts', displayFile), 'CertDisplay');
GlobalFonts.registerFromPath(path.join(ASSETS, 'fonts', 'LiberationSerif-Regular.ttf'), 'CertText');
GlobalFonts.registerFromPath(path.join(ASSETS, 'fonts', 'FreeSerifBold.ttf'), 'CertFallback'); // Devanagari etc.
const DISPLAY = '"CertDisplay", "CertFallback", serif';
const TEXT = '"CertText", "CertFallback", serif';

// ---- Layout (pixel positions on the 1672x941 templates) ----------------------
const LAYOUT = {
  gold: {
    nameCx: 836, nameBase: 475, nameSize: 85, nameMaxW: 700,
    days:   { cx: 436, base: 645, size: 92, maxW: 108 },
    streak: { cx: 806, base: 645, size: 92, maxW: 90 },   // flame icon sits to the right
    date: { x: 138, maxW: 194, base: 849 }, cid: { x: 1321, maxW: 224, base: 849 }, small: 21,
    stops: [[0, '#fff3c4'], [0.38, '#f6cf6a'], [0.62, '#d9a441'], [1, '#a8741f']],
    glow: 'rgba(255,190,80,0.85)', edge: 'rgba(255,244,200,0.55)', small_color: '#e8cf93',
  },
  silver: {
    nameCx: 837, nameBase: 455, nameSize: 95, nameMaxW: 740,
    days:   { cx: 475, base: 671, size: 81, maxW: 96 },
    streak: { cx: 836, base: 671, size: 81, maxW: 96 },
    date: { x: 155, maxW: 154, base: 819 }, cid: { x: 1351, maxW: 209, base: 819 }, small: 21,
    stops: [[0, '#ffffff'], [0.4, '#d6e2f5'], [0.65, '#9fb3d1'], [1, '#6c7f9f']],
    glow: 'rgba(110,170,255,0.85)', edge: 'rgba(255,255,255,0.5)', small_color: '#cdd6e6',
  },
  platinum: {
    nameCx: 836, nameBase: 488, nameSize: 98, nameMaxW: 760,
    days:   { cx: 528, base: 693, size: 74, maxW: 92 },
    streak: { cx: 838, base: 693, size: 74, maxW: 92 },
    date: { x: 169, maxW: 143, base: 864 }, cid: { x: 1449, maxW: 184, base: 864 }, small: 21,
    stops: [[0, '#ffffff'], [0.4, '#e6f2ff'], [0.68, '#bcd9f5'], [1, '#8fb2d6']],
    glow: 'rgba(70,160,255,0.9)', edge: 'rgba(255,255,255,0.55)', small_color: '#bfe0ff',
  },
};

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const templates = new Map();
async function getTemplate(tier) {
  if (!templates.has(tier)) templates.set(tier, await loadImage(path.join(ASSETS, 'cert', tier + '.png')));
  return templates.get(tier);
}

function tierForDays(totalDays) {
  const d = Number(totalDays) || 0;
  if (d >= PLATINUM_DAYS) return 'platinum';
  if (d >= GOLD_DAYS) return 'gold';
  return 'silver';
}
function istDateStr(ts) {
  const d = new Date((ts || Date.now()) + 5.5 * 60 * 60 * 1000);
  return `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()}`;
}
// Same algorithm as certId() on the website dashboard, so "ID CSC-XXXX-XXXX" there and the ID on the image always match.
function certId(name, totalDays, firstSupportAt) {
  const str = (name || '') + '|' + (totalDays || 0) + '|' + (firstSupportAt || 0);
  let h = 0;
  for (let i = 0; i < str.length; i++) h = (h * 31 + str.charCodeAt(i)) >>> 0;
  const x = h.toString(16).toUpperCase().padStart(8, '0');
  return x.slice(0, 4) + '-' + x.slice(4, 8);
}
// Keep letters/marks/digits/space and a few name punctuation chars (drops emoji & symbols the font can't draw).
function cleanName(raw) {
  let s = String(raw || '').normalize('NFC').replace(/[^\p{L}\p{M}\p{N}\s.'’\-_]/gu, '').replace(/\s+/g, ' ').trim();
  if (!s) s = 'Supporter';
  return s.length > 30 ? s.slice(0, 29).trimEnd() + '…' : s;
}

function metalGradient(ctx, stops, top, bottom) {
  const g = ctx.createLinearGradient(0, top, 0, bottom);
  stops.forEach(([p, c]) => g.addColorStop(p, c));
  return g;
}
// Draws centered text that shrinks to fit maxW; glow + dark outline + metal gradient + bright edge.
function metalText(ctx, text, cx, base, size, maxW, L) {
  let s = size;
  ctx.textAlign = 'center'; ctx.textBaseline = 'alphabetic';
  ctx.font = `${s}px ${DISPLAY}`;
  while (ctx.measureText(text).width > maxW && s > 24) { s -= 2; ctx.font = `${s}px ${DISPLAY}`; }
  ctx.lineJoin = 'round';
  ctx.save(); ctx.shadowColor = L.glow; ctx.shadowBlur = 22; ctx.fillStyle = L.glow; ctx.globalAlpha = 0.5; ctx.fillText(text, cx, base); ctx.restore();
  ctx.save(); ctx.lineWidth = Math.max(3, s * 0.035); ctx.strokeStyle = 'rgba(0,0,0,0.6)'; ctx.strokeText(text, cx, base); ctx.restore();
  ctx.fillStyle = metalGradient(ctx, L.stops, base - s * 0.72, base + s * 0.04);
  ctx.fillText(text, cx, base);
  ctx.save(); ctx.lineWidth = 1.2; ctx.strokeStyle = L.edge; ctx.strokeText(text, cx, base); ctx.restore();
}
// Left-aligned footer text that shrinks to fit the space the template leaves for it (icons sit just before x).
function smallText(ctx, text, x, base, size, maxW, color) {
  let s = size;
  ctx.textAlign = 'left'; ctx.textBaseline = 'alphabetic';
  ctx.font = `${s}px ${TEXT}`;
  while (ctx.measureText(text).width > maxW && s > 12) { s -= 0.5; ctx.font = `${s}px ${TEXT}`; }
  ctx.save(); ctx.shadowColor = 'rgba(0,0,0,0.7)'; ctx.shadowBlur = 4; ctx.fillStyle = color; ctx.fillText(text, x, base); ctx.restore();
}

/**
 * opts: { name, totalDays, streak, tier?, issuedAt?, firstSupportAt?, format? }
 * returns a Buffer (JPEG by default, or PNG when format === 'png')
 */
async function renderCertificate(opts) {
  const totalDays = Math.max(0, parseInt(opts.totalDays, 10) || 0);
  const streak = Math.max(0, parseInt(opts.streak, 10) || 0);
  const tier = LAYOUT[opts.tier] ? opts.tier : tierForDays(totalDays);
  const L = LAYOUT[tier];
  const img = await getTemplate(tier);
  const canvas = createCanvas(img.width, img.height);
  const ctx = canvas.getContext('2d');
  ctx.drawImage(img, 0, 0);

  metalText(ctx, cleanName(opts.name), L.nameCx, L.nameBase, L.nameSize, L.nameMaxW, L);
  metalText(ctx, String(totalDays), L.days.cx, L.days.base, L.days.size, L.days.maxW, L);
  metalText(ctx, String(streak), L.streak.cx, L.streak.base, L.streak.size, L.streak.maxW, L);
  smallText(ctx, 'Issued: ' + istDateStr(opts.issuedAt), L.date.x, L.date.base, L.small, L.date.maxW, L.small_color);
  smallText(ctx, 'Certificate ID: ' + certId(opts.rawName != null ? opts.rawName : opts.name, totalDays, opts.firstSupportAt), L.cid.x, L.cid.base, L.small, L.cid.maxW, L.small_color);

  return opts.format === 'png' ? canvas.encode('png') : canvas.encode('jpeg', 94);
}

module.exports = { renderCertificate, tierForDays, cleanName };
