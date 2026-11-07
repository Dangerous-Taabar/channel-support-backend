// certificate.js — renders the "Certificate of Support" image (Silver / Gold / Platinum)
// by writing the supporter's live data on top of the blank templates.
// Needs:  npm install @napi-rs/canvas
//
// HOW TEMPLATES + LAYOUTS WORK (so you never have to touch the site / GitHub for a new festival card):
//   * Template image   : Redis key  certtpl:<tier>    (uploaded from the bot panel). Falls back to assets/cert/<tier>.png
//   * Text layout      : Redis key  certlayout:<tier>  (fine-tuned from the bot panel). Falls back to a built-in preset.
//   * Layouts are stored as FRACTIONS of the image width / height, so a template works at ANY resolution
//     (1024x576, Telegram's compressed 1280x720, the original 1672x941 ...) and the text always lands in the same spot.
//   server.js plugs Redis in through setProviders() — this file never talks to Redis itself.
const path = require('path');
const fs = require('fs');
const { createCanvas, loadImage, GlobalFonts } = require('@napi-rs/canvas');

const ASSETS = path.join(__dirname, 'assets');
const GOLD_DAYS = parseInt(process.env.CERT_GOLD_DAYS || '30', 10);
const PLATINUM_DAYS = parseInt(process.env.CERT_PLATINUM_DAYS || '75', 10);
const TIERS = ['silver', 'gold', 'platinum'];

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

// ---- Colours per tier (metal look of the numbers / name) ---------------------
const STYLE = {
  gold: {
    stops: [[0, '#fff3c4'], [0.38, '#f6cf6a'], [0.62, '#d9a441'], [1, '#a8741f']],
    glow: 'rgba(255,190,80,0.85)', edge: 'rgba(255,244,200,0.55)', small_color: '#e8cf93',
  },
  silver: {
    stops: [[0, '#ffffff'], [0.4, '#d6e2f5'], [0.65, '#9fb3d1'], [1, '#6c7f9f']],
    glow: 'rgba(110,170,255,0.85)', edge: 'rgba(255,255,255,0.5)', small_color: '#cdd6e6',
  },
  platinum: {
    stops: [[0, '#ffffff'], [0.4, '#e6f2ff'], [0.68, '#bcd9f5'], [1, '#8fb2d6']],
    glow: 'rgba(70,160,255,0.9)', edge: 'rgba(255,255,255,0.55)', small_color: '#bfe0ff',
  },
};

// Festival templates have different colours than the old classic ones (the Diamond card is ruby red), so the number
// colours follow the preset too. Gold keeps its gold metal.
const FESTIVAL_STYLE = {
  silver:   { glow: 'rgba(255,215,160,0.75)' },
  platinum: { stops: [[0, '#ffffff'], [0.4, '#ffe9ee'], [0.68, '#ff9fb2'], [1, '#e2445e']], glow: 'rgba(255,60,90,0.9)', edge: 'rgba(255,255,255,0.6)', small_color: '#ffd0d8' },
};
function styleFor(tier, lay) { return Object.assign({}, STYLE[tier], lay && lay.preset === 'festival' ? FESTIVAL_STYLE[tier] : null); }

// ---- Layout presets (all numbers are FRACTIONS: x/cx/maxW of width, base/size of height) -------------
// "classic"  = the original 1672x941 templates (name + 2 numbers + "Issued"/"Certificate ID" footer line)
// "festival" = the ChatGPT-style festival templates (name between the two ornament lines, numbers inside the laurels,
//              no footer text because the festival ribbon already sits there)
const CW = 1672, CH = 941;
const CLASSIC_PX = {
  gold:     { nameCx: 836, nameBase: 475, nameSize: 85, nameMaxW: 700, days: [436, 645, 92, 108], streak: [806, 645, 92, 90],  date: [138, 849, 194], cid: [1321, 849, 224] },
  silver:   { nameCx: 837, nameBase: 455, nameSize: 95, nameMaxW: 740, days: [475, 671, 81, 96],  streak: [836, 671, 81, 96],  date: [155, 819, 154], cid: [1351, 819, 209] },
  platinum: { nameCx: 836, nameBase: 488, nameSize: 98, nameMaxW: 760, days: [528, 693, 74, 92],  streak: [838, 693, 74, 92],  date: [169, 864, 143], cid: [1449, 864, 184] },
};
function classicLayout(tier) {
  const p = CLASSIC_PX[tier] || CLASSIC_PX.gold;
  const f = (a) => ({ cx: a[0] / CW, base: a[1] / CH, size: a[2] / CH, maxW: a[3] / CW });
  return {
    preset: 'classic',
    name: { cx: p.nameCx / CW, base: p.nameBase / CH, size: p.nameSize / CH, maxW: p.nameMaxW / CW },
    days: f(p.days), streak: f(p.streak),
    date: { x: p.date[0] / CW, base: p.date[1] / CH, maxW: p.date[2] / CW },
    cid: { x: p.cid[0] / CW, base: p.cid[1] / CH, maxW: p.cid[2] / CW },
    small: 21 / CH,
  };
}
// Measured per template (name between the two ornaments, numbers inside the laurels, level with the tier text):
//   gold     -> 1024x576  Diwali template (streak number sits LEFT of the flame icon)
//   silver   -> 1280x720  Diwali fireworks template
//   platinum -> 1280x721  Diwali "Diamond" template
const FESTIVAL_PX = {
  gold:     { w: 1024, h: 576, name: [512, 246, 44, 460], days: [258, 340, 40, 84],  streak: [487, 340, 40, 56] },
  silver:   { w: 1280, h: 720, name: [640, 274, 42, 520], days: [371, 366, 40, 100], streak: [627, 366, 40, 110] },
  platinum: { w: 1280, h: 721, name: [640, 288, 42, 500], days: [379, 388, 40, 100], streak: [624, 388, 40, 110] },
};
function festivalLayout(tier) {
  const p = FESTIVAL_PX[tier] || FESTIVAL_PX.gold;
  const f = (a) => ({ cx: a[0] / p.w, base: a[1] / p.h, size: a[2] / p.h, maxW: a[3] / p.w });
  return { preset: 'festival', name: f(p.name), days: f(p.days), streak: f(p.streak), date: null, cid: null, small: 21 / p.h };
}
function defaultLayout(tier, preset) {
  return preset === 'festival' ? festivalLayout(tier) : classicLayout(tier);
}
// With nothing saved: the old full-size 16:9 templates (~1672x941) -> classic, anything else (1024x576 festival art,
// Telegram's 1280x720 compressed copy, ...) -> festival. The bot also saves the layout at upload time, so this is only a fallback.
function guessPreset(w, h) { return (w >= 1600 && Math.abs(w / h - 16 / 9) < 0.02) ? 'classic' : 'festival'; }

function sanitizeLayout(l, tier, w, h) {
  const base = defaultLayout(tier, (l && l.preset === 'festival') ? 'festival' : (l && l.preset === 'classic') ? 'classic' : guessPreset(w, h));
  if (!l || typeof l !== 'object') return base;
  const out = { preset: l.preset || base.preset, small: Number(l.small) > 0 ? Number(l.small) : base.small, date: base.date, cid: base.cid };
  for (const k of ['name', 'days', 'streak']) {
    const s = l[k] || {}, b = base[k];
    const num = (v, d) => (Number.isFinite(Number(v)) && v !== null && v !== '' ? Number(v) : d);
    out[k] = { cx: num(s.cx, b.cx), base: num(s.base, b.base), size: num(s.size, b.size), maxW: num(s.maxW, b.maxW) };
  }
  if ('date' in l) out.date = l.date; if ('cid' in l) out.cid = l.cid;
  return out;
}

// loadImage() from the canvas library never settles on some corrupt buffers, which would freeze every certificate
// render (and the group post). Check the file signature first and give up after a few seconds.
function looksLikeImage(b) {
  if (!Buffer.isBuffer(b) || b.length < 64) return false;
  const png = b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47;
  const jpg = b[0] === 0xff && b[1] === 0xd8;
  const webp = b.slice(0, 4).toString() === 'RIFF' && b.slice(8, 12).toString() === 'WEBP';
  return png || jpg || webp;
}
async function safeLoadImage(b) {
  if (!looksLikeImage(b)) throw new Error('Ye valid PNG / JPG / WEBP image nahi hai.');
  let timer;
  const guard = new Promise((_, rej) => { timer = setTimeout(() => rej(new Error('Image decode timeout — file corrupt lag rahi hai.')), 8000); });
  try { return await Promise.race([loadImage(b), guard]); } finally { clearTimeout(timer); }
}

// ---- Storage hooks (set by server.js) -------------------------------------------------
let providers = { loadTemplate: null, loadLayout: null };
function setProviders(p) { providers = Object.assign({ loadTemplate: null, loadLayout: null }, p || {}); templates.clear(); }

const templates = new Map(); // tier -> { img, w, h, source, layout, layoutSource }
async function getTemplate(tier) {
  if (templates.has(tier)) return templates.get(tier);
  let img = null, source = 'file';
  if (providers.loadTemplate) {
    try {
      const buf = await providers.loadTemplate(tier);
      if (buf && buf.length) { img = await safeLoadImage(buf); source = 'bot'; }
    } catch (e) { console.error('[cert] stored template unusable, using packaged file:', e.message); img = null; }
  }
  if (!img) img = await loadImage(path.join(ASSETS, 'cert', tier + '.png'));
  let stored = null;
  if (providers.loadLayout) { try { stored = await providers.loadLayout(tier); } catch (e) { stored = null; } }
  const layout = sanitizeLayout(stored, tier, img.width, img.height);
  const entry = { img, w: img.width, h: img.height, source, layout, layoutSource: stored ? 'custom' : 'preset' };
  templates.set(tier, entry);
  return entry;
}
function clearTemplateCache(tier) {
  if (tier) templates.delete(tier); else templates.clear();
}
async function templateInfo(tier) {
  const t = await getTemplate(tier);
  return { width: t.w, height: t.h, source: t.source, preset: t.layout.preset, layoutSource: t.layoutSource, layout: t.layout };
}

// Re-encodes an uploaded image so it is small enough for Redis (<= ~640 KB) without visible quality loss.
async function prepareTemplate(buffer) {
  const img = await safeLoadImage(buffer);
  let w = img.width, h = img.height;
  if (w < 500 || h < 280) throw new Error(`Image bahut chhoti hai (${w}x${h}). Kam se kam 1000px chaudi image bhejo.`);
  const MAXW = 1800;
  if (w > MAXW) { h = Math.round(h * MAXW / w); w = MAXW; }
  const LIMIT = 640 * 1024;
  let out = null;
  for (let round = 0; round < 4 && !out; round++) {
    const canvas = createCanvas(w, h);
    canvas.getContext('2d').drawImage(img, 0, 0, w, h);
    for (const q of [92, 88, 84, 80, 75, 70]) {
      const b = await canvas.encode('jpeg', q);
      if (b.length <= LIMIT) { out = b; break; }
    }
    if (!out) { w = Math.round(w * 0.88); h = Math.round(h * 0.88); }
  }
  if (!out) throw new Error('Image compress nahi ho payi — simple/chhoti image bhejo.');
  return { buffer: out, width: w, height: h, aspect: w / h };
}

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
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
  const minSize = Math.max(10, size * 0.4);
  ctx.textAlign = 'center'; ctx.textBaseline = 'alphabetic';
  ctx.font = `${s}px ${DISPLAY}`;
  while (ctx.measureText(text).width > maxW && s > minSize) { s -= 1; ctx.font = `${s}px ${DISPLAY}`; }
  ctx.lineJoin = 'round';
  ctx.save(); ctx.shadowColor = L.glow; ctx.shadowBlur = Math.max(6, s * 0.25); ctx.fillStyle = L.glow; ctx.globalAlpha = 0.5; ctx.fillText(text, cx, base); ctx.restore();
  ctx.save(); ctx.lineWidth = Math.max(2, s * 0.035); ctx.strokeStyle = 'rgba(0,0,0,0.6)'; ctx.strokeText(text, cx, base); ctx.restore();
  ctx.fillStyle = metalGradient(ctx, L.stops, base - s * 0.72, base + s * 0.04);
  ctx.fillText(text, cx, base);
  ctx.save(); ctx.lineWidth = Math.max(0.8, s * 0.014); ctx.strokeStyle = L.edge; ctx.strokeText(text, cx, base); ctx.restore();
}
// Left-aligned footer text that shrinks to fit the space the template leaves for it (icons sit just before x).
function smallText(ctx, text, x, base, size, maxW, color) {
  let s = size;
  ctx.textAlign = 'left'; ctx.textBaseline = 'alphabetic';
  ctx.font = `${s}px ${TEXT}`;
  while (ctx.measureText(text).width > maxW && s > 8) { s -= 0.5; ctx.font = `${s}px ${TEXT}`; }
  ctx.save(); ctx.shadowColor = 'rgba(0,0,0,0.7)'; ctx.shadowBlur = 4; ctx.fillStyle = color; ctx.fillText(text, x, base); ctx.restore();
}
// Calibration helper: thin cyan box + centre cross around the field being nudged (only in "Adjust layout" previews).
function drawGuide(ctx, f, W, H, label) {
  const cx = f.cx * W, base = f.base * H, size = f.size * H, mw = f.maxW * W;
  ctx.save();
  ctx.strokeStyle = 'rgba(0,255,255,0.95)'; ctx.lineWidth = Math.max(1.5, W / 700); ctx.setLineDash([6, 4]);
  ctx.strokeRect(cx - mw / 2, base - size * 0.78, mw, size * 0.95);
  ctx.setLineDash([]);
  const r = Math.max(5, W / 160);
  ctx.beginPath(); ctx.moveTo(cx - r, base); ctx.lineTo(cx + r, base); ctx.moveTo(cx, base - r); ctx.lineTo(cx, base + r); ctx.stroke();
  if (label) {
    const fs = Math.max(12, Math.round(W / 70));
    ctx.font = `bold ${fs}px ${TEXT}`; ctx.textAlign = 'center'; ctx.textBaseline = 'alphabetic';
    ctx.fillStyle = 'rgba(0,255,255,1)'; ctx.shadowColor = 'rgba(0,0,0,0.9)'; ctx.shadowBlur = 4;
    ctx.fillText(label, cx, base - size * 0.78 + (size * 0.95) / 2 + fs * 0.35); // centred inside the box
  }
  ctx.restore();
}

/**
 * opts: { name, totalDays, streak, tier?, issuedAt?, firstSupportAt?, format?, highlight? }
 * highlight: 'name' | 'days' | 'streak'  -> draws a cyan guide box (used only by the bot's "Adjust layout" preview)
 * returns a Buffer (JPEG by default, or PNG when format === 'png')
 */
async function renderCertificate(opts) {
  const totalDays = Math.max(0, parseInt(opts.totalDays, 10) || 0);
  const streak = Math.max(0, parseInt(opts.streak, 10) || 0);
  const tier = STYLE[opts.tier] ? opts.tier : tierForDays(totalDays);
  // opts.templateBuffer / opts.layout render a card that is NOT live (used for Festival Set previews)
  let T;
  if (opts.templateBuffer) {
    const img = await safeLoadImage(opts.templateBuffer);
    T = { img, w: img.width, h: img.height, layout: sanitizeLayout(opts.layout, tier, img.width, img.height) };
  } else T = await getTemplate(tier);
  const W = T.w, H = T.h, lay = T.layout, S = styleFor(tier, lay);
  const canvas = createCanvas(W, H);
  const ctx = canvas.getContext('2d');
  ctx.drawImage(T.img, 0, 0);

  const field = (f) => [f.cx * W, f.base * H, f.size * H, f.maxW * W];
  if (!opts.guideOnly) { // guideOnly = empty template + labelled boxes (reference image for ChatGPT)
    metalText(ctx, cleanName(opts.name), ...field(lay.name), S);
    metalText(ctx, String(totalDays), ...field(lay.days), S);
    metalText(ctx, String(streak), ...field(lay.streak), S);
  }
  if (!opts.guideOnly && lay.date && lay.cid) {
    const small = lay.small * H;
    smallText(ctx, 'Issued: ' + istDateStr(opts.issuedAt), lay.date.x * W, lay.date.base * H, small, lay.date.maxW * W, S.small_color);
    smallText(ctx, 'Certificate ID: ' + certId(opts.rawName != null ? opts.rawName : opts.name, totalDays, opts.firstSupportAt), lay.cid.x * W, lay.cid.base * H, small, lay.cid.maxW * W, S.small_color);
  }
  if (opts.highlight === 'all') {
    drawGuide(ctx, lay.name, W, H, 'NAME'); drawGuide(ctx, lay.days, W, H, 'DAYS'); drawGuide(ctx, lay.streak, W, H, 'STREAK');
  } else if (opts.highlight && lay[opts.highlight]) drawGuide(ctx, lay[opts.highlight], W, H);

  return opts.format === 'png' ? canvas.encode('png') : canvas.encode('jpeg', 94);
}

module.exports = {
  renderCertificate, tierForDays, cleanName, clearTemplateCache,
  setProviders, templateInfo, prepareTemplate, defaultLayout, sanitizeLayout, TIERS,
};
