const puppeteer = require('puppeteer-core');
const path = require('path');
const fs = require('fs');
const { execSync } = require('child_process');

async function main() {
  const edgePath = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe';
  const chromePath = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
  const execPath = fs.existsSync(edgePath) ? edgePath : chromePath;

  console.log('Using browser at:', execPath);

  const browser = await puppeteer.launch({
    executablePath: execPath,
    headless: 'new',
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--allow-file-access-from-files']
  });

  const page = await browser.newPage();
  await page.setViewport({ width: 1200, height: 900 });

  const htmlPath = path.resolve(__dirname, '..', 'index.html');
  await page.goto('file:///' + htmlPath.replace(/\\/g, '/'), { waitUntil: 'domcontentloaded' });

  // Make certificate screen active
  await page.evaluate(() => {
    document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
    const s = document.getElementById('s-certificate');
    if (s) s.classList.add('active');
    window.supporter = { name: 'VIP Member', totalDays: 45, streak: 14 };
    if (typeof initCardParticles === 'function') initCardParticles();
  });

  // Themes to render
  const themes = ['navratri', 'diwali', 'normal'];

  // Ensure output dirs
  const publicDir = path.resolve(__dirname, '..', 'public');
  if (!fs.existsSync(publicDir)) fs.mkdirSync(publicDir, { recursive: true });

  const framesDir = path.resolve(__dirname, '..', 'temp_frames');
  if (!fs.existsSync(framesDir)) fs.mkdirSync(framesDir, { recursive: true });

  for (const theme of themes) {
    console.log(`Generating 30fps frames for theme: ${theme}...`);
    // Clean frames dir
    const oldFiles = fs.readdirSync(framesDir);
    for (const f of oldFiles) fs.unlinkSync(path.join(framesDir, f));

    // Render 90 frames (3 seconds at 30 fps)
    const totalFrames = 90;
    for (let i = 0; i < totalFrames; i++) {
      const timeMs = (i / totalFrames) * 3000;
      const dataUrl = await page.evaluate(({ theme, timeMs }) => {
        drawCertificate(theme, timeMs);
        const c = document.getElementById('certCanvas');
        return c ? c.toDataURL('image/png') : null;
      }, { theme, timeMs });

      if (!dataUrl) throw new Error('Canvas dataURL is null');
      const base64Data = dataUrl.replace(/^data:image\/png;base64,/, '');
      const pad = String(i).padStart(4, '0');
      fs.writeFileSync(path.join(framesDir, `frame_${pad}.png`), Buffer.from(base64Data, 'base64'));
    }

    // Convert frames to high quality MP4 with ffmpeg
    const mp4Path = path.join(publicDir, `card-${theme}.mp4`);
    if (fs.existsSync(mp4Path)) fs.unlinkSync(mp4Path);

    console.log(`Encoding ${mp4Path} via ffmpeg...`);
    const ffmpegCmd = `ffmpeg -y -framerate 30 -i "${framesDir}\\frame_%04d.png" -c:v libx264 -profile:v high -level 4.0 -pix_fmt yuv420p -movflags +faststart -crf 20 "${mp4Path}"`;
    execSync(ffmpegCmd, { stdio: 'ignore' });
    console.log(`Saved: ${mp4Path} (${fs.statSync(mp4Path).size} bytes)`);
  }

  // Cleanup temp frames
  for (const f of fs.readdirSync(framesDir)) fs.unlinkSync(path.join(framesDir, f));
  fs.rmdirSync(framesDir);

  await browser.close();
  console.log('All card animation videos generated successfully!');
}

main().catch(err => {
  console.error('Generation failed:', err);
  process.exit(1);
});
