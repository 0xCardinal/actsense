// Homepage hero backdrop: a grid of faint monospace letters with a slow wave
// of light passing through it. Letters stay dim around the brand so the text
// keeps its contrast. Pauses off-screen and draws a single still frame for
// visitors who prefer reduced motion.
document.addEventListener('DOMContentLoaded', function () {
  const canvas = document.querySelector('.as-hero-letters');
  if (!canvas) return;

  const ctx = canvas.getContext('2d');
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const CHARS = 'ACTSENSE';
  const STEP = 22;
  const FRAME_MS = 1000 / 30; // the wave is slow; 30fps is plenty

  let width = 0;
  let height = 0;
  let running = false;
  let visible = true;
  let last = 0;

  function resize() {
    const rect = canvas.getBoundingClientRect();
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    width = rect.width;
    height = rect.height;
    canvas.width = Math.round(width * dpr);
    canvas.height = Math.round(height * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    draw(performance.now());
  }

  function draw(t) {
    const dark = document.documentElement.classList.contains('dark');
    const ink = dark ? '245, 245, 244' : '17, 24, 39';
    const peak = dark ? 0.32 : 0.22;
    // The brand sits a little above the middle of the hero.
    const cx = width / 2;
    const cy = height * 0.42;

    ctx.clearRect(0, 0, width, height);
    ctx.font = '12px "Google Sans Code", ui-monospace, monospace';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';

    for (let y = STEP / 2, row = 0; y < height; y += STEP, row++) {
      for (let x = STEP / 2, col = 0; x < width; x += STEP, col++) {
        const wave = Math.sin(x / 140 - t / 1400) * Math.cos(y / 90 + t / 2100);
        const light = Math.max(0, wave) * peak + 0.03;
        // Quiet around the brand, full strength toward the sides.
        const away = Math.min(1, Math.hypot((x - cx) / (Math.min(width, 1100) * 0.42), (y - cy) / (height * 0.5)));
        const alpha = light * away;
        if (alpha < 0.012) continue;
        ctx.fillStyle = 'rgba(' + ink + ',' + alpha.toFixed(3) + ')';
        ctx.fillText(CHARS[(row + col) % CHARS.length], x, y);
      }
    }
  }

  function step(t) {
    if (!running) return;
    if (t - last >= FRAME_MS) {
      last = t;
      draw(t);
    }
    requestAnimationFrame(step);
  }

  function setRunning(on) {
    if (reduceMotion) return;
    if (on && !running) {
      running = true;
      requestAnimationFrame(step);
    } else if (!on) {
      running = false;
    }
  }

  // Draw once the monospace font is ready, so the first frame isn't in a
  // fallback face.
  (document.fonts ? document.fonts.ready : Promise.resolve()).then(function () {
    new ResizeObserver(resize).observe(canvas);

    new IntersectionObserver(function (entries) {
      visible = entries[0].isIntersecting;
      setRunning(visible && !document.hidden);
    }).observe(canvas);

    document.addEventListener('visibilitychange', function () {
      setRunning(visible && !document.hidden);
    });

    // Redraw in the new colours when the theme toggles.
    new MutationObserver(function () {
      draw(performance.now());
    }).observe(document.documentElement, { attributes: true, attributeFilter: ['class'] });
  });
});
