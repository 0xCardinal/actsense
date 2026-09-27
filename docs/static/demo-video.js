// Demo loop (docs/scripts/record_demo.py): a light and a dark video that
// follow the docs theme. Only the visible one loads and plays, and only while
// on screen. With reduced motion it waits behind its poster, with controls.
document.addEventListener('DOMContentLoaded', function() {
  const videos = Array.from(document.querySelectorAll('video[data-demo]'));
  if (videos.length === 0) return;

  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
  const onScreen = new Set();

  const shouldPlay = function(video) {
    return !reducedMotion.matches && onScreen.has(video) && getComputedStyle(video).display !== 'none';
  };

  const sync = function() {
    videos.forEach(function(video) {
      video.controls = reducedMotion.matches;
      if (shouldPlay(video)) {
        video.preload = 'auto';
        if (video.paused) video.play().catch(function() {});
      } else if (!video.paused) {
        video.pause();
      }
    });
  };

  videos.forEach(function(video) {
    // The browser can pause a muted loop on its own (for example while it
    // first buffers); resume it a few times if it should still be playing.
    let resumes = 0;
    video.addEventListener('pause', function() {
      if (resumes >= 3) return;
      setTimeout(function() {
        if (video.paused && shouldPlay(video)) {
          resumes += 1;
          video.play().catch(function() {});
        }
      }, 250);
    });
  });

  const observer = new IntersectionObserver(function(entries) {
    entries.forEach(function(entry) {
      if (entry.isIntersecting) onScreen.add(entry.target);
      else onScreen.delete(entry.target);
    });
    sync();
  }, { threshold: 0.25 });
  videos.forEach(function(video) { observer.observe(video); });

  // Hextra switches themes by toggling the `dark` class on <html>.
  new MutationObserver(sync).observe(document.documentElement, { attributes: true, attributeFilter: ['class'] });
  reducedMotion.addEventListener('change', sync);
});
