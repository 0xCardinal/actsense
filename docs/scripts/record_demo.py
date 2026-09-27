"""Record the actsense demo loop shown on the docs home and Usage pages.

Drives the real frontend through one story (audit a repo, filter to critical,
open a finding, fix it in the editor) and writes a light and a dark video to
docs/assets/videos/.

Needs the app running: the frontend on :5173 (proxying to the backend on
:8000), plus ffmpeg on PATH. The audit and fix responses are captured once
from the backend and replayed, so the video doesn't depend on GitHub timing.

    uv run --with playwright python docs/scripts/record_demo.py
    uv run --with playwright python docs/scripts/record_demo.py --theme dark
"""

import argparse
import base64
import json
import shutil
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path

from playwright.sync_api import sync_playwright

APP = "http://localhost:5173/"
API = "http://localhost:8000"
REPO = "step-security/github-actions-goat"
OUT = Path(__file__).resolve().parents[1] / "assets" / "videos"
WIDTH, HEIGHT, FPS = 1600, 1000, 30

WORKFLOW = """name: PR build
on:
  pull_request_target:
    types: [opened, synchronize]

jobs:
  build:
    runs-on: ubuntu-latest
    permissions: write-all
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - name: Greet
        run: echo "Building ${{ github.event.pull_request.title }}"
      - run: npm install && npm test
"""

# A visible cursor and click ripple; headless Chromium draws neither.
CURSOR_JS = """
document.addEventListener('DOMContentLoaded', () => {
  const style = document.createElement('style');
  style.textContent = `
    #demo-cursor { position: fixed; left: 0; top: 0; z-index: 2147483647;
      pointer-events: none; transform: translate(-100px, -100px);
      filter: drop-shadow(0 1px 2px rgba(0,0,0,.35)); }
    .demo-ripple { position: fixed; z-index: 2147483646; pointer-events: none;
      width: 36px; height: 36px; margin: -18px 0 0 -18px; border-radius: 50%;
      border: 2px solid #3b82f6; background: rgba(59,130,246,.18);
      animation: demo-ripple .5s ease-out forwards; }
    @keyframes demo-ripple { from { transform: scale(.3); opacity: 1; }
      to { transform: scale(1.4); opacity: 0; } }
    #demo-end { position: fixed; inset: 0; z-index: 2147483645; display: grid;
      place-items: center; opacity: 0; transition: opacity .6s ease;
      background: var(--demo-end-bg); color: var(--demo-end-fg);
      font-family: 'Google Sans', -apple-system, sans-serif; text-align: center; }
    #demo-end.on { opacity: 1; }
    #demo-end h1 { margin: 0 0 12px; font-size: 64px; font-weight: 700; letter-spacing: -.03em; }
    #demo-end p { margin: 0 0 32px; font-size: 22px; opacity: .7; }
    #demo-end code { display: inline-block; padding: 16px 24px; border-radius: 12px;
      font: 20px 'Google Sans Code', ui-monospace, Menlo, monospace;
      background: var(--demo-end-code); border: 1px solid var(--demo-end-line); }
  `;
  document.head.appendChild(style);
  const cursor = document.createElement('div');
  cursor.id = 'demo-cursor';
  cursor.innerHTML = '<svg width="22" height="26" viewBox="0 0 22 26"><path d="M2 2 L2 21 L7.5 16 L11 24 L14.5 22.5 L11 14.8 L18.5 14.8 Z" fill="#111" stroke="#fff" stroke-width="1.6" stroke-linejoin="round"/></svg>';
  document.body.appendChild(cursor);
  addEventListener('mousemove', e => {
    cursor.style.transform = `translate(${e.clientX - 2}px, ${e.clientY - 2}px)`;
  }, true);
  addEventListener('mousedown', e => {
    const r = document.createElement('div');
    r.className = 'demo-ripple';
    r.style.left = e.clientX + 'px';
    r.style.top = e.clientY + 'px';
    document.body.appendChild(r);
    setTimeout(() => r.remove(), 600);
  }, true);
});
"""

# Replays recorded responses at demo pace: the audit stream's events are
# spread over a couple of seconds so the live log scrolls, and the editor's
# fix request waits a beat so its loading state shows.
PACING_JS = """
const realFetch = window.fetch;
const sleep = ms => new Promise(r => setTimeout(r, ms));
window.fetch = async (input, init) => {
  const path = new URL(typeof input === 'string' ? input : input.url, location.href).pathname;
  if (path === '/api/audit/fix') await sleep(1000);
  const response = await realFetch(input, init);
  if (path !== '/api/audit/stream') return response;
  const events = (await response.text()).split('\\n\\n').filter(Boolean);
  const gap = Math.min(80, 1800 / Math.max(events.length, 1));
  const encoder = new TextEncoder();
  const body = new ReadableStream({
    async start(controller) {
      for (const event of events) {
        controller.enqueue(encoder.encode(event + '\\n\\n'));
        await sleep(event.startsWith('event: result') ? 0 : gap);
      }
      controller.close();
    },
  });
  return new Response(body, { status: 200, headers: response.headers });
};
"""

END_CARD = """
(theme) => {
  const dark = theme === 'dark';
  document.getElementById('demo-cursor')?.remove();
  const el = document.createElement('div');
  el.id = 'demo-end';
  el.style.setProperty('--demo-end-bg', dark ? '#0b0c0f' : '#f7f7f8');
  el.style.setProperty('--demo-end-fg', dark ? '#f3f4f6' : '#111827');
  el.style.setProperty('--demo-end-code', dark ? '#16181d' : '#ffffff');
  el.style.setProperty('--demo-end-line', dark ? '#2a2e37' : '#e5e7eb');
  el.innerHTML = '<div><h1>actsense</h1><p>Audit your own workflows in one command</p>'
    + '<code>docker run --rm -p 8000:8000 ghcr.io/0xcardinal/actsense:latest</code></div>';
  document.body.appendChild(el);
  requestAnimationFrame(() => requestAnimationFrame(() => el.classList.add('on')));
}
"""


def api(path, body=None):
    req = urllib.request.Request(
        API + path,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=300) as resp:
        return json.load(resp)


def recorded_audit_stream():
    """One real audit of REPO, as the event stream the frontend reads."""
    req = urllib.request.Request(
        API + "/api/audit/stream",
        data=json.dumps({"repository": REPO, "use_clone": True}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=600) as resp:
        body = resp.read().decode()
    if "event: result" not in body:
        raise SystemExit(f"Audit of {REPO} produced no result:\n{body[-2000:]}")
    return body


class Screencast:
    """Collects Chromium screencast frames with their capture times."""

    def __init__(self, page, frames_dir):
        self.dir = frames_dir
        self.frames = []
        self.cdp = page.context.new_cdp_session(page)
        self.cdp.on("Page.screencastFrame", self._on_frame)

    def _on_frame(self, event):
        path = self.dir / f"{len(self.frames):05d}.jpg"
        path.write_bytes(base64.b64decode(event["data"]))
        self.frames.append((path, event["metadata"]["timestamp"]))
        self.cdp.send("Page.screencastFrameAck", {"sessionId": event["sessionId"]})

    def start(self):
        self.cdp.send("Page.startScreencast", {
            "format": "jpeg", "quality": 92, "maxWidth": WIDTH, "maxHeight": HEIGHT, "everyNthFrame": 1,
        })

    def stop(self):
        self.cdp.send("Page.stopScreencast")
        return self.frames


def write_video(frames, tail, dest_stem, poster_at):
    """Turn timestamped frames into constant-rate MP4 and WebM files plus a poster.

    Chromium only sends a frame when the page changes, so each frame is held
    until the next one arrives, and the last for `tail` seconds.
    """
    listing = dest_stem.with_suffix(".txt")
    lines = []
    for (path, ts), nxt in zip(frames, frames[1:] + [(None, None)]):
        duration = (nxt[1] - ts) if nxt[1] is not None else tail
        lines.append(f"file '{path}'\nduration {max(duration, 0.001):.4f}")
    lines.append(f"file '{frames[-1][0]}'")
    listing.write_text("\n".join(lines) + "\n")

    # Screencast JPEGs are full-range; browsers' hardware decoders expect the
    # usual limited-range BT.709, and some fail on anything else.
    video_filter = (f"fps={FPS},scale={WIDTH}:{HEIGHT}:flags=lanczos:in_range=pc:out_range=tv"
                    ":out_color_matrix=bt709,format=yuv420p")
    colour = ["-color_range", "tv", "-colorspace", "bt709", "-color_primaries", "bt709", "-color_trc", "bt709"]
    common = ["ffmpeg", "-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i", str(listing),
              "-vf", video_filter, *colour, "-an"]
    subprocess.run(common + ["-c:v", "libx264", "-preset", "slow", "-crf", "26",
                             "-movflags", "+faststart", str(dest_stem.with_suffix(".mp4"))], check=True)
    subprocess.run(common + ["-c:v", "libvpx-vp9", "-b:v", "0", "-crf", "40", "-row-mt", "1",
                             str(dest_stem.with_suffix(".webm"))], check=True)

    start = frames[0][1]
    poster = min(frames, key=lambda f: abs((f[1] - start) - poster_at))[0]
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-i", str(poster), "-c:v", "libwebp",
                    "-quality", "82", str(dest_stem.with_suffix(".webp"))], check=True)
    listing.unlink()


def glide(page, target, steps=28):
    """Move the cursor smoothly to the centre of a locator and return that point."""
    target.scroll_into_view_if_needed()
    box = target.bounding_box()
    x, y = box["x"] + box["width"] / 2, box["y"] + box["height"] / 2
    page.mouse.move(x, y, steps=steps)
    return x, y


def click(page, target, pause=0.25):
    glide(page, target)
    page.wait_for_timeout(int(pause * 1000))
    page.mouse.down()
    page.mouse.up()


def record(theme, audit_stream, fix):
    with tempfile.TemporaryDirectory() as tmp, sync_playwright() as p:
        browser = p.chromium.launch()
        ctx = browser.new_context(viewport={"width": WIDTH, "height": HEIGHT}, color_scheme=theme)
        ctx.add_init_script(f"localStorage.setItem('actsense-theme', '{theme}')")
        ctx.add_init_script(CURSOR_JS)

        # Pace the replay in the page: sleeping in a route handler would
        # also stall frame capture.
        ctx.add_init_script(PACING_JS)

        page = ctx.new_page()
        page.route(lambda url: url.endswith("/api/audit/stream"), lambda route: route.fulfill(
            status=200, content_type="text/event-stream", body=audit_stream))
        page.route(lambda url: url.endswith("/api/audit/fix"), lambda route: route.fulfill(
            status=200, content_type="application/json", body=json.dumps(fix)))
        page.goto(APP)
        page.wait_for_timeout(1500)
        page.mouse.move(WIDTH / 2, HEIGHT - 120)

        cast = Screencast(page, Path(tmp))
        cast.start()
        t0 = time.monotonic()
        wait = page.wait_for_timeout

        # 1. Audit a repository.
        wait(700)
        field = page.get_by_placeholder("owner/repo or https://github.com/owner/repo")
        click(page, field)
        page.keyboard.type(REPO, delay=40)
        wait(300)
        click(page, page.get_by_role("button", name="Audit", exact=True))
        page.wait_for_selector(".react-flow__node")
        wait(2200)

        # 2. Filter to critical findings and trace a node's lineage.
        click(page, page.locator(".severity-item", has_text="Critical"))
        wait(900)
        click(page, page.locator(".react-flow__controls-fitview"))
        wait(1300)
        glide(page, page.locator(".react-flow__node", has_text="toc-tou").first)
        wait(1400)

        # 3. Open the node, then its critical finding.
        click(page, page.locator(".react-flow__node", has_text="toc-tou").first, pause=0.1)
        page.wait_for_selector(".issue-item")
        wait(1300)
        click(page, page.locator(".issue-item", has_text="insecure_pull_request_target").first)
        page.wait_for_selector(".issue-modal")
        wait(3200)
        click(page, page.locator(".issue-modal-close"))
        wait(400)
        click(page, page.locator(".node-details-panel .close-button, .close-button").first)
        wait(700)

        # 4. Fix a workflow in the editor.
        click(page, page.get_by_text("Create a secure workflow"))
        page.wait_for_selector(".yaml-editor-textarea")
        wait(600)
        click(page, page.locator(".yaml-editor-textarea"))
        page.locator(".yaml-editor-textarea").fill(WORKFLOW)
        wait(1300)
        click(page, page.locator(".yaml-editor-secure-button"))
        page.wait_for_selector(".yaml-fix-card")
        wait(2300)
        click(page, page.locator(".yaml-fix-apply-all"))
        wait(2800)

        # 5. End card.
        page.evaluate(END_CARD, theme)
        wait(3200)

        frames = cast.stop()
        print(f"{theme}: {len(frames)} frames over {time.monotonic() - t0:.1f}s")
        browser.close()

        OUT.mkdir(parents=True, exist_ok=True)
        suffix = "" if theme == "light" else "-dark"
        write_video(frames, 0.3, OUT / f"demo{suffix}", poster_at=6.5)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--theme", choices=["light", "dark", "both"], default="both")
    args = parser.parse_args()
    if not shutil.which("ffmpeg"):
        raise SystemExit("ffmpeg is required")

    audit_stream = recorded_audit_stream()
    fix = api("/api/audit/fix", {"yaml_content": WORKFLOW})
    for theme in (["light", "dark"] if args.theme == "both" else [args.theme]):
        record(theme, audit_stream, fix)
    for f in sorted(OUT.glob("demo*")):
        print(f"{f.relative_to(OUT.parents[2])}  {f.stat().st_size / 1e6:.1f} MB")


if __name__ == "__main__":
    main()
