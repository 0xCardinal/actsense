"""Render og.html to static/og.png at 1200x630.

    python3 docs/scripts/og/render.py

Needs Playwright (`pip install playwright && playwright install chromium`)
and network access for Google Fonts.
"""
from pathlib import Path

from playwright.sync_api import sync_playwright

HERE = Path(__file__).resolve().parent
OUT = HERE.parent.parent / "static" / "og.png"


def main() -> None:
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1200, "height": 630})
        page.goto((HERE / "og.html").as_uri())
        page.wait_for_selector("body[data-ready='1']")
        page.screenshot(path=str(OUT))
        browser.close()
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
