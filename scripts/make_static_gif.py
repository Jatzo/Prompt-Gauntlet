"""Renders scripts/static_gif.html to docs/figures/static-test.gif, one frame at a time.

The page draws a given moment with `draw(t)`, so every frame is exact and no browser timing or
reduced-motion setting can change the result. Frames go through ffmpeg's two-pass palette, which
keeps the dark ground free of dithering bands.

Needs Python with Playwright (and its Chromium) and ffmpeg on PATH. Usage, from the repo root:
    python scripts/make_static_gif.py
    python scripts/make_static_gif.py scripts/discovery_gif.html docs/figures/discovery.gif
"""

import base64
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
PAGE = ROOT / "scripts" / "static_gif.html"
FONTS = ROOT / "arena" / "static" / "fonts"
OUT = ROOT / "docs" / "figures" / "static-test.gif"
FPS = 15
SECONDS = 12.0
FACES = (
    ("Plex Sans", 400, "IBMPlexSans-Regular-Latin1.woff2"),
    ("Plex Sans", 600, "IBMPlexSans-SemiBold-Latin1.woff2"),
    ("Plex Sans", 700, "IBMPlexSans-Bold-Latin1.woff2"),
    ("Plex Mono", 400, "IBMPlexMono-Regular-Latin1.woff2"),
    ("Plex Mono", 600, "IBMPlexMono-SemiBold-Latin1.woff2"),
)


def font_faces() -> str:
    rules = []
    for family, weight, name in FACES:
        data = base64.b64encode((FONTS / name).read_bytes()).decode()
        rules.append(
            f'@font-face {{ font-family: "{family}"; font-weight: {weight}; '
            f'src: url(data:font/woff2;base64,{data}) format("woff2"); }}'
        )
    return "\n".join(rules)


def main(page: Path = PAGE, out: Path = OUT) -> int:
    if shutil.which("ffmpeg") is None:
        print("ffmpeg is not on PATH. Install it, then run this again.", file=sys.stderr)
        return 1
    html = page.read_text(encoding="utf-8").replace("FONT_FACES", font_faces())
    with tempfile.TemporaryDirectory() as scratch:
        frames = Path(scratch)
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page(viewport={"width": 1200, "height": 675})
            page.set_content(html)
            page.evaluate("document.fonts.ready")
            for index in range(round(FPS * SECONDS)):
                page.evaluate(f"draw({index / FPS})")
                page.screenshot(path=str(frames / f"{index:04d}.png"))
            browser.close()
        palette = frames / "palette.png"
        pattern = str(frames / "%04d.png")
        subprocess.run(
            [
                "ffmpeg",
                "-v",
                "error",
                "-y",
                "-framerate",
                str(FPS),
                "-i",
                pattern,
                "-vf",
                "palettegen=stats_mode=diff",
                str(palette),
            ],
            check=True,
        )
        subprocess.run(
            [
                "ffmpeg",
                "-v",
                "error",
                "-y",
                "-framerate",
                str(FPS),
                "-i",
                pattern,
                "-i",
                str(palette),
                "-lavfi",
                "paletteuse=dither=none:diff_mode=rectangle",
                "-loop",
                "0",
                str(out),
            ],
            check=True,
        )
    print(f"{out.relative_to(ROOT)}: {out.stat().st_size / 1_000_000:.2f} MB")
    return 0


if __name__ == "__main__":
    # With no arguments, part 1's GIF; with PAGE and OUT (repo-relative), any other page.
    if len(sys.argv) == 3:
        sys.exit(main(ROOT / sys.argv[1], ROOT / sys.argv[2]))
    sys.exit(main())
