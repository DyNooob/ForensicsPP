#!/usr/bin/env python3
# Forensics++ (ForensicsPP.com)
# Local-first browser forensics workbench
#
# Copyright (c) 2026 DyNooob. All rights reserved.
# Author: DyNooob
# Website: https://www.loken.cn
# Platform: DigiForensics.cn
# Project: https://github.com/DyNooob/ForensicsPP
#
# Forensics++ is an open-source, browser-side toolkit for CTF/MISC,
# lightweight forensic triage, encoding/decoding, metadata inspection,
# hashes, archive parsing, and local analysis.
#
# Do not use this project for unauthorized access, intrusion,
# privacy infringement, or unlawful activity.
#
# Released under the MIT License.
# Full source code: https://github.com/DyNooob/ForensicsPP

from __future__ import annotations

from pathlib import Path
from PIL import Image, ImageDraw, ImageFont


SHOT_DIR = Path("layout-audit-screenshots")
OUT = SHOT_DIR / "contact-sheet.png"
SKIP = {OUT.name, "collapsed-home.png"}
THUMB_W = 320
THUMB_H = 180
LABEL_H = 24
GAP = 16
COLS = 4


def natural_key(path: Path) -> tuple[int, str]:
    preferred = [
        "home",
        "home-consent",
        "collapsed-home-current",
        "hash",
        "sqlite",
        "email",
        "image",
        "codec",
        "pcap",
        "timestamp",
    ]
    stem = path.stem
    return (preferred.index(stem) if stem in preferred else len(preferred), stem)


def fit_image(path: Path) -> Image.Image:
    image = Image.open(path).convert("RGB")
    image.thumbnail((THUMB_W, THUMB_H), Image.Resampling.LANCZOS)
    canvas = Image.new("RGB", (THUMB_W, THUMB_H), "#f7fafc")
    x = (THUMB_W - image.width) // 2
    y = (THUMB_H - image.height) // 2
    canvas.paste(image, (x, y))
    return canvas


def main() -> None:
    images = sorted(
        [path for path in SHOT_DIR.glob("*.png") if path.name not in SKIP],
        key=natural_key,
    )
    if not images:
        raise SystemExit("No screenshots found.")

    rows = (len(images) + COLS - 1) // COLS
    width = COLS * THUMB_W + (COLS + 1) * GAP
    height = rows * (THUMB_H + LABEL_H) + (rows + 1) * GAP
    sheet = Image.new("RGB", (width, height), "#eaf1f7")
    draw = ImageDraw.Draw(sheet)
    font = ImageFont.load_default()

    for index, path in enumerate(images):
        row, col = divmod(index, COLS)
        x = GAP + col * (THUMB_W + GAP)
        y = GAP + row * (THUMB_H + LABEL_H + GAP)
        draw.text((x, y), path.stem, fill="#172033", font=font)
        sheet.paste(fit_image(path), (x, y + LABEL_H))

    OUT.parent.mkdir(parents=True, exist_ok=True)
    sheet.save(OUT)
    print(f"Wrote {OUT} with {len(images)} screenshots.")


if __name__ == "__main__":
    main()
