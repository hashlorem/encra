"""Compose Encra's app icon: an inked whorl on a paper squircle (macOS grid:
1024 canvas, 824 shape, soft drop shadow).

The source print is thicker-ridged than the in-app ones so it survives being
shrunk to Dock and Finder sizes:
    python3 generate.py whorl 21 1100 19 whorl-icon.png
    python3 compose_icon.py whorl-icon.png app-icon.png
    npx tauri icon tools/fingerprint/app-icon.png
"""
import sys
from PIL import Image, ImageDraw, ImageFilter

src, out = sys.argv[1], sys.argv[2]
SIZE, SHAPE = 1024, 824
off = (SIZE - SHAPE) // 2
PAPER, INK = (242, 240, 234), (27, 27, 26)

def squircle_mask(size, n=5.0):
    # Superellipse |x|^n + |y|^n = 1, close to Apple's continuous corners.
    big = size * 4
    m = Image.new("L", (big, big), 0)
    px = m.load()
    r = big / 2
    for y in range(big):
        dy = abs((y + 0.5 - r) / r) ** n
        if dy > 1:
            continue
        half = (1 - dy) ** (1 / n) * r
        for x in range(int(r - half), int(r + half)):
            px[x, y] = 255
    return m.resize((size, size), Image.LANCZOS)

mask = squircle_mask(SHAPE)
canvas = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))

shadow = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
shadow.paste((0, 0, 0, 90), (off, off + 12), mask)
canvas = Image.alpha_composite(canvas, shadow.filter(ImageFilter.GaussianBlur(14)))

tile = Image.new("RGBA", (SHAPE, SHAPE), PAPER + (255,))
alpha = Image.open(src).getchannel("A")
h = int(SHAPE * 0.80)
w = int(alpha.width * h / alpha.height)
alpha = alpha.resize((w, h), Image.LANCZOS).rotate(-6, resample=Image.BICUBIC, expand=True)
ink = Image.new("RGBA", alpha.size, INK + (255,))
ink.putalpha(alpha)
tile.alpha_composite(ink, ((SHAPE - ink.width) // 2, (SHAPE - ink.height) // 2 + 6))
tile.putalpha(mask)
canvas.alpha_composite(tile, (off, off))
canvas.save(out)

# Preview at the sizes macOS actually shows.
prev = Image.new("RGBA", (1024 + 256 + 128 + 64 + 32 + 120, 1024), (200, 200, 200, 255))
x = 0
for s in (1024, 256, 128, 64, 32):
    prev.alpha_composite(canvas.resize((s, s), Image.LANCZOS), (x, 0))
    x += s + 30
prev.save(out.replace(".png", "-preview.png"))
