"""Generate Encra's synthetic fingerprint images.

Every print in the app comes from this script, so none of them is a real
person's finger. It follows the usual recipe for synthetic test prints:

1. An orientation field from the Sherlock-Monro zero-pole model, with cores
   and deltas placed for the pattern type (whorl, loop, arch).
2. Ridges grown from noise by repeatedly filtering with a bank of Gabor
   filters, each pixel taking the filter that matches its orientation.
3. An inked-finger mask: ragged edges, lighter pressure toward the rim,
   blotches, pores and paper grain.

Output is an alpha-only mask (the app draws it with CSS `mask-image` over
the ink colour, so one file covers light and dark themes).

Dev-only dependencies, not part of the app build:
    python3 -m venv .venv && .venv/bin/pip install numpy scipy pillow

Usage:
    python3 generate.py KIND SEED SIZE PERIOD OUT.png [--preview PREVIEW.png]

The prints in src/assets/prints/ were made with:
    whorl 21 900 11   -> print-whorl.png
    loop_l 5 640 9    -> print-loop.png (then resized to 192px tall for the Seal control)
    arch 11 640 9     -> print-arch.png
"""
import argparse

import numpy as np
from PIL import Image
from scipy.ndimage import gaussian_filter
from scipy.signal import fftconvolve

BINS = 24

# Singular points as fractions of the canvas, y pointing up.
PATTERNS = {
    "loop_r": ([-0.02 + 0.06j], [0.20 - 0.20j]),
    "loop_l": ([0.03 + 0.07j], [-0.21 - 0.19j]),
    "whorl": ([-0.02 + 0.09j, 0.03 + 0.01j], [-0.26 - 0.22j, 0.27 - 0.20j]),
    "arch": ([0.0 + 0.02j], [0.0 - 0.06j]),
}


def orientation(kind, size, rng):
    y, x = np.mgrid[0:size, 0:size].astype(float)
    z = (x - size / 2) - 1j * (y - size / 2)
    cores, deltas = PATTERNS[kind]
    theta = np.zeros((size, size))
    for core in cores:
        theta += np.angle(z - core * size)
    for delta in deltas:
        theta -= np.angle(z - delta * size)
    # Halve, and flip back to image coordinates where y points down.
    theta = -theta / 2.0
    # A slow wobble so the ridges are not mathematically clean.
    wobble = gaussian_filter(rng.standard_normal((size, size)), 40)
    theta += wobble / (np.abs(wobble).max() + 1e-9) * 0.12
    return np.mod(theta, np.pi)


def gabor_bank(period):
    r = 12
    yy, xx = np.mgrid[-r:r + 1, -r:r + 1].astype(float)
    bank = []
    for k in range(BINS):
        t = k * np.pi / BINS
        across = -xx * np.sin(t) + yy * np.cos(t)
        along = xx * np.cos(t) + yy * np.sin(t)
        g = np.exp(-0.5 * (across ** 2 / 3.6 ** 2 + along ** 2 / 4.8 ** 2))
        g *= np.cos(2 * np.pi * across / period)
        g -= g.mean()
        bank.append(g / np.abs(g).sum())
    return bank


def grow_ridges(theta, period, rng, iterations=22):
    bank = gabor_bank(period)
    bins = np.round(theta / np.pi * BINS).astype(int) % BINS
    image = rng.standard_normal(theta.shape)
    for _ in range(iterations):
        out = np.zeros_like(image)
        for k, kernel in enumerate(bank):
            mask = bins == k
            if mask.any():
                out[mask] = fftconvolve(image, kernel, mode="same")[mask]
        out /= out.std() + 1e-9
        image = np.tanh(2.2 * out)
    return image


def ink(ridges, rng):
    size = ridges.shape[0]
    y, x = np.mgrid[0:size, 0:size].astype(float)
    cx, cy = size / 2, size / 2 + 0.03 * size
    # Fingertip shape: rounder on top, flatter toward the crease.
    ry = np.where(y < cy, 0.40 * size, 0.44 * size)
    d = np.sqrt(((x - cx) / (0.33 * size)) ** 2 + ((y - cy) / ry) ** 2)
    edge = gaussian_filter(rng.standard_normal((size, size)), 14)
    d = np.clip(d + edge / np.abs(edge).max() * 0.06, 0, None)

    pressure = np.clip(1.15 - d ** 2.2, 0, 1)
    blotch = gaussian_filter(rng.standard_normal((size, size)), 6)
    blotch /= np.abs(blotch).max()
    level = 0.36 + 0.45 * (1 - pressure) + blotch * 0.22

    alpha = np.clip(((ridges + 1) / 2 - level) * 3.2, 0, 1)
    alpha *= np.clip((1.0 - d) * 24, 0, 1)
    pores = gaussian_filter((rng.random((size, size)) < 0.0028).astype(float), 0.9) > 0.08
    alpha[pores] *= 0.15
    alpha = gaussian_filter(alpha, 0.6)
    alpha *= 0.86 + 0.14 * rng.random((size, size))
    return np.clip(alpha, 0, 1)


def crop(alpha, pad=8):
    ys, xs = np.nonzero(alpha > 0.02)
    return alpha[max(ys.min() - pad, 0):ys.max() + pad, max(xs.min() - pad, 0):xs.max() + pad]


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("kind", choices=sorted(PATTERNS))
    parser.add_argument("seed", type=int)
    parser.add_argument("size", type=int)
    parser.add_argument("period", type=float, help="ridge spacing in pixels")
    parser.add_argument("out")
    parser.add_argument("--preview", help="also write ink-on-paper preview PNG")
    args = parser.parse_args()

    rng = np.random.default_rng(args.seed)
    theta = orientation(args.kind, args.size, rng)
    alpha = crop(ink(grow_ridges(theta, args.period, rng), rng))

    # 16 alpha levels are invisible at display size and compress far better.
    levels = np.round(alpha * 15) / 15
    a = (levels * 255).astype(np.uint8)
    Image.fromarray(np.dstack([np.zeros_like(a), a]), "LA").save(args.out, optimize=True)

    if args.preview:
        paper = np.array([242, 240, 234], float)
        inked = paper * (1 - levels[..., None]) + np.array([27, 27, 26], float) * levels[..., None]
        Image.fromarray(inked.astype(np.uint8)).save(args.preview)


if __name__ == "__main__":
    main()
