#!/usr/bin/env python3
import os
import struct
import sys
import zlib

out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "seeds")
os.makedirs(out, exist_ok=True)


def chunk(tag, data):
    c = struct.pack(">I", len(data)) + tag + data
    return c + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)


def make_png(w, h, color_type):
    nch = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[color_type]
    ihdr = struct.pack(">IIBBBBB", w, h, 8, color_type, 0, 0, 0)
    out_png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
    if color_type == 3:
        out_png += chunk(b"PLTE", bytes(range(3 * 8)))
        row = bytes(x % 8 for x in range(w))
    elif color_type == 0:
        row = bytes((x * 13) % 256 for x in range(w))
    elif color_type == 4:
        row = bytes((x * 13) % 256 for x in range(w * 2))
    else:
        row = bytes((x * 7) % 256 for x in range(w * nch))
    raw = b"".join(b"\x00" + row for _ in range(h))
    out_png += chunk(b"IDAT", zlib.compress(raw))
    out_png += chunk(b"IEND", b"")
    return out_png


seeds = {
    "seed_1x1_rgba.png": make_png(1, 1, 6),
    "seed_4x4_rgb.png": make_png(4, 4, 2),
    "seed_8x8_gray.png": make_png(8, 8, 0),
    "seed_16x16_pal.png": make_png(16, 16, 3),
    "seed_5x3_gray_alpha.png": make_png(5, 3, 4),
    "seed_32x32_rgba.png": make_png(32, 32, 6),
}

for name, data in seeds.items():
    with open(os.path.join(out, name), "wb") as f:
        f.write(data)

print("wrote %d seeds to %s" % (len(seeds), out))
