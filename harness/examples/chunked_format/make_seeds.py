#!/usr/bin/env python3
import os
import struct
import sys

out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "seeds")
os.makedirs(out, exist_ok=True)

magic = b"AIFZ"
hdr = magic + b"\x01"


def chunk(t, payload):
    return bytes([t]) + struct.pack("<H", len(payload)) + payload


seeds = {
    "seed_magic.bin": hdr,
    "seed_meta.bin": hdr + chunk(0x01, b"\xef\xbe\xad\xde"),
    "seed_text.bin": hdr + chunk(0x02, b"HI!BUG"),
    "seed_two.bin": hdr + chunk(0x01, b"\x01\x02\x03\x04") + chunk(0x02, b"HIx!"),
    "seed_special_small.bin": hdr + chunk(0x42, b"\x01" + b"B" * 7),
}

for name, data in seeds.items():
    with open(os.path.join(out, name), "wb") as f:
        f.write(data)

print("wrote %d seeds to %s" % (len(seeds), out))
