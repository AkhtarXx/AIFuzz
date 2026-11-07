#!/usr/bin/env python3
import os
import sys

out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "seeds")
os.makedirs(out, exist_ok=True)

seeds = {
    "seed_basic.bin": bytes([0xC1, 0x0D, 0x01, 0x02, 0xAB, 0xCD]),
    "seed_dead.bin": bytes([0xC1, 0x0D, 0x03, 0x02, 0xDE, 0xAD]),
    "seed_multi.bin": bytes([0xC1, 0x0D, 0x00, 0x01, 0xFF, 0x02, 0x03, 0x41, 0x42, 0x43]),
}

for name, data in seeds.items():
    with open(os.path.join(out, name), "wb") as f:
        f.write(data)

print("wrote %d seeds to %s" % (len(seeds), out))
