#include <stdint.h>
#include <stddef.h>

#include "aifuzz/fzdata.h"

static const uint8_t MAGIC[4] = {0x41, 0x47, 0x4E, 0x54};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FzData d;
  size_t totals[4] = {0, 0, 0, 0};
  size_t special = 0;
  const uint8_t *p;
  size_t got;
  uint8_t type;
  uint16_t len;

  d = fz_init(data, size);
  if (fz_remaining(&d) < 4) {
    return 0;
  }
  p = fz_bytes(&d, 4, &got);
  if (got < 4) {
    return 0;
  }
  for (got = 0; got < 4; got++) {
    if (p[got] != MAGIC[got]) {
      return 0;
    }
  }
  while (!fz_empty(&d)) {
    type = fz_u8(&d);
    len = fz_u16le(&d);
    p = fz_bytes(&d, len, &got);
    if (type == 0x99) {
      special += got;
      if (special > 1000) {
        volatile size_t sink = special;
        (void)sink;
      }
    } else if (type < 4) {
      totals[type] += got;
      if (totals[type] > 100000) {
        volatile size_t sink = totals[type];
        (void)sink;
      }
    }
  }
  return 0;
}
