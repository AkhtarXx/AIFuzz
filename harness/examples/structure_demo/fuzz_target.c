#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "aifuzz/fzdata.h"

#define MAX_RECORDS 512

static const uint8_t FORMAT_TAG[2] = {0xC1, 0x0D};

static size_t custom_mutator(uint8_t *data, size_t size, size_t max_size, unsigned int seed) {
  size_t i;
  uint8_t choice;

  if (size < 4) {
    if (max_size < 8) {
      return size;
    }
    data[0] = FORMAT_TAG[0];
    data[1] = FORMAT_TAG[1];
    data[2] = 0x01;
    data[3] = 0x00;
    return 4;
  }
  choice = (uint8_t)(seed % 3u);
  if (choice == 0 && 2 * size <= max_size) {
    memcpy(data + size, data, size);
    return 2 * size;
  }
  if (choice == 1 && size > 2) {
    i = 2 + (seed % (size - 2));
    data[i] ^= 0x20;
    return size;
  }
  i = 2 + (seed % (size - 2));
  data[i] = (uint8_t)(seed & 0xff);
  return size;
}

size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t max_size, unsigned int seed) {
  return custom_mutator(data, size, max_size, seed);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FzData d;
  size_t counts[4] = {0, 0, 0, 0};
  size_t records = 0;
  const uint8_t *p;
  size_t got;
  uint8_t type;
  uint8_t len;

  d = fz_init(data, size);
  p = fz_bytes(&d, 2, &got);
  if (got < 2 || memcmp(p, FORMAT_TAG, 2) != 0) {
    return 0;
  }
  while (!fz_empty(&d) && records < MAX_RECORDS) {
    type = fz_u8(&d);
    len = fz_u8(&d);
    p = fz_bytes(&d, len, &got);
    if (got < 1) {
      break;
    }
    if (type < 4) {
      counts[type] += got;
    }
    if (type == 3 && got >= 2 && p[0] == 0xDE && p[1] == 0xAD) {
      volatile size_t sink = counts[0];
      (void)sink;
    }
    records++;
  }
  return 0;
}
