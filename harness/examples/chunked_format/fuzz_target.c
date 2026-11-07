#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "aifuzz/fzdata.h"

#define CHUNK_PAYLOAD_MAX 4096

typedef struct {
  uint8_t type;
  uint16_t len;
  uint8_t payload[CHUNK_PAYLOAD_MAX];
} chunk_t;

static const uint8_t MAGIC[4] = {0x41, 0x49, 0x46, 0x5A};

static int parse_header(FzData *d) {
  if (fz_remaining(d) < 5) {
    return -1;
  }
  if (memcmp(d->buf + d->pos, MAGIC, 4) != 0) {
    return -1;
  }
  d->pos += 4;
  if (fz_u8(d) != 1) {
    return -1;
  }
  return 0;
}

static void process_meta(chunk_t *c) {
  uint32_t id;
  if (c->len < 4) {
    return;
  }
  id = (uint32_t)c->payload[0];
  id |= (uint32_t)c->payload[1] << 8;
  id |= (uint32_t)c->payload[2] << 16;
  id |= (uint32_t)c->payload[3] << 24;
  if (id == 0xDEADBEEFu) {
    volatile uint32_t sink = id;
    (void)sink;
  }
}

static void process_text(chunk_t *c) {
  char out[8];
  size_t i;
  if (c->len < 3) {
    return;
  }
  if (c->payload[0] == 'H' && c->payload[1] == 'I') {
    for (i = 0; i < 4; i++) {
      out[i] = (char)c->payload[i + 2];
    }
    if (out[0] == 'B' && out[1] == 'U' && out[2] == 'G') {
      volatile char sink = out[3];
      (void)sink;
    }
  }
}

static void process_special(chunk_t *c) {
  char tag[16];
  size_t n;
  if (c->len == 0) {
    return;
  }
  if (c->payload[0] & 1) {
    memcpy(tag, c->payload + 1, (size_t)c->len - 1);
  } else {
    n = (size_t)c->len - 1;
    if (n > sizeof(tag)) {
      n = sizeof(tag);
    }
    memcpy(tag, c->payload + 1, n);
  }
  if (tag[0] == 0x7F) {
    volatile char sink = tag[0];
    (void)sink;
  }
}

static void process_chunk(chunk_t *c) {
  switch (c->type) {
    case 0x01:
      process_meta(c);
      break;
    case 0x02:
      process_text(c);
      break;
    case 0x42:
      process_special(c);
      break;
    default:
      break;
  }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FzData d;
  chunk_t c;
  const uint8_t *p;
  size_t got;

  d = fz_init(data, size);
  if (parse_header(&d) != 0) {
    return 0;
  }
  while (!fz_empty(&d)) {
    memset(&c, 0, sizeof(c));
    c.type = fz_u8(&d);
    c.len = fz_u16le(&d);
    p = fz_bytes(&d, c.len, &got);
    if (got > sizeof(c.payload)) {
      got = sizeof(c.payload);
    }
    if (got > 0) {
      memcpy(c.payload, p, got);
    }
    c.len = (uint16_t)got;
    process_chunk(&c);
  }
  return 0;
}
