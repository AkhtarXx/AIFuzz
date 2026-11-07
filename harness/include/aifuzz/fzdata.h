#ifndef AIFUZZ_FZDATA_H
#define AIFUZZ_FZDATA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef struct {
  const uint8_t *buf;
  size_t len;
  size_t pos;
} FzData;

static inline FzData fz_init(const uint8_t *buf, size_t len) {
  FzData d;
  d.buf = buf;
  d.len = len;
  d.pos = 0;
  return d;
}

static inline size_t fz_remaining(const FzData *d) {
  return d->len - d->pos;
}

static inline bool fz_empty(const FzData *d) {
  return fz_remaining(d) == 0;
}

static inline const uint8_t *fz_rest(FzData *d, size_t *out_len) {
  size_t n = fz_remaining(d);
  const uint8_t *p = d->buf + d->pos;
  d->pos += n;
  *out_len = n;
  return p;
}

static inline const uint8_t *fz_bytes(FzData *d, size_t max_len, size_t *out_len) {
  size_t avail = fz_remaining(d);
  size_t n = max_len < avail ? max_len : avail;
  const uint8_t *p = d->buf + d->pos;
  d->pos += n;
  *out_len = n;
  return p;
}

static inline uint8_t fz_u8(FzData *d) {
  if (fz_empty(d)) {
    return 0;
  }
  return d->buf[d->pos++];
}

static inline uint16_t fz_u16le(FzData *d) {
  uint16_t v = 0;
  v |= (uint16_t)fz_u8(d);
  v |= (uint16_t)fz_u8(d) << 8;
  return v;
}

static inline uint32_t fz_u32le(FzData *d) {
  uint32_t v = 0;
  v |= (uint32_t)fz_u8(d);
  v |= (uint32_t)fz_u8(d) << 8;
  v |= (uint32_t)fz_u8(d) << 16;
  v |= (uint32_t)fz_u8(d) << 24;
  return v;
}

static inline uint64_t fz_u64le(FzData *d) {
  uint64_t v = 0;
  int i;
  for (i = 0; i < 8; i++) {
    v |= (uint64_t)fz_u8(d) << (8 * i);
  }
  return v;
}

static inline bool fz_bool(FzData *d) {
  return (fz_u8(d) & 1) != 0;
}

static inline int64_t fz_i64(FzData *d) {
  return (int64_t)fz_u64le(d);
}

static inline double fz_f64(FzData *d) {
  uint64_t bits = fz_u64le(d);
  double out;
  memcpy(&out, &bits, sizeof(out));
  return out;
}

static inline size_t fz_range(FzData *d, size_t hi) {
  uint64_t v = 0;
  size_t t;
  int nb = 1;
  int i;
  if (hi == 0) {
    return 0;
  }
  if (hi == (size_t)-1) {
    hi -= 1;
  }
  t = hi;
  while (t >= 256) {
    t >>= 8;
    nb++;
  }
  if (nb > 8) {
    nb = 8;
  }
  for (i = 0; i < nb; i++) {
    v |= (uint64_t)fz_u8(d) << (8 * i);
  }
  return (size_t)(v % ((uint64_t)hi + 1));
}

#endif
