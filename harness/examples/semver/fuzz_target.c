#include <stdint.h>
#include <stddef.h>

#include "aifuzz/fzdata.h"

typedef struct {
  long maj;
  long min;
  long pat;
} ver_t;

static int parse_ver(const char *s, size_t n, ver_t *v) {
  long parts[3] = {0, 0, 0};
  int idx = 0;
  size_t i;

  for (i = 0; i < n; i++) {
    if (s[i] == '.') {
      idx++;
      if (idx > 2) {
        return -1;
      }
    } else if (s[i] >= '0' && s[i] <= '9') {
      parts[idx] = parts[idx] * 10 + (s[i] - '0');
      if (parts[idx] > 1000000) {
        return -1;
      }
    } else {
      return -1;
    }
  }
  if (idx < 2) {
    return -1;
  }
  v->maj = parts[0];
  v->min = parts[1];
  v->pat = parts[2];
  return 0;
}

static int cmp_ver(const ver_t *a, const ver_t *b) {
  if (a->maj != b->maj) {
    return a->maj < b->maj ? -1 : 1;
  }
  if (a->min != b->min) {
    return a->min < b->min ? -1 : 1;
  }
  if (a->pat != b->pat) {
    return a->pat < b->pat ? -1 : 1;
  }
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  ver_t a;
  ver_t b;
  size_t mid = size / 2;
  int c;

  if (size == 0) {
    return 0;
  }
  if (parse_ver((const char *)data, mid, &a) != 0) {
    return 0;
  }
  if (parse_ver((const char *)(data + mid), size - mid, &b) != 0) {
    return 0;
  }
  c = cmp_ver(&a, &b);
  if (c < 0) {
    volatile int sink = -1;
    (void)sink;
  } else if (c > 0) {
    volatile int sink = 1;
    (void)sink;
  } else {
    volatile int sink = 0;
    (void)sink;
  }
  return 0;
}
