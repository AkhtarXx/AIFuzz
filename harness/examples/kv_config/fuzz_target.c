#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "aifuzz/fzdata.h"

#define KEY_MAX 32
#define VALUE_MAX 128

static int split_line(const char *line, size_t n, char *key, char *value) {
  size_t i;
  size_t klen = 0;
  size_t vlen = 0;
  int seen_eq = 0;

  for (i = 0; i < n; i++) {
    if (line[i] == '=') {
      seen_eq = 1;
      break;
    }
    if (klen < KEY_MAX - 1) {
      key[klen++] = line[i];
    }
  }
  if (!seen_eq || klen == 0) {
    return -1;
  }
  for (i = i + 1; i < n; i++) {
    if (vlen < VALUE_MAX - 1) {
      value[vlen++] = line[i];
    }
  }
  key[klen] = '\0';
  value[vlen] = '\0';
  return 0;
}

__attribute__((noinline)) static void fill_buffer(char *buf, long count) {
  long i;
  for (i = 0; i < count; i++) {
    buf[i] = (char)(i & 0xff);
  }
}

static void apply_setting(const char *key, const char *value) {
  if (strcmp(key, "name") == 0) {
    volatile size_t n = strlen(value);
    (void)n;
  } else if (strcmp(key, "mode") == 0) {
    if (strcmp(value, "strict") == 0 || strcmp(value, "lax") == 0) {
      volatile int mode_ok = 1;
      (void)mode_ok;
    }
  } else if (strcmp(key, "repeat") == 0) {
    long count = atol(value);
    char *buf;
    if (count < 0 || count > 100000) {
      return;
    }
    buf = (char *)malloc(32);
    if (buf == NULL) {
      return;
    }
    fill_buffer(buf, count);
    free(buf);
  }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char key[KEY_MAX];
  char value[VALUE_MAX];
  const char *line;
  size_t start = 0;
  size_t i;
  size_t linelen;

  for (i = 0; i <= size; i++) {
    if (i == size || data[i] == '\n') {
      linelen = i - start;
      line = (const char *)(data + start);
      if (linelen > 0 && line[0] != '#' && line[0] != ';') {
        if (split_line(line, linelen, key, value) == 0) {
          apply_setting(key, value);
        }
      }
      start = i + 1;
    }
  }
  return 0;
}
