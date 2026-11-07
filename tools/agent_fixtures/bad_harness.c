#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <time.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0) {
    exit(0);
  }
  if (data[0] == 'A') {
    if (rand() % 2 == 0) {
      exit(1);
    }
    if (time(0) % 3 == 0) {
      return -1;
    }
  }
  return 0;
}
