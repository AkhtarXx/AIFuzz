#include <png.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  png_image image;
  png_bytep buffer;

  memset(&image, 0, sizeof(image));
  image.version = PNG_IMAGE_VERSION;
  if (png_image_begin_read_from_memory(&image, data, size) == 0) {
    return 0;
  }
  image.format = PNG_FORMAT_RGBA;
  buffer = (png_bytep)malloc(PNG_IMAGE_SIZE(image));
  if (buffer != NULL) {
    if (png_image_finish_read(&image, NULL, buffer, 0, NULL) == 0) {
      volatile int sink = 1;
      (void)sink;
    }
    free(buffer);
  } else {
    png_image_free(&image);
  }
  return 0;
}
