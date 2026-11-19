/* HTSP wire format: the deserializer htsp_read_message() runs on every client message,
 * before authentication (src/htsp_server.c), then a re-serialize of what it built. */
#include "tvheadend.h"
#include "htsmsg_binary.h"
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  tvh_fuzz_init();
  void *buf = malloc(size ? size : 1);
  memcpy(buf, data, size);
  /* takes ownership of buf: tied to the message on success, freed on failure */
  htsmsg_t *m = htsmsg_binary_deserialize0(buf, size, buf);
  if (m) {
    void *out = NULL;
    size_t outlen = 0;
    if (htsmsg_binary_serialize(m, &out, &outlen, INT32_MAX) == 0)
      free(out);
    htsmsg_destroy(m);
  }
  return 0;
}
