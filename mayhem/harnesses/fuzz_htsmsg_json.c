/* JSON: the parser behind API POST bodies, config files and grabber data
 * (src/htsmsg_json.c, src/misc/json.c), plus a serialize of the result. */
#include "tvheadend.h"
#include "htsmsg_json.h"
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  tvh_fuzz_init();
  char *s = tvh_fuzz_strdup(data, size);
  htsmsg_t *m = htsmsg_json_deserialize(s);
  if (m) {
    free(htsmsg_json_serialize_to_str(m, 1));
    htsmsg_destroy(m);
  }
  free(s);
  return 0;
}
