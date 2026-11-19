/* XML: the parser for XMLTV grabber output and SAT>IP/UPnP device descriptions
 * (src/htsmsg_xml.c). */
#include "tvheadend.h"
#include "htsmsg_xml.h"
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  char err[256];
  tvh_fuzz_init();
  /* takes ownership of the buffer */
  htsmsg_t *m = htsmsg_xml_deserialize(tvh_fuzz_strdup(data, size), err, sizeof(err));
  if (m)
    htsmsg_destroy(m);
  return 0;
}
