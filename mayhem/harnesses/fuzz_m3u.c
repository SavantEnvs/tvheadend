/* M3U/EXTM3U/HLS playlists fetched from remote servers by IPTV automatic networks
 * (src/misc/m3u.c), with relative URL resolution against the playlist URL. */
#include "tvheadend.h"
#include "misc/m3u.h"
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  tvh_fuzz_init();
  char *s = tvh_fuzz_strdup(data, size);
  htsmsg_t *m = parse_m3u(s, "UTF-8", "http://example.com/dir/list.m3u");
  if (m)
    htsmsg_destroy(m);
  free(s);
  return 0;
}
