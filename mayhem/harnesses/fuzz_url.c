/* URLs from IPTV mux configs, M3U playlist entries and HTTP client redirects (Location:),
 * parsed by urlparse() (src/url.c; the regex variant, as built without liburiparser),
 * then copied and recomposed as the HTTP client does on a redirect. */
#include "tvheadend.h"
#include "url.h"
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  url_t u, c;
  tvh_fuzz_init();
  char *s = tvh_fuzz_strdup(data, size);
  urlinit(&u);
  if (urlparse(s, &u) == 0) {
    urlinit(&c);
    urlcopy(&c, &u);
    urlrecompose(&c);
    urlreset(&c);
  }
  urlreset(&u);
  free(s);
  return 0;
}
