/* DVB/ATSC SI text and date decoding: the strings and times in broadcast service, event and
 * network tables (src/input/mpegts/dvb_support.c). The first byte picks the configured
 * default charset (the mux/network "charset" setting); the rest is the SI field. */
#include "tvheadend.h"
#include "input/mpegts/dvb.h"
#include "lang_str.h"
#include "fuzz_common.h"

static const char *charsets[] = {
  NULL, "AUTO", "AUTO_POLISH", "ISO-6937", "ISO-8859-1", "ISO-8859-5", "ISO-8859-9",
  "ISO-8859-15", "UTF-8", "GB2312", "UCS2"
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  char dst[256];
  tvh_fuzz_init();
  if (size < 1)
    return -1;
  const char *cs = charsets[data[0] % (sizeof(charsets) / sizeof(charsets[0]))];
  data++; size--;

  dvb_get_string(dst, sizeof(dst), data, size, cs, NULL);
  /* both read a leading count byte, and callers only pass them a non-empty field */
  if (size >= 1) {
    dvb_get_string_with_len(dst, sizeof(dst), data, size, cs, NULL);
    lang_str_t *ls = atsc_get_string(data, size);
    if (ls)
      lang_str_destroy(ls);
  }
  /* len counts UTF-16 units, not bytes (dvb_psi.c passes 7 for the 14-byte VCT short_name) */
  atsc_utf16_to_utf8(data, (int)(size / 2), dst, sizeof(dst));
  if (size >= 5)
    (void)dvb_convert_date(data, 0);
  return 0;
}
