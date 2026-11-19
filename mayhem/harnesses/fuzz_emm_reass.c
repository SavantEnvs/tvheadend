/* EMM filtering/reassembly (src/descrambler/emm_reass.c): EMM sections are taken straight from
 * the broadcast TS and filtered (and, for Viaccess/Cryptoworks, reassembled from shared+data
 * parts) per card before being forwarded to the card server.
 *
 * Input layout, mirroring what cc_new_card() stores from the card server's card data:
 *   caid[2] ua[8] nprov[1] { provid[3] sa[8] } * (nprov % 17)  then a sequence of EMM sections,
 *   each one's length taken from its own section header (3 + 12-bit section_length), as the PSI
 *   table layer (descrambler_table_callback -> cc_emm) hands complete sections to emm_filter().
 *   Sections shorter than 6 bytes are parsed and skipped, never passed in: the only real
 *   source, descrambler_table_callback(), drops them first (descrambler.c:1316, `if (len < 6)`).
 *   The mux pointer is one of two values, picked by the high bit of section byte 1, so the
 *   "shared part came from another mux" branches are reachable. A fresh emm_reass_t per input. */
#include "tvheadend.h"
#include "descrambler/emm_reass.h"
#include "fuzz_common.h"

static volatile uint8_t sink;

static void emm_send(void *aux, const uint8_t *radata, int ralen, void *mux)
{
  uint8_t x = 0;
  for (int i = 0; i < ralen; i++)
    x ^= radata[i];
  sink = x;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  static int mux_a, mux_b;
  emm_reass_t ra;
  size_t off = 0;
  int i, nprov;

  tvh_fuzz_init();
  if (size < 11)
    return -1;
  emm_reass_init(&ra, LS_CWC, (data[0] << 8) | data[1]);
  memcpy(ra.ua, data + 2, 8);
  nprov = data[10] % 17;
  off = 11;
  if (size - off < (size_t)nprov * 11) {
    emm_reass_done(&ra);
    return -1;
  }
  ra.providers = nprov ? calloc(nprov, sizeof(emm_provider_t)) : NULL;
  ra.providers_count = nprov;
  for (i = 0; i < nprov; i++, off += 11) {
    ra.providers[i].id = (data[off] << 16) | (data[off + 1] << 8) | data[off + 2];
    memcpy(ra.providers[i].sa, data + off + 3, 8);
  }
  while (size - off >= 3) {
    size_t len = 3 + (((data[off + 1] & 0x0f) << 8) | data[off + 2]);
    if (len > size - off)
      break;
    if (len < 6) { /* descrambler_table_callback() returns early on len < 6 (descrambler.c:1316) */
      off += len;
      continue;
    }
    /* each section in its own exact-size buffer, as a reassembled PSI section is */
    uint8_t *sec = malloc(len);
    memcpy(sec, data + off, len);
    emm_filter(&ra, sec, len, (data[off + 1] & 0x80) ? (void *)&mux_b : (void *)&mux_a,
               emm_send, NULL);
    free(sec);
    off += len;
  }
  emm_reass_done(&ra);
  return 0;
}
