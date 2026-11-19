/* CCcam client protocol (src/descrambler/cccam.c): the messages a remote CCcam card server sends
 * once the session is up (new card / card removed / ECM replies / server data / partner info).
 *
 * cccam.c's handlers are file-static, so this harness compiles cccam.c itself and build.sh links
 * it without build.fuzz's own cccam.o. The input is the decrypted server stream: cccam_read() is
 * reproduced without the per-session stream cipher (cccam_decrypt with keys from the handshake),
 * i.e. 4-byte frames {seq, cmd, len_hi, len_lo} + len payload bytes, sitting in the same sbuf the
 * session loop (cc_session in cclient.c) reads the socket into, and each complete frame goes to
 * cccam_running_reply() exactly as cccam_read() passes it. A fresh client per input. */
#include "descrambler/cccam.c"
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  cccam_t *cccam;
  cc_card_data_t *pcard;
  sbuf_t rbuf;

  tvh_fuzz_init();
  cccam = calloc(1, sizeof(*cccam));
  cccam->cc_subsys = LS_CCCAM;
  cccam->cc_name = (char *)"fuzz";
  cccam->cc_id = "cccam";
  cccam->cc_username = (char *)"user";
  /* already connected: caclient_set_status() then has no idnode change to notify */
  cccam->cac_status = CACLIENT_STATUS_CONNECTED;
  cccam->cc_fd = -1;
  cccam->cc_write_running = 0;     /* queued replies (cc_write_message enq=1) are freed */
  tvh_mutex_init(&cccam->cc_mutex, NULL);
  TAILQ_INIT(&cccam->cc_writeq);
  LIST_INIT(&cccam->cc_services);
  LIST_INIT(&cccam->cc_cards);
  memcpy(cccam->cccam_nodeid, "\x11\x22\x33\x44\x55\x66\x77\x88", 8);

  sbuf_init(&rbuf);
  sbuf_alloc(&rbuf, 1024);
  sbuf_append(&rbuf, data, size);
  tvh_mutex_lock(&cccam->cc_mutex); /* "cc_mutex is held" (cccam_running_reply) */
  while (rbuf.sb_ptr >= 4) {
    int r = ((rbuf.sb_data[2] << 8) | rbuf.sb_data[3]) + 4;
    if (rbuf.sb_ptr < r)
      break;
    if (cccam_running_reply(cccam, rbuf.sb_data, r) < 0)
      break;
    sbuf_cut(&rbuf, r);
  }
  tvh_mutex_unlock(&cccam->cc_mutex);
  sbuf_free(&rbuf);

  while ((pcard = LIST_FIRST(&cccam->cc_cards)) != NULL)
    cc_remove_card((cclient_t *)cccam, pcard);
  tvh_mutex_destroy(&cccam->cc_mutex);
  free(cccam);
  return 0;
}
