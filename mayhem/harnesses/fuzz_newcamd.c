/* newcamd client protocol (src/descrambler/cwc.c): the replies a remote newcamd card server
 * sends: the card data reply at login (cwc_decode_card_data_reply, from cwc_init_session) and
 * then the running replies (ECM answers, 0xD3 card add) in the session loop (cwc_running_reply,
 * from cwc_read).
 *
 * cwc.c's handlers are file-static, so this harness compiles cwc.c itself and build.sh links it
 * without build.fuzz's own cwc.o. The input is the decrypted server stream: frames of
 * {len_hi, len_lo} + len bytes. des_decrypt() (triple-DES with the session key) is skipped, but its
 * framing contract is kept: a frame is accepted only if (len % 8) == 0 and len >= 16, and the
 * decrypted message is len + 2 - 8 bytes long (the last 8 bytes are the IV block).
 *   - The first frame is the login card-data reply. cwc_init_session() reads it into a
 *     CWS_NETMSGSIZE stack buffer, rejecting len > CWS_NETMSGSIZE (cwc_read_message); this harness
 *     also rejects len + 2 > CWS_NETMSGSIZE so the copy stays inside the buffer. It is handled
 *     only if byte 12 is MSG_CARD_DATA, as cwc_init_session() requires.
 *   - The remaining frames sit in the sbuf the session loop reads the socket into (cc_session)
 *     and are handled exactly as cwc_read() handles them.
 * A fresh client per input. */
#include "descrambler/cwc.c"
#include "fuzz_common.h"

static int frame_ok(int msglen)
{
  return msglen % 8 == 0 && msglen >= 16 && msglen + 2 - 8 >= 15;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  uint8_t buf[CWS_NETMSGSIZE];
  cc_card_data_t *pcard;
  cwc_t *cwc;
  sbuf_t rbuf;
  int msglen;

  tvh_fuzz_init();
  if (size < 2)
    return -1;
  msglen = (data[0] << 8) | data[1];
  if (msglen + 2 > sizeof(buf) || msglen + 2 > size || !frame_ok(msglen))
    return -1;

  cwc = calloc(1, sizeof(*cwc));
  cwc->cc_subsys = LS_CWC;
  cwc->cc_name = (char *)"fuzz";
  cwc->cc_id = "newcamd";
  cwc->cc_username = (char *)"user";
  /* already connected: caclient_set_status() then has no idnode change to notify */
  cwc->cac_status = CACLIENT_STATUS_CONNECTED;
  cwc->cc_fd = -1;
  tvh_mutex_init(&cwc->cc_mutex, NULL);
  TAILQ_INIT(&cwc->cc_writeq);
  LIST_INIT(&cwc->cc_services);
  LIST_INIT(&cwc->cc_cards);

  tvh_mutex_lock(&cwc->cc_mutex);
  memset(buf, 0, sizeof(buf));
  memcpy(buf, data, msglen + 2);
  if (buf[12] != MSG_CARD_DATA ||
      cwc_decode_card_data_reply(cwc, buf, msglen + 2 - 8) < 0)
    goto done;
  data += msglen + 2;
  size -= msglen + 2;

  sbuf_init(&rbuf);
  sbuf_alloc(&rbuf, 1024);
  sbuf_append(&rbuf, data, size);
  while (rbuf.sb_ptr >= 2) {
    int rsize, r;
    msglen = (rbuf.sb_data[0] << 8) | rbuf.sb_data[1];
    if (rbuf.sb_ptr < 2 + msglen)
      break;
    rsize = msglen + 2;
    if (!frame_ok(msglen))
      break;
    r = msglen + 2 - 8;
    if (cwc_running_reply(cwc, rbuf.sb_data[12], rbuf.sb_data, r) < 0)
      break;
    sbuf_cut(&rbuf, rsize);
  }
  sbuf_free(&rbuf);

done:
  tvh_mutex_unlock(&cwc->cc_mutex);
  while ((pcard = LIST_FIRST(&cwc->cc_cards)) != NULL)
    cc_remove_card((cclient_t *)cwc, pcard);
  tvh_mutex_destroy(&cwc->cc_mutex);
  free(cwc);
  return 0;
}
