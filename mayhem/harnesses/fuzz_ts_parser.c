/* Elementary-stream parsing of a tuned service's MPEG-TS: the parser a subscription puts in
 * front of every consumer (parser_create(), src/parsers/message.c) gets an SMT_START naming the
 * service's components, then the input as SMT_MPEGTS packets, as a mux input delivers them.
 * That reaches PES header parsing, PCR handling, the per-codec parsers (MPEG-2 video, H.264,
 * HEVC, MPEG audio, AC-3/E-AC-3/AC-4, AAC/LATM, ADTS, DVB subtitles, teletext, RDS, Opus) and
 * the HbbTV AIT section parser (PSI section reassembly, src/input/mpegts/dvb_psi_lib.c).
 *
 * The input is a TS stream: whole 188-byte packets (a trailing partial packet is cut off, as
 * the mux input only delivers whole ones). The component PIDs are fixed below, PID 0x100 also
 * carries the PCR. Parsed packets go to a sink that frees them. A new parser per input. */
#include "tvheadend.h"
#include "service.h"
#include "subscriptions.h"
#include "streaming.h"
#include "packet.h"
#include "parsers/parsers.h"
#include "fuzz_common.h"

static const struct { int16_t pid; int type; } comps[] = {
  { 0x100, SCT_H264 },      { 0x101, SCT_HEVC },     { 0x102, SCT_MPEG2VIDEO },
  { 0x103, SCT_MPEG2AUDIO },{ 0x104, SCT_AC3 },      { 0x105, SCT_EAC3 },
  { 0x106, SCT_AAC },       { 0x107, SCT_MP4A },     { 0x108, SCT_DVBSUB },
  { 0x109, SCT_TELETEXT },  { 0x10a, SCT_HBBTV },    { 0x10b, SCT_RDS },
  { 0x10c, SCT_AC4 },       { 0x10d, SCT_OPUS },     { 0x10e, SCT_TEXTSUB },
};
#define NCOMPS (sizeof(comps) / sizeof(comps[0]))

static service_t svc;
static th_subscription_t sub;

static void sink(void *opaque, streaming_message_t *sm)
{
  streaming_msg_free(sm);
}

static htsmsg_t *sink_info(void *opaque, htsmsg_t *list)
{
  htsmsg_add_str(list, NULL, "fuzz sink");
  return list;
}

static streaming_ops_t sink_ops = { .st_cb = sink, .st_info = sink_info };

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  streaming_target_t out;

  tvh_fuzz_init();
  svc.s_nicename = (char *)"fuzz";
  sub.ths_service = &svc;
  size -= size % 188;
  if (size == 0)
    return -1;

  streaming_target_init(&out, &sink_ops, NULL, 0);
  streaming_target_t *prs = parser_create(&out, &sub);

  streaming_start_t *ss = calloc(1, sizeof(*ss) + NCOMPS * sizeof(streaming_start_component_t));
  ss->ss_refcount = 1;
  ss->ss_num_components = NCOMPS;
  ss->ss_pcr_pid = 0x100;
  ss->ss_pmt_pid = 0x20;
  ss->ss_service_id = 1;
  for (size_t i = 0; i < NCOMPS; i++) {
    ss->ss_components[i].es_index = i + 1;
    ss->ss_components[i].es_pid = comps[i].pid;
    ss->ss_components[i].es_type = comps[i].type;
    memcpy(ss->ss_components[i].es_lang, "eng", 4);
  }
  streaming_target_deliver(prs, streaming_msg_create_data(SMT_START, ss));
  streaming_target_deliver(prs, streaming_msg_create_data(SMT_MPEGTS, pktbuf_alloc(data, size)));
  parser_destroy(prs);
  return 0;
}
