/* tvh_selftest — known-answer checks of tvheadend's own parsers, linked against the normal
 * (unsanitized) build. Prints one "<case>\t<result>" line per case; mayhem/test.sh diffs each
 * line against mayhem/selftest.expected. */
#include "tvheadend.h"
#include "htsmsg_json.h"
#include "htsmsg_binary.h"
#include "htsmsg_xml.h"
#include "misc/m3u.h"
#include "url.h"
#include "input/mpegts/dvb.h"
#include "harnesses/fuzz_common.h"

static void out(const char *name, const char *res)
{
  printf("%s\t%s\n", name, res ? res : "(null)");
}

static void out_msg(const char *name, htsmsg_t *m)
{
  char *s = m ? htsmsg_json_serialize_to_str(m, 0) : NULL;
  if (s) {
    /* one line per case */
    for (char *p = s; *p; p++) if (*p == '\n') *p = ' ';
  }
  out(name, s);
  free(s);
  if (m) htsmsg_destroy(m);
}

static void json_case(const char *name, const char *in)
{
  out_msg(name, htsmsg_json_deserialize(in));
}

static void xml_case(const char *name, const char *in)
{
  char err[128] = "";
  htsmsg_t *m = htsmsg_xml_deserialize(strdup(in), err, sizeof(err));
  if (!m) { char b[160]; snprintf(b, sizeof(b), "error: %s", err); out(name, b); return; }
  out_msg(name, m);
}

static void m3u_case(const char *name, const char *in)
{
  char *s = strdup(in);
  out_msg(name, parse_m3u(s, "UTF-8", "http://example.com/dir/list.m3u"));
  free(s);
}

static void url_case(const char *name, const char *in)
{
  url_t u; char b[1024];
  urlinit(&u);
  if (urlparse(in, &u)) { out(name, "error"); urlreset(&u); return; }
  snprintf(b, sizeof(b), "scheme=%s user=%s pass=%s host=%s port=%d path=%s query=%s frag=%s",
           u.scheme ?: "", u.user ?: "", u.pass ?: "", u.host ?: "", u.port,
           u.path ?: "", u.query ?: "", u.frag ?: "");
  urlrecompose(&u);
  size_t l = strlen(b);
  snprintf(b + l, sizeof(b) - l, " raw=%s", u.raw ?: "");
  out(name, b);
  urlreset(&u);
}

static void binary_case(const char *name, const char *json)
{
  htsmsg_t *m = htsmsg_json_deserialize(json);
  void *bin = NULL; size_t len = 0;
  if (!m || htsmsg_binary_serialize(m, &bin, &len, INT32_MAX)) { out(name, "error"); return; }
  htsmsg_destroy(m);
  char hex[64]; snprintf(hex, sizeof(hex), "len=%zu ", len);
  /* skip the 4-byte length prefix the serializer adds */
  void *copy = malloc(len - 4); memcpy(copy, (uint8_t *)bin + 4, len - 4);
  m = htsmsg_binary_deserialize0(copy, len - 4, copy);
  char *s = m ? htsmsg_json_serialize_to_str(m, 0) : NULL;
  char b[1024]; snprintf(b, sizeof(b), "%s%s", hex, s ?: "(null)");
  out(name, b);
  free(s); free(bin);
  if (m) htsmsg_destroy(m);
}

static void dvb_case(const char *name, const uint8_t *in, size_t len, const char *cs)
{
  char dst[256];
  if (dvb_get_string(dst, sizeof(dst), in, len, cs, NULL)) { out(name, "error"); return; }
  out(name, dst);
}

int main(void)
{
  tvh_fuzz_init();

  json_case("json_object", "{\"a\":1,\"b\":\"x\\u00e9y\",\"c\":[1,2.5,-3],\"d\":{\"e\":true,\"f\":null}}");
  json_case("json_escapes", "[\"tab\\there\",\"q\\\"uote\",\"sl\\/ash\"]");
  json_case("json_invalid", "{\"a\":");
  binary_case("binary_roundtrip", "{\"method\":\"hello\",\"htspversion\":34,\"list\":[\"a\",\"b\"],\"sub\":{\"n\":-7}}");
  xml_case("xml_simple", "<?xml version=\"1.0\"?><tv><channel id=\"c1\"><display-name lang=\"en\">One &amp; Two</display-name></channel></tv>");
  xml_case("xml_charref", "<a>&#65;&#x42;<![CDATA[<raw>]]></a>");
  xml_case("xml_unclosed", "<a><b></a>");
  m3u_case("m3u_extinf", "#EXTM3U\n#EXTINF:-1 tvg-id=\"ch1\" tvg-logo=\"logo.png\" group-title=\"News\",Channel One\nhttp://srv/stream1.ts\n#EXTINF:5,Second\nrel/stream2.ts\n");
  m3u_case("m3u_not_m3u", "hello\nworld\n");
  url_case("url_full", "http://user:pw@example.com:8080/path/x.ts?a=1&b=2#frag");
  url_case("url_rtsp", "rtsp://10.0.0.1/?src=1&freq=11494&pol=h&msys=dvbs");
  url_case("url_bad", "::not a url");
  dvb_case("dvb_ascii", (const uint8_t *)"Hello World", 11, NULL);
  dvb_case("dvb_8859_9", (const uint8_t *)"\x05" "G\xfc" "zel", 6, NULL);
  dvb_case("dvb_utf8", (const uint8_t *)"\x15" "caf\xc3\xa9", 6, NULL);
  {
    /* 1993-10-13 12:45:00 UTC: the example in EN 300 468 annex C */
    const uint8_t d[5] = { 0xC0, 0x79, 0x12, 0x45, 0x00 };
    char b[32]; snprintf(b, sizeof(b), "%lld", (long long)dvb_convert_date(d, 0));
    out("dvb_date", b);
  }
  return 0;
}
