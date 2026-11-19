/* The HTTP server (port 9981): one client connection's bytes, sent to the daemon's own TCP
 * server (src/tcp.c accept loop -> http_serve() -> http_serve_requests(), src/http.c) on a
 * loopback port. That covers the request line and header parsing, keep-alive request loops, the
 * PROXY v1 preamble and X-Forwarded-For, Basic and Digest Authorization parsing
 * (http_get_header_value), query/POST argument parsing, path resolution, access checks and the
 * error/401 replies with their nonces.
 *
 * The server runs with config_boot()'s defaults (Digest auth, MD5) plus `proxy` on, with the
 * /api path registered and the default (empty) access list, so requests are refused at the
 * access check: no handler can change daemon state between inputs.
 *
 * State kept across inputs, on purpose: the config, the api hook tree and the TCP server thread
 * (none changes per request). What one input does change (the nonces issued in 401 replies and
 * the registered paths) is dropped after each input with http_server_done(), and the server is
 * started again; the harness waits for the server to close the connection before that. */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "tvheadend.h"
#include "config.h"
#include "access.h"
#include "api.h"
#include "http.h"
#include "tcp.h"
#include "webui/webui.h"
#include "fuzz_common.h"

extern tvh_mutex_t mtimer_lock;
extern int tvheadend_webui_port;

static struct sockaddr_in srv;

static void server_up(void)
{
  http_server_init("127.0.0.1");
  webui_api_init();
  http_server_register();
}

static void server_init(void)
{
  static int done;
  if (done)
    return;
  done = 1;
  tvh_fuzz_init();
  tvh_mutex_init(&mtimer_lock, NULL);
  /* the config_boot() defaults the HTTP server reads, plus the PROXY protocol option */
  config.http_auth = HTTP_AUTH_DIGEST;
  config.http_auth_algo = HTTP_AUTH_ALGO_MD5;
  config.realm = strdup("tvheadend");
  config.proxy = 1;
  /* a free loopback port for this process */
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  socklen_t sl = sizeof(srv);
  memset(&srv, 0, sizeof(srv));
  srv.sin_family = AF_INET;
  srv.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (fd < 0 || bind(fd, (struct sockaddr *)&srv, sizeof(srv)) ||
      getsockname(fd, (struct sockaddr *)&srv, &sl))
    abort();
  close(fd);
  tvheadend_webui_port = ntohs(srv.sin_port);
  access_init(0, 0);
  api_init();
  tcp_server_init();
  server_up();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  char buf[65536];
  size_t off = 0;

  server_init();
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0 || connect(fd, (struct sockaddr *)&srv, sizeof(srv)))
    abort();
  /* the replies are drained as the request goes out, so neither side blocks on a full buffer */
  while (off < size) {
    ssize_t r = send(fd, data + off, size - off, MSG_NOSIGNAL | MSG_DONTWAIT);
    if (r > 0) { off += r; continue; }
    if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      if (recv(fd, buf, sizeof(buf), MSG_DONTWAIT) == 0) break;
      continue;
    }
    break;
  }
  shutdown(fd, SHUT_WR);
  /* EOF: the server has finished with the connection */
  while (recv(fd, buf, sizeof(buf), 0) > 0)
    ;
  close(fd);

  http_server_done();
  server_up();
  return 0;
}
