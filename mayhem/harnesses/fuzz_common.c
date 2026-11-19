#include "tvheadend.h"
#include "tvhlog.h"
#include "intlconv.h"
#include "tvh_locale.h"
#include "fuzz_common.h"

extern pthread_t main_tid;
extern int tvhlog_run; /* src/tvhlog.c, not in tvhlog.h */

void tvh_fuzz_init(void)
{
  static int done;
  if (done)
    return;
  done = 1;
  main_tid = pthread_self();
  /* the global mutexes main() sets up first */
  tvh_mutex_init(&fork_lock, NULL);
  tvh_mutex_init(&global_lock, NULL);
  tvh_mutex_init(&tasklet_lock, NULL);
  tvh_mutex_init(&atomic_lock, NULL);
  tvh_gettext_init();
  tvh_thread_init(0);
  /* errors only; logging stays synchronous (no log thread is started), with no output
     options set, so nothing is queued across inputs */
  tvhlog_init(LOG_ERR, 0, NULL);
  tvhlog_run = 0;
  intlconv_init();
}

char *tvh_fuzz_strdup(const uint8_t *data, size_t size)
{
  char *s = malloc(size + 1);
  memcpy(s, data, size);
  s[size] = '\0';
  return s;
}
