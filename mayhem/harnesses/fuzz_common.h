/* Shared one-time setup for the tvheadend harnesses: the subset of main()'s init order
 * (src/main.c) that the fuzzed parsers depend on. */
#ifndef TVH_FUZZ_COMMON_H
#define TVH_FUZZ_COMMON_H
#include <stddef.h>
#include <stdint.h>
void tvh_fuzz_init(void);
/* malloc'd NUL-terminated copy of the input */
char *tvh_fuzz_strdup(const uint8_t *data, size_t size);
#endif
