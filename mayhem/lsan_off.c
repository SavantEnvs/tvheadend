/* Leak detection is off for every target (leaks are not the bug class fuzzed here). */
int __lsan_is_turned_off(void);
int __lsan_is_turned_off(void) { return 1; }
