#!/usr/bin/env bash
#
# mayhem/build.sh — build tvheadend twice and link the fuzz harnesses against its objects.
#
# tvheadend is one monolithic daemon (custom ./configure + GNU make, no library target), so:
#   1) build.test: a normal-flags build; mayhem/selftest.c links against its objects (test.sh runs it)
#   2) build.fuzz: the same build with ASan+UBSan (halting), SanCov and DWARF 3
#   3) every harness in mayhem/harnesses links against build.fuzz's objects, with main.o's `main`
#      renamed (main.c also defines globals like global_lock that the code needs)
# The configure flags keep the build offline: by default it downloads and builds ffmpeg,
# libhdhomerun and dvb-scan tables. Both build dirs (build.*) are gitignored upstream.
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

CONF_ARGS=(--cc="$CC" --python=python3 --nowerror
  --disable-libav --disable-ffmpeg_static --disable-hdhomerun_static --disable-hdhomerun_client
  --disable-dvbscan --disable-avahi --disable-dbus_1 --disable-pcre --disable-pcre2
  --disable-uriparser --disable-vue_build --disable-ccache --disable-tvhcsa --disable-bundle
  --disable-pie --disable-libsystemd_daemon)
LIBS=(-lssl -lcrypto -lz -lpthread -ldl -lm -lrt)

# configure writes the build dir AND the shared $SRC/.config.mk, so configure+make run back to back.
build_tvh() { # <builddir> <cflags> <ldflags>
  BUILDDIR="$SRC/$1" ./configure "${CONF_ARGS[@]}" --cflags="$2" --ldflags="$3" >/dev/null
  make -j"$MAYHEM_JOBS" BUILDDIR="$SRC/$1" "$SRC/$1/tvheadend"
}

# The objects of the daemon minus main(): main.o is kept (it defines global state) with `main`
# renamed so the harness's (or libFuzzer's) main wins.
tvh_objs() { # <builddir>
  local b="$SRC/$1"
  objcopy --redefine-sym main=tvh_main "$b/src/main.o" "$b/main_nomain.o"
  find "$b/src" -name '*.o' ! -path "$b/src/main.o" | LC_ALL=C sort
  echo "$b/main_nomain.o" "$b/build.o" "$b/timestamp.o"
}

# 1) test build, normal flags, then the self-test (mayhem/test.sh runs it)
build_tvh build.test "$COVERAGE_FLAGS" "$COVERAGE_FLAGS"
mapfile -t TOBJS < <(tvh_objs build.test | tr ' ' '\n')
TINC=(-I"$SRC/build.test" -I"$SRC/src" -I"$SRC")
"$CC" -O1 -g $COVERAGE_FLAGS -fms-extensions -funsigned-char -D_FILE_OFFSET_BITS=64 "${TINC[@]}" \
  mayhem/selftest.c mayhem/harnesses/fuzz_common.c "${TOBJS[@]}" "${LIBS[@]}" -o "$SRC/tvh_selftest"

# 2) fuzz build: the whole daemon instrumented.
#    UBSan's shift-base check is relaxed (only it): tvheadend reads big-endian words everywhere as
#    `d[0] << 24 | ...` on promoted uint8_t (RB32() in src/parsers/bitstream.h and many more), which
#    halts on any byte >= 0x80. shift-exponent (shifting by >= the width) and the rest stay on.
UB_RELAX=""
case "$SANITIZER_FLAGS" in *undefined*) UB_RELAX="-fno-sanitize=shift-base" ;; esac
FFLAGS="$SANITIZER_FLAGS $UB_RELAX $DEBUG_FLAGS -fsanitize=fuzzer-no-link"
build_tvh build.fuzz "$FFLAGS" "$SANITIZER_FLAGS"
mapfile -t FOBJS < <(tvh_objs build.fuzz | tr ' ' '\n')
FINC=(-I"$SRC/build.fuzz" -I"$SRC/src" -I"$SRC")
HCFLAGS=(-O1 $SANITIZER_FLAGS $UB_RELAX $DEBUG_FLAGS -fms-extensions -funsigned-char -D_FILE_OFFSET_BITS=64 "${FINC[@]}")

mkdir -p "$SRC/build.fuzz/harness"
"$CC" "${HCFLAGS[@]}" -c mayhem/lsan_off.c -o "$SRC/build.fuzz/harness/lsan_off.o"
"$CC" "${HCFLAGS[@]}" -c mayhem/harnesses/fuzz_common.c -o "$SRC/build.fuzz/harness/fuzz_common.o"
"$CC" "${HCFLAGS[@]}" -c "$STANDALONE_FUZZ_MAIN" -o "$SRC/build.fuzz/harness/standalone_main.o"
COMMON=("$SRC/build.fuzz/harness/lsan_off.o" "$SRC/build.fuzz/harness/fuzz_common.o")

# 3) one fuzzer + one -standalone reproducer per harness.
#    The CA-client harnesses #include the protocol's .c file (its reply handlers are static), so
#    they link without that file's own object.
replaced_obj() { # <harness name> -> the build.fuzz object the harness compiles in itself
  case "$1" in
    fuzz_cccam)   echo "$SRC/build.fuzz/src/descrambler/cccam.o" ;;
    fuzz_newcamd) echo "$SRC/build.fuzz/src/descrambler/cwc.o" ;;
  esac
}
for h in mayhem/harnesses/fuzz_*.c; do
  name=$(basename "$h" .c)
  [ "$name" = fuzz_common ] && continue
  skip=$(replaced_obj "$name")
  if [ -n "$skip" ]; then
    [ -f "$skip" ] || { echo "build.sh: $skip missing (is the CA client enabled?)" >&2; exit 1; }
    HOBJS=()
    for o in "${FOBJS[@]}"; do [ "$o" = "$skip" ] || HOBJS+=("$o"); done
  else
    HOBJS=("${FOBJS[@]}")
  fi
  "$CC" "${HCFLAGS[@]}" -fsanitize=fuzzer-no-link -c "$h" -o "$SRC/build.fuzz/harness/$name.o"
  "$CC" $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$SRC/build.fuzz/harness/$name.o" \
    "${COMMON[@]}" "${HOBJS[@]}" "${LIBS[@]}" -o "$SRC/$name"
  "$CC" $SANITIZER_FLAGS $DEBUG_FLAGS "$SRC/build.fuzz/harness/standalone_main.o" \
    "$SRC/build.fuzz/harness/$name.o" "${COMMON[@]}" "${HOBJS[@]}" "${LIBS[@]}" -o "$SRC/$name-standalone"
done
ls -l "$SRC"/fuzz_* "$SRC/tvh_selftest"
