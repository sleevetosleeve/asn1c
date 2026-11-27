#!/bin/sh
#
# Purpose: regress issue #5 (float-mapped REAL member descriptors).
# Original source: issue #5 and PR #7 (e5b6965); dedicated coverage per #19.
# Version/date: 1.0, 2026-11-27.
# Parameters: Automake source/build roots and optional CC, CFLAGS.
# Returns: zero when per-field descriptor wiring and the float round-trip pass.
# Errors: generation, compilation, grep, or runtime failures exit nonzero.
# Responsible party: asn1c maintainers.
# History: initial dedicated test for the float REAL member descriptor fix.
# Example: make check TESTS=check-issue-5-float-real-members.sh

set -eu

source_root=$(cd "${abs_top_srcdir:-${top_srcdir:?top_srcdir is required}}" && pwd)
build_root=$(cd "${abs_top_builddir:-${top_builddir:?top_builddir is required}}" && pwd)
compiler="$build_root/asn1c/asn1c"
skeletons="$source_root/skeletons"
schema="$source_root/tests/tests-asn1c-compiler/issue-5/real-repro.asn1"
harness="$source_root/tests/tests-asn1c-compiler/issue-5/check-float-real-members.c"
test_root=$(mktemp -d "${TMPDIR:-/tmp}/asn1c-issue-5-float-real.XXXXXX")
trap 'rm -rf "$test_root"' EXIT HUP INT TERM
mkdir "$test_root/generated"

# The -fwide-types float mapping must wire the per-field descriptors in the
# member table and include NativeReal.h so the generated file compiles.
if ! "$compiler" -fcompound-names -fwide-types -no-gen-example \
    -S "$skeletons" -D "$test_root/generated" "$schema" \
    >"$test_root/generate.log" 2>&1; then
    cat "$test_root/generate.log" >&2
    exit 1
fi
grep -q "#include <NativeReal.h>" "$test_root/generated/Vec3.h"
grep -Eq 'float[[:space:]]+x;' "$test_root/generated/Vec3.h"
grep -Eq 'float[[:space:]]+y;' "$test_root/generated/Vec3.h"
if sed -n '/asn_TYPE_member_t asn_MBR/,/^};/p' "$test_root/generated/Vec3.c" \
    | grep -q '&asn_DEF_REAL[,:]'; then
    echo 'FAIL: member table references wide asn_DEF_REAL' >&2
    exit 1
fi
sed -n '/asn_TYPE_member_t asn_MBR/,/^};/p' "$test_root/generated/Vec3.c" \
    | grep -Eq '&asn_DEF_x_[0-9]+,'
sed -n '/asn_TYPE_member_t asn_MBR/,/^};/p' "$test_root/generated/Vec3.c" \
    | grep -Eq '&asn_DEF_y_[0-9]+,'

# Compile the generated code strictly, then run the DER/BER round-trip.
if ! ${CC:-cc} -std=gnu18 -Wall -Werror ${CFLAGS:-} \
    -I"$test_root/generated" -c "$test_root/generated/Vec3.c" \
    -o "$test_root/Vec3.o" >"$test_root/Vec3-compile.log" 2>&1; then
    cat "$test_root/Vec3-compile.log" >&2
    exit 1
fi
if ! ${CC:-cc} ${CFLAGS:-} -I"$test_root/generated" \
    "$harness" "$test_root/generated"/*.c -lm \
    -o "$test_root/check-float-real-members" \
    >"$test_root/test-compile.log" 2>&1; then
    cat "$test_root/test-compile.log" >&2
    exit 1
fi
"$test_root/check-float-real-members"

# Without -fwide-types the same schema must still compile as generated.
mkdir "$test_root/narrow"
if ! "$compiler" -fcompound-names -no-gen-example \
    -S "$skeletons" -D "$test_root/narrow" "$schema" \
    >"$test_root/narrow-generate.log" 2>&1; then
    cat "$test_root/narrow-generate.log" >&2
    exit 1
fi
if ! ${CC:-cc} -std=gnu18 -Wall -Werror ${CFLAGS:-} \
    -I"$test_root/narrow" -c "$test_root/narrow/Vec3.c" \
    -o "$test_root/narrow-Vec3.o" >"$test_root/narrow-compile.log" 2>&1; then
    cat "$test_root/narrow-compile.log" >&2
    exit 1
fi
echo 'PASS: issue #5 float REAL member descriptors and round-trip'
