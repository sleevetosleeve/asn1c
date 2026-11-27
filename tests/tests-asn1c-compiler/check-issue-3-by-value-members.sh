#!/bin/sh
#
# Purpose: regress issue #3 (by-value members for non-recursive references).
# Original source: issue #3 and PR #4 (a7346cc); dedicated coverage per #19.
# Version/date: 1.0, 2026-11-27.
# Parameters: Automake source/build roots and optional CC, CFLAGS.
# Returns: zero when member classification and the DER/BER round-trip pass.
# Errors: generation, compilation, grep, or runtime failures exit nonzero.
# Responsible party: asn1c maintainers.
# History: initial dedicated test for the by-value member classification.
# Example: make check TESTS=check-issue-3-by-value-members.sh

set -eu

source_root=$(cd "${abs_top_srcdir:-${top_srcdir:?top_srcdir is required}}" && pwd)
build_root=$(cd "${abs_top_builddir:-${top_builddir:?top_builddir is required}}" && pwd)
compiler="$build_root/asn1c/asn1c"
skeletons="$source_root/skeletons"
schema="$source_root/tests/tests-asn1c-compiler/issue-3/shapes.asn1"
harness="$source_root/tests/tests-asn1c-compiler/issue-3/check-by-value-members.c"
test_root=$(mktemp -d "${TMPDIR:-/tmp}/asn1c-issue-3-by-value.XXXXXX")
trap 'rm -rf "$test_root"' EXIT HUP INT TERM
mkdir "$test_root/generated"

# A non-recursive reference member must be emitted by value; a member that
# closes a genuine recursion cycle must stay a pointer.
if ! "$compiler" -fcompound-names -no-gen-example \
    -S "$skeletons" -D "$test_root/generated" \
    "$schema" >"$test_root/generate.log" 2>&1; then
    cat "$test_root/generate.log" >&2
    exit 1
fi
grep -Eq 'Leaf_t[[:space:]]+root;' "$test_root/generated/Tree.h"
grep -Eq 'struct Node[[:space:]]*\*next;' "$test_root/generated/Node.h"

# The embedded member must be wire-compatible: DER encode and BER decode.
for module in Leaf Node Tree; do
    if ! ${CC:-cc} -std=gnu18 -Wall -Werror ${CFLAGS:-} \
        -I"$test_root/generated" -c "$test_root/generated/$module.c" \
        -o "$test_root/$module.o" >"$test_root/$module-compile.log" 2>&1; then
        cat "$test_root/$module-compile.log" >&2
        exit 1
    fi
done
if ! ${CC:-cc} ${CFLAGS:-} -I"$test_root/generated" \
    "$harness" "$test_root/generated"/*.c -lm \
    -o "$test_root/check-by-value-members" \
    >"$test_root/test-compile.log" 2>&1; then
    cat "$test_root/test-compile.log" >&2
    exit 1
fi
"$test_root/check-by-value-members"
echo 'PASS: issue #3 by-value classification and DER/BER round-trip'
