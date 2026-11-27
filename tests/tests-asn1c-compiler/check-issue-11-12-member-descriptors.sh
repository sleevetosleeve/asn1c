#!/bin/sh
#
# Purpose: regress issues #11 and #12 (member descriptor naming and dedup).
# Original source: issues #11/#12 and PR #13 (4dab92c, 905c05d); per #19.
# Version/date: 1.0, 2026-11-27.
# Parameters: Automake source/build roots and optional CC, CFLAGS.
# Returns: zero when -fcompound-names succeeds and no symbol is defined twice.
# Errors: generation, compilation, or duplicate-symbol failures exit nonzero.
# Responsible party: asn1c maintainers.
# History: initial dedicated test for the member descriptor alias fixes.
# Example: make check TESTS=check-issue-11-12-member-descriptors.sh

set -eu

source_root=$(cd "${abs_top_srcdir:-${top_srcdir:?top_srcdir is required}}" && pwd)
build_root=$(cd "${abs_top_builddir:-${top_builddir:?top_builddir is required}}" && pwd)
compiler="$build_root/asn1c/asn1c"
skeletons="$source_root/skeletons"
test_root=$(mktemp -d "${TMPDIR:-/tmp}/asn1c-issue-11-12-desc.XXXXXX")
trap 'rm -rf "$test_root"' EXIT HUP INT TERM

# Reject duplicated exported symbols across separately compiled siblings.
# Arguments: two object files whose global symbol tables must not overlap.
check_no_duplicate_symbols() {
    duplicates=$(nm --defined-only -g "$1" "$2" 2>/dev/null \
        | awk '$2 ~ /^[TDBR]$/ {print $3}' | sort | uniq -d)
    if [ -n "$duplicates" ]; then
        echo "FAIL: duplicate global symbols across $1 and $2:" >&2
        echo "$duplicates" >&2
        exit 1
    fi
}

# Issue #11: a REAL type reference narrowed to C float must not mint dead
# per-member descriptors registered by the bare member name, so two types
# sharing member names must compile under -fcompound-names without a FATAL.
mkdir "$test_root/real"
cat > "$test_root/real/Coords.asn1" <<'EOF'
Coords DEFINITIONS ::= BEGIN

Coord ::= REAL (WITH COMPONENTS { mantissa (-16777215..16777215), base (2), exponent (-149..104) })

Vec2 ::= SEQUENCE { x Coord, y Coord }

Vec3 ::= SEQUENCE { x Coord, y Coord, z Coord }

END
EOF
mkdir "$test_root/real/out"
if ! "$compiler" -fcompound-names -S "$skeletons" -no-gen-example \
    -D "$test_root/real/out" "$test_root/real/Coords.asn1" \
    >"$test_root/real/generate.log" 2>&1; then
    cat "$test_root/real/generate.log" >&2
    exit 1
fi
for module in Vec2 Vec3; do
    if ! ${CC:-cc} -std=gnu18 -Wall -Werror ${CFLAGS:-} \
        -I"$test_root/real/out" -c "$test_root/real/out/$module.c" \
        -o "$test_root/real/$module.o" >"$test_root/real/$module.log" 2>&1; then
        cat "$test_root/real/$module.log" >&2
        exit 1
    fi
done
check_no_duplicate_symbols "$test_root/real/Vec2.o" "$test_root/real/Vec3.o"

# Issue #12: member-level unsuffixed aliases must be named as registered
# (the compound name), so sibling types with same-named members must not
# silently define the same weak alias in both translation units.
mkdir "$test_root/alltypes"
cat > "$test_root/alltypes/AllTypes.asn1" <<'EOF'
AllTypes DEFINITIONS AUTOMATIC TAGS ::= BEGIN

A ::= SEQUENCE {
    i   INTEGER (0..10),
    b   BIT STRING { one(0) },
    e   ENUMERATED { aa, bb }
}

B ::= SEQUENCE {
    i   INTEGER (0..10),
    b   BIT STRING { one(0) },
    e   ENUMERATED { aa, bb }
}

END
EOF
mkdir "$test_root/alltypes/out"
if ! "$compiler" -fcompound-names -S "$skeletons" -no-gen-example \
    -D "$test_root/alltypes/out" "$test_root/alltypes/AllTypes.asn1" \
    >"$test_root/alltypes/generate.log" 2>&1; then
    cat "$test_root/alltypes/generate.log" >&2
    exit 1
fi
for module in A B; do
    if ! ${CC:-cc} -std=gnu18 -Wall -Werror ${CFLAGS:-} \
        -I"$test_root/alltypes/out" -c "$test_root/alltypes/out/$module.c" \
        -o "$test_root/alltypes/$module.o" >"$test_root/alltypes/$module.log" 2>&1; then
        cat "$test_root/alltypes/$module.log" >&2
        exit 1
    fi
done
check_no_duplicate_symbols "$test_root/alltypes/A.o" "$test_root/alltypes/B.o"

echo 'PASS: issues #11/#12 member descriptor naming without duplicate symbols'
