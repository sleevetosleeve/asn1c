#!/usr/bin/env bash
#
# Smoke test for the external decode context (issue #15): the generated
# converter-example must decode identically with code generated with and
# without -fno-ctx-members, including chunked (RC_WMORE) input reads.
# Inputs: top_builddir/top_srcdir, CC, MAKE; the 610-ext-ctx-ber-OK.asn1 module.
# Returns/errors: zero when both builds round-trip all codecs byte-identically
#   and reject truncated input; nonzero on any mismatch or build failure.
# Example: make -C tests/tests-asn1c-smoke check TESTS=check-ext-ctx.sh
set -eu

test_build_root=$(cd "${top_builddir:-../..}" && pwd)
test_source_root=$(cd "${top_srcdir:-../..}" && pwd)
test_directory=$(mktemp -d "${TMPDIR:-/tmp}/asn1c-ext-ctx.XXXXXX")
trap 'rm -rf "$test_directory"' EXIT

module="$test_source_root/tests/tests-asn1c-compiler/610-ext-ctx-ber-OK.asn1"

# BER encoding of NetMsg { id 42, body worldRequest { x 7, flag TRUE } }
# (AUTOMATIC TAGS): 30 0d 80 01 2a a1 08 a0 06 80 01 07 81 01 ff
printf '\060\015\200\001\052\241\010\240\006\200\001\007\201\001\377' \
    > "$test_directory/msg.ber"
# Truncated: header plus the first byte of id.
printf '\060\015\200\001' > "$test_directory/trunc.ber"

# Wrap { only { v 99 } }: the inline member sits at offset 0, so parent and
# child share the base address (arena frame aliasing regression).
# 30 05 a0 03 80 01 63
printf '\060\005\240\003\200\001\143' > "$test_directory/wrap.ber"

for mode in def ext; do
    gen="$test_directory/generated-$mode"
    mkdir "$gen"
    if [ "$mode" = ext ]; then
        flags="-fno-ctx-members"
    else
        flags=""
    fi
    # shellcheck disable=SC2086
    "$test_build_root/asn1c/asn1c" -S "$test_source_root/skeletons" \
        -D "$gen" -pdu=all $flags "$module"
    "${MAKE:-make}" -C "$gen" -f converter-example.mk CC="${CC:-cc}" > /dev/null
done

conv_def="$test_directory/generated-def/converter-example"
conv_ext="$test_directory/generated-ext/converter-example"

# Purpose: run one converter invocation and compare its stdout to $2.
# Example: expect_out "$conv_def" msg.der -p NetMsg -iber -oder msg.ber
run_cmp() {
    local conv=$1 expected=$2
    shift 2
    "$conv" "$@" > "$test_directory/out.actual"
    cmp "$expected" "$test_directory/out.actual"
}

for conv in "$conv_def" "$conv_ext"; do
    tag=$(basename "$(dirname "$conv")")

    # Whole-buffer BER decode re-encodes to identical DER.
    run_cmp "$conv" "$test_directory/msg.ber" \
        -p NetMsg -iber -oder "$test_directory/msg.ber"

    # One-byte input chunks force RC_WMORE resumes through the arena.
    run_cmp "$conv" "$test_directory/msg.ber" \
        -p NetMsg -b 1 -iber -oder "$test_directory/msg.ber"

    # XER output, then XER input (chunked) back to DER.
    "$conv" -p NetMsg -iber -oxer "$test_directory/msg.ber" \
        > "$test_directory/$tag.xer"
    run_cmp "$conv" "$test_directory/msg.ber" \
        -p NetMsg -b 2 -ixer -oder "$test_directory/$tag.xer"

    # JER output, then JER input (chunked) back to DER.
    "$conv" -p NetMsg -iber -ojer "$test_directory/msg.ber" \
        > "$test_directory/$tag.jer"
    run_cmp "$conv" "$test_directory/msg.ber" \
        -p NetMsg -b 3 -ijer -oder "$test_directory/$tag.jer"

    # Binary codecs: UPER, APER, OER, CBOR round-trips.
    for codec in uper aper oer cbor; do
        "$conv" -p NetMsg -iber -o"$codec" "$test_directory/msg.ber" \
            > "$test_directory/msg.$codec"
        run_cmp "$conv" "$test_directory/msg.ber" \
            -p NetMsg -i"$codec" -oder "$test_directory/msg.$codec"
    done

    # Aliasing regression through the converter: chunked Wrap decode.
    run_cmp "$conv" "$test_directory/wrap.ber" \
        -p Wrap -b 1 -iber -oder "$test_directory/wrap.ber"

    # Truncated input must fail cleanly (not hang or crash).
    if "$conv" -p NetMsg -b 1 -iber -oder "$test_directory/trunc.ber" \
        > /dev/null 2> "$test_directory/$tag.trunc.err"; then
        echo "FAIL: $tag converter accepted truncated BER" >&2
        exit 1
    fi
done

# Both generation modes must produce identical XER and JER output.
cmp "$test_directory/generated-def.xer" "$test_directory/generated-ext.xer"
cmp "$test_directory/generated-def.jer" "$test_directory/generated-ext.jer"

echo 'ext-ctx converter smoke test passed'
