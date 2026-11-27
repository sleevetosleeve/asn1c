/*
 * Purpose: verify float-mapped REAL members use their per-field descriptor.
 * Original source: issue #5 (member table referenced asn_DEF_REAL for floats).
 * Version/date: 1.0, 2026-11-27.
 * Parameters: none.
 * Returns: zero when the C float members round-trip through DER/BER exactly.
 * Errors: failed assertions terminate the test with a nonzero status.
 * Responsible party: asn1c maintainers.
 * History: added for the dedicated issue #5 regression coverage.
 * Example: run from check-issue-5-float-real-members.sh after generation.
 */

#include <asn_application.h>
#include <string.h>

#include "Vec3.h"

int
main(void) {
    /* Binary base-2 REALs: 1.5 == 3 * 2^-1, -0.25 == -1 * 2^-2. */
    static const uint8_t expected_der[] = {
        0x30, 0x0a, 0x09, 0x03, 0x80, 0xff, 0x03,
        0x09, 0x03, 0xc0, 0xfe, 0x01,
    };
    Vec3_t value = {.x = 1.5, .y = -0.25};
    Vec3_t *decoded = NULL;
    uint8_t buf[64];
    asn_enc_rval_t enc;
    asn_dec_rval_t dec;
    int failed = 0;

    /* The narrowing must produce C float members, not wide REAL_t. */
    if(sizeof(value.x) != sizeof(float) || sizeof(value.y) != sizeof(float))
        return 1;

    /* The per-field descriptor must drive encoding with the float width. */
    enc = asn_encode_to_buffer(NULL, ATS_DER, &asn_DEF_Vec3, &value, buf,
                               sizeof(buf));
    if(enc.encoded < 0 || (size_t)enc.encoded != sizeof(expected_der)
       || memcmp(buf, expected_der, sizeof(expected_der))) {
        fprintf(stderr, "FAIL: Vec3 DER mismatch (%zd bytes)\n", enc.encoded);
        return 1;
    }

    /* Decoding must write into the float fields via the same descriptor. */
    dec = asn_decode(NULL, ATS_BER, &asn_DEF_Vec3, (void **)&decoded,
                     expected_der, sizeof(expected_der));
    if(dec.code != RC_OK || dec.consumed != sizeof(expected_der)) {
        fprintf(stderr, "FAIL: Vec3 BER decode status=%d consumed=%zu\n",
                dec.code, dec.consumed);
        failed = 1;
    } else if(decoded->x != 1.5 || decoded->y != -0.25) {
        fprintf(stderr, "FAIL: Vec3 decoded float values differ\n");
        failed = 1;
    }
    /* Freeing must walk the float layout, not the wide REAL_t union. */
    if(decoded) ASN_STRUCT_FREE(asn_DEF_Vec3, decoded);
    if(failed) return 1;
    printf("PASS: issue #5 float REAL member descriptor round-trip\n");
    return 0;
}
