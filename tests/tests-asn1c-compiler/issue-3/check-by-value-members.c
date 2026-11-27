/*
 * Purpose: prove by-value members and pointer recursion coexist correctly.
 * Original source: issue #3 (pointer members for non-recursive references).
 * Version/date: 1.0, 2026-11-27.
 * Parameters: none.
 * Returns: zero when the embedded Leaf member round-trips through DER/BER.
 * Errors: failed assertions terminate the test with a nonzero status.
 * Responsible party: asn1c maintainers.
 * History: added for the dedicated issue #3 regression coverage.
 * Example: run from check-issue-3-by-value-members.sh after code generation.
 */

#include <asn_application.h>
#include <string.h>

#include "Tree.h"

static int
check_by_value_roundtrip(void) {
    static const uint8_t expected_der[] = {
        0x30, 0x0b, 0x30, 0x03, 0x02, 0x01, 0x07,
        0x16, 0x04, 'l', 'e', 'a', 'f',
    };
    Tree_t tree = {.root = {.value = 7},
                   .label = {.buf = (uint8_t *)"leaf", .size = 4}};
    Tree_t *decoded = NULL;
    uint8_t buf[64];
    asn_enc_rval_t enc;
    asn_dec_rval_t dec;
    int failed = 0;

    /* The non-recursive reference member must be embedded, not a pointer. */
    if(sizeof(((Tree_t *)0)->root) != sizeof(Leaf_t)) return 1;

    enc = asn_encode_to_buffer(NULL, ATS_DER, &asn_DEF_Tree, &tree, buf,
                               sizeof(buf));
    if(enc.encoded < 0 || (size_t)enc.encoded != sizeof(expected_der)
       || memcmp(buf, expected_der, sizeof(expected_der))) {
        fprintf(stderr, "FAIL: Tree DER mismatch (%zd bytes)\n", enc.encoded);
        return 1;
    }

    dec = asn_decode(NULL, ATS_BER, &asn_DEF_Tree, (void **)&decoded,
                     expected_der, sizeof(expected_der));
    if(dec.code != RC_OK || dec.consumed != sizeof(expected_der)) {
        fprintf(stderr, "FAIL: Tree BER decode status=%d consumed=%zu\n",
                dec.code, dec.consumed);
        failed = 1;
    } else if(decoded->root.value != 7 || decoded->label.size != 4
              || memcmp(decoded->label.buf, "leaf", 4)) {
        fprintf(stderr, "FAIL: Tree decoded values differ\n");
        failed = 1;
    }
    if(decoded) ASN_STRUCT_FREE(asn_DEF_Tree, decoded);
    return failed;
}

int
main(void) {
    if(check_by_value_roundtrip()) return 1;
    printf("PASS: issue #3 by-value member DER/BER round-trip\n");
    return 0;
}
