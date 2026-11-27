/*
 * Unit test for the external decode-context arena (issue #15):
 * asn_ext_ctx_get() frame allocation incl. heap overflow past the inline
 * capacity, frame reuse per structure instance, asn_struct_external_ctx_reset()
 * semantics, and the dual-path asn_get_struct_ctx() fetch (arena wins over the
 * embedded member when the codec context carries one; sentinel without arena
 * yields NULL).
 */
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <asn_application.h>
#include <asn_internal.h>

struct ext_ctx_probe_s { char pad[8]; asn_struct_ctx_t ctx; };

int
main(void) {
    asn_struct_external_ctx_t ext;
    char storage[16][64];
    asn_struct_ctx_t *frames[16];
    asn_codec_ctx_t codec_ctx;
    unsigned i;

    memset(&ext, 0, sizeof(ext));
    assert(ext.frames_used == 0 && ext.heap_frames == 0);

    /* Allocate more frames than the inline capacity: forces heap overflow. */
    for(i = 0; i < 16; i++) {
        frames[i] = asn_ext_ctx_get(&ext, storage[i], (const void *)(i + 1));
        assert(frames[i] != 0);
        assert(frames[i]->phase == 0 && frames[i]->step == 0
               && frames[i]->ptr == 0 && frames[i]->left == 0);
        frames[i]->phase = (short)(i + 1);
    }
    assert(ext.frames_used == 16);
    assert(ext.heap_frames != 0);	/* overflowed past ASN_EXT_CTX_INLINE_FRAMES */
    for(i = 0; i < 16; i++)
        assert(asn_ext_ctx_get(&ext, storage[i], (const void *)(i + 1))
               == frames[i]);	/* reuse */

    /* Aliasing regression: nested inline members share the base address of
       their parent (single-member SEQUENCE wrapper at offset 0), so frames
       must be discriminated by the type key, not just the address. */
    {
        asn_struct_ctx_t *outer = asn_ext_ctx_get(&ext, storage[0], (const void *)100);
        asn_struct_ctx_t *inner = asn_ext_ctx_get(&ext, storage[0], (const void *)200);
        assert(outer != 0 && inner != 0 && outer != inner);
        outer->phase = 1;
        assert(inner->phase == 0);	/* unaffected by the outer frame */
        assert(asn_ext_ctx_get(&ext, storage[0], (const void *)100) == outer);
        assert(asn_ext_ctx_get(&ext, storage[0], (const void *)200) == inner);
    }

    /* Reset releases the scratch of every frame and zeroes the arena. */
    frames[3]->ptr = malloc(32);
    assert(frames[3]->ptr != 0);
    asn_struct_external_ctx_reset(&ext);
    assert(ext.frames_used == 0 && ext.heap_frames == 0);
    frames[3] = asn_ext_ctx_get(&ext, storage[3], (const void *)4);
    assert(frames[3] != 0 && frames[3]->phase == 0 && frames[3]->ptr == 0);

    /* Dual-path fetch: embedded member when no arena is carried. */
    {
        struct ext_ctx_probe_s st;
        memset(&st, 0, sizeof(st));
        memset(&codec_ctx, 0, sizeof(codec_ctx));
        assert(asn_get_struct_ctx(&codec_ctx, &st,
               offsetof(struct ext_ctx_probe_s, ctx), &st) == &st.ctx);
        assert(asn_get_struct_ctx(0, &st,
               offsetof(struct ext_ctx_probe_s, ctx), &st) == &st.ctx);
        /* Sentinel offset without an arena cannot be resolved. */
        assert(asn_get_struct_ctx(&codec_ctx, &st, ASN_CTX_OFFSET_EXTERNAL, &st) == 0);
        assert(asn_get_struct_ctx(0, &st, ASN_CTX_OFFSET_EXTERNAL, &st) == 0);
        /* With an arena in the codec context, the arena wins, even for a
           structure that still has an embedded member. */
        codec_ctx.ext_struct_ctx = &ext;
        assert(asn_get_struct_ctx(&codec_ctx, &st,
               offsetof(struct ext_ctx_probe_s, ctx), (const void *)1)
               == asn_ext_ctx_get(&ext, &st, (const void *)1));
        assert(asn_get_struct_ctx(&codec_ctx, &st, ASN_CTX_OFFSET_EXTERNAL,
               (const void *)2)
               == asn_ext_ctx_get(&ext, &st, (const void *)2));
    }

    asn_struct_external_ctx_reset(&ext);
    printf("check-ext-ctx: all assertions passed\n");
    return 0;
}
