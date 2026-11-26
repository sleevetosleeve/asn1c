/*-
 * Copyright (c) 2003, 2004 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <constr_TYPE.h>
#include <asn_application.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

/*
 * Version of the ASN.1 infrastructure shipped with compiler.
 */
int get_asn1c_environment_version(void) { return ASN1C_ENVIRONMENT_VERSION; }

/*
 * External decode context arena (see constr_TYPE.h). One arena per top-level
 * decode operation; frames are keyed by the structure instance address so
 * that RC_WMORE resumes find the same frame again.
 */
asn_struct_ctx_t *asn_ext_ctx_get(asn_struct_external_ctx_t *ext, void *st) {
	size_t i;
	if(!ext || !st) return 0;
	for(i = 0; i < ext->frames_used && i < ASN_EXT_CTX_INLINE_FRAMES; i++)
		if(ext->inline_frames[i].st == st)
			return &ext->inline_frames[i].ctx;
	if(ext->frames_used > ASN_EXT_CTX_INLINE_FRAMES)
		for(i = ASN_EXT_CTX_INLINE_FRAMES; i < ext->frames_used; i++)
			if(ext->heap_frames[i - ASN_EXT_CTX_INLINE_FRAMES].st == st)
				return &ext->heap_frames[i - ASN_EXT_CTX_INLINE_FRAMES].ctx;
	if(ext->frames_used < ASN_EXT_CTX_INLINE_FRAMES) {
		asn_struct_ctx_frame_t *f = &ext->inline_frames[ext->frames_used++];
		f->st = st;
		memset(&f->ctx, 0, sizeof(f->ctx));
		return &f->ctx;
	}
	if(ext->frames_used - ASN_EXT_CTX_INLINE_FRAMES >= ext->heap_capacity) {
		size_t ncap = ext->heap_capacity ? ext->heap_capacity * 2 : 8;
		asn_struct_ctx_frame_t *nf = (asn_struct_ctx_frame_t *)
			realloc(ext->heap_frames, ncap * sizeof(*nf));
		if(!nf) return 0;
		ext->heap_frames = nf;
		ext->heap_capacity = ncap;
	}
	{
		asn_struct_ctx_frame_t *f =
			&ext->heap_frames[ext->frames_used - ASN_EXT_CTX_INLINE_FRAMES];
		ext->frames_used++;
		f->st = st;
		memset(&f->ctx, 0, sizeof(f->ctx));
		return &f->ctx;
	}
}


void asn_struct_external_ctx_reset(asn_struct_external_ctx_t *ext) {
	size_t i;
	if(!ext) return;
	for(i = 0; i < ext->frames_used && i < ASN_EXT_CTX_INLINE_FRAMES; i++)
		FREEMEM(ext->inline_frames[i].ctx.ptr);
	if(ext->frames_used > ASN_EXT_CTX_INLINE_FRAMES)
		for(i = ASN_EXT_CTX_INLINE_FRAMES; i < ext->frames_used; i++)
			FREEMEM(ext->heap_frames[i - ASN_EXT_CTX_INLINE_FRAMES].ctx.ptr);
	free(ext->heap_frames);
	memset(ext, 0, sizeof(*ext));
}

asn_struct_ctx_t *asn_get_struct_ctx(const asn_codec_ctx_t *opt_codec_ctx,
                                     void *st, unsigned ctx_offset) {
	if(opt_codec_ctx && opt_codec_ctx->ext_struct_ctx)
		return asn_ext_ctx_get(
			(asn_struct_external_ctx_t *)opt_codec_ctx->ext_struct_ctx, st);
	if(!st || ctx_offset == ASN_CTX_OFFSET_EXTERNAL) return 0;
	return (asn_struct_ctx_t *)((char *)st + ctx_offset);
}

static asn_app_consume_bytes_f _print2fp;

/*
 * Return the outmost tag of the type.
 */
ber_tlv_tag_t
asn_TYPE_outmost_tag(const asn_TYPE_descriptor_t *type_descriptor,
		const void *struct_ptr, int tag_mode, ber_tlv_tag_t tag) {

	if(tag_mode)
		return tag;

	if(type_descriptor->tags_count)
		return type_descriptor->tags[0];

	return type_descriptor->op->outmost_tag(type_descriptor, struct_ptr, 0, 0);
}

/*
 * Print the target language's structure in human readable form.
 */
int
asn_fprint(FILE *stream, const asn_TYPE_descriptor_t *td,
           const void *struct_ptr) {
    if(!stream) stream = stdout;
    if(!td || !struct_ptr) {
        errno = EINVAL;
        return -1;
	}

	/* Invoke type-specific printer */
    if(td->op->print_struct(td, struct_ptr, 1, _print2fp, stream)) {
        return -1;
    }

    /* Terminate the output */
    if(_print2fp("\n", 1, stream)) {
        return -1;
    }

    return fflush(stream);
}

/*
 * Copy a structuture.
 */
int
asn_copy(const asn_TYPE_descriptor_t *td,
         void **struct_dst, const void *struct_src) {

    if(!td || !struct_dst || !struct_src) {
        errno = EINVAL;
        return -1;
    }

    if(!td->op) {
        errno = ENOSYS;
        return -1;
    }
    
    return td->op->copy_struct(td, struct_dst, struct_src);
}

/* Dump the data into the specified stdio stream */
static int
_print2fp(const void *buffer, size_t size, void *app_key) {
	FILE *stream = (FILE *)app_key;

	if(fwrite(buffer, 1, size, stream) != size)
		return -1;

	return 0;
}


/*
 * Some compilers do not support variable args macros.
 * This function is a replacement of ASN_DEBUG() macro.
 */
void CC_PRINTFLIKE(1, 2) ASN_DEBUG_f(const char *fmt, ...);
void ASN_DEBUG_f(const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
}
