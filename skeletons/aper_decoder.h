/*-
 * Copyright (c) 2005-2017 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#ifndef	_APER_DECODER_H_
#define	_APER_DECODER_H_

#include <asn_application.h>
#include <aper_support.h>

#ifdef __cplusplus
extern "C" {
#endif

struct asn_TYPE_descriptor_s;	/* Forward declaration */

/*
 * Aligned PER decoder of a "complete encoding" as per X.691#10.1.
 * On success, this call always returns (.consumed >= 1), in BITS, as per X.691#10.1.3.
 */
asn_dec_rval_t aper_decode_complete(
       const struct asn_codec_ctx_s *opt_codec_ctx,
       const struct asn_TYPE_descriptor_s *type_descriptor,	/* Type to decode */
       void **struct_ptr,	/* Pointer to a target structure's pointer */
       const void *buffer,	/* Data to be decoded */
       size_t size		/* Size of data buffer */
									);

/*
 * Aligned PER decoder of any ASN.1 type. May be invoked by the application.
 * WARNING: This call returns the number of BITS read from the stream. Beware.
 */
asn_dec_rval_t aper_decode(
      const struct asn_codec_ctx_s *opt_codec_ctx,
      const struct asn_TYPE_descriptor_s *type_descriptor,	/* Type to decode */
      void **struct_ptr,	/* Pointer to a target structure's pointer */
      const void *buffer,	/* Data to be decoded */
      size_t size,		/* Size of data buffer */
      int skip_bits,		/* Number of unused leading bits, 0..7 */
      int unused_bits		/* Number of unused tailing bits, 0..7 */
      );

/*
 * Variant of aper_decode() for code generated with -fno-ctx-members:
 * parsing contexts live in the caller-owned external arena ext_ctx instead
 * of embedded _asn_ctx members. Zero-initialize the arena once, pass it on
 * every call, and reset it with asn_struct_external_ctx_reset() before
 * decoding fresh data into the same structures. Passing NULL for ext_ctx
 * behaves like aper_decode().
 * WARNING: Like aper_decode(), this call returns the number of BITS read.
 */
asn_dec_rval_t aper_decode_ctx(
      const struct asn_codec_ctx_s *opt_codec_ctx,
      const struct asn_TYPE_descriptor_s *type_descriptor,	/* Type to decode */
      void **struct_ptr,	/* Pointer to a target structure's pointer */
      struct asn_struct_external_ctx_s *ext_ctx,	/* External parsing-context arena */
      const void *buffer,	/* Data to be decoded */
      size_t size,		/* Size of data buffer */
      int skip_bits,		/* Number of unused leading bits, 0..7 */
      int unused_bits		/* Number of unused tailing bits, 0..7 */
      );

#ifdef __cplusplus
}
#endif

#endif	/* _APER_DECODER_H_ */
