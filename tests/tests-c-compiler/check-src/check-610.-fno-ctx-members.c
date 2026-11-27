/*
 * check-610.-fno-ctx-members.c
 *
 * Regression for the external decode context (issue #15, Phases 0-4):
 * the module is generated with -fno-ctx-members, so NetMsg_t has no embedded
 * _asn_ctx member; decoding must go through the *_decode_ctx() entry points
 * with a caller-owned asn_struct_external_ctx_t arena, including across
 * RC_WMORE chunk boundaries. Plain entry points must fail cleanly (RC_FAIL)
 * on such code for the resumable codecs (BER/CER, XER, JER, OER); PER and
 * CBOR never consult the embedded context at decode time, so their plain
 * entry points keep working. ASN_STRUCT_RESET_CTX() must make the struct
 * re-decodable.
 */
#undef	NDEBUG
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <NetMsg.h>
#include <Wrap.h>
#include <asn_application.h>
#include <der_encoder.h>
#include <ber_decoder.h>
#include <xer_decoder.h>
#include <jer_decoder.h>
#include <oer_decoder.h>
#include <uper_decoder.h>
#include <aper_decoder.h>
#include <cbor_decoder.h>

typedef asn_dec_rval_t (*decode_ctx_fn)(asn_struct_external_ctx_t *ext,
		void **msg, const uint8_t *buf, size_t n);

static asn_dec_rval_t
fn_ber(asn_struct_external_ctx_t *ext, void **msg, const uint8_t *buf, size_t n) {
	return ber_decode_ctx(0, &asn_DEF_NetMsg, msg, ext, buf, n);
}
static asn_dec_rval_t
fn_ber_wrap(asn_struct_external_ctx_t *ext, void **msg, const uint8_t *buf, size_t n) {
	return ber_decode_ctx(0, &asn_DEF_Wrap, msg, ext, buf, n);
}
static asn_dec_rval_t
fn_xer(asn_struct_external_ctx_t *ext, void **msg, const uint8_t *buf, size_t n) {
	return xer_decode_ctx(0, &asn_DEF_NetMsg, msg, ext, buf, n);
}
static asn_dec_rval_t
fn_jer(asn_struct_external_ctx_t *ext, void **msg, const uint8_t *buf, size_t n) {
	return jer_decode_ctx(0, &asn_DEF_NetMsg, msg, ext, buf, n);
}

static uint8_t enc_buf[2048];
static size_t enc_len;
static int
enc_cb(const void *buf, size_t size, void *key) {
	(void)key;
	if(enc_len + size > sizeof(enc_buf)) return -1;
	memcpy(enc_buf + enc_len, buf, size);
	enc_len += size;
	return 0;
}
static ssize_t
encode_with(enum asn_transfer_syntax ats, const NetMsg_t *m) {
	enc_len = 0;
	asn_enc_rval_t er = asn_encode(0, ats, &asn_DEF_NetMsg, m, enc_cb, 0);
	if(er.encoded == (ssize_t)-1) return -1;
	return (ssize_t)enc_len;
}

/* Feed the encoded PDU in `chunk`-sized pieces, resuming on RC_WMORE. */
static int
decode_chunked(decode_ctx_fn fn, asn_struct_external_ctx_t *ext,
		const uint8_t *buf, size_t len, size_t chunk, int allow_trailing,
		void **out) {
	void *msg = NULL;
	uint8_t pend[2048];
	size_t plen = 0, off = 0;
	for(;;) {
		while(plen < sizeof(pend) && off < len) {
			size_t n = len - off;
			if(n > chunk) n = chunk;
			memcpy(pend + plen, buf + off, n);
			plen += n; off += n;
		}
		if(plen == 0) return -3;
		asn_dec_rval_t dr = fn(ext, &msg, pend, plen);
		if(dr.consumed > plen) return -4;
		memmove(pend, pend + dr.consumed, plen - dr.consumed);
		plen -= dr.consumed;
		if(dr.code == RC_OK) {
			*out = msg;
			if(plen != 0 && !allow_trailing) return -2;
			return 0;
		}
		if(dr.code == RC_WMORE) {
			if(off >= len) return -3;	/* truncated */
			continue;
		}
		return -1;
	}
}

static int
check(const NetMsg_t *m) {
	if(!m) return 1;
	if(m->id != 42) return 2;
	if(m->body.present != body_PR_worldRequest) return 3;
	if(m->body.choice.worldRequest.x != 7) return 4;
	if(m->body.choice.worldRequest.flag == 0) return 5;
	return 0;
}

int
main(int ac, char **av) {
	uint8_t buf[256];
	NetMsg_t src;
	NetMsg_t *dec = NULL;
	asn_struct_external_ctx_t ext;
	int rc;

	(void)ac; (void)av;

	memset(&src, 0, sizeof(src));
	src.id = 42;
	src.body.present = body_PR_worldRequest;
	src.body.choice.worldRequest.x = 7;
	src.body.choice.worldRequest.flag = 1;

	asn_enc_rval_t er = der_encode_to_buffer(&asn_DEF_NetMsg, &src, buf, sizeof(buf));
	if(er.encoded == (ssize_t)-1) { printf("ENCODE FAIL\n"); return 1; }
	printf("encoded %zd bytes, sizeof(NetMsg_t)=%zu\n",
		(ssize_t)er.encoded, sizeof(NetMsg_t));
#ifdef ASN_CTX_OFFSET_EXTERNAL
	assert(sizeof(NetMsg_t) < 64);	/* no embedded 24-byte ctx members */
#endif

	/* Contract: plain ber_decode() cannot resume -fno-ctx-members code. */
	{
		NetMsg_t *m2 = NULL;
		asn_dec_rval_t dr = ber_decode(0, &asn_DEF_NetMsg, (void **)&m2, buf, er.encoded);
		printf("plain ber_decode on ext code: code=%d (expect %d)\n", dr.code, RC_FAIL);
		if(dr.code != RC_FAIL) return 1;
		if(m2) ASN_STRUCT_FREE(asn_DEF_NetMsg, m2);
	}

	/* Full-buffer decode through the external arena. */
	memset(&ext, 0, sizeof(ext));
	rc = fn_ber(&ext, (void **)&dec, buf, er.encoded).code == RC_OK ? 0 : -1;
	if(rc == 0) rc = check(dec);
	printf("full-buffer ber_decode_ctx: %s (rc=%d)\n", rc == 0 ? "PASS" : "FAIL", rc);
	if(rc) return 1;
	ASN_STRUCT_FREE_CTX(asn_DEF_NetMsg, dec, &ext);	/* also resets the arena */
	dec = NULL;
	rc = decode_chunked(fn_ber, &ext, buf, er.encoded, 1, 0, (void **)&dec);
	if(rc == 0) rc = check(dec);
	printf("chunked(1B) ber_decode_ctx: %s (rc=%d)\n", rc == 0 ? "PASS" : "FAIL", rc);
	if(rc) return 1;

	ASN_STRUCT_FREE_CTX(asn_DEF_NetMsg, dec, &ext);
	dec = NULL;
	rc = decode_chunked(fn_ber, &ext, buf, er.encoded, 3, 0, (void **)&dec);
	if(rc == 0) rc = check(dec);
	printf("chunked(3B) ber_decode_ctx: %s (rc=%d)\n", rc == 0 ? "PASS" : "FAIL", rc);
	if(rc) return 1;

	/* Re-decode into the same struct after ASN_STRUCT_RESET_CTX. */
	ASN_STRUCT_RESET_CTX(asn_DEF_NetMsg, dec, &ext);
	{
		asn_dec_rval_t dr = ber_decode_ctx(0, &asn_DEF_NetMsg, (void **)&dec,
				&ext, buf, er.encoded);
		printf("redecode after RESET_CTX: %s (code=%d)\n",
			dr.code == RC_OK ? "PASS" : "FAIL", dr.code);
		if(dr.code != RC_OK || check(dec)) return 1;
	}
	ASN_STRUCT_FREE_CTX(asn_DEF_NetMsg, dec, &ext);
	dec = NULL;

	/* Every codec through the generic asn_decode_ctx() dispatcher. */
	{
		struct { const char *name; enum asn_transfer_syntax ats; } codecs[] = {
			{"BER", ATS_BER}, {"XER", ATS_BASIC_XER}, {"JER", ATS_JER},
			{"OER", ATS_BASIC_OER}, {"UPER", ATS_UNALIGNED_BASIC_PER},
			{"APER", ATS_ALIGNED_BASIC_PER}, {"CBOR", ATS_CBOR},
		};
		for(unsigned i = 0; i < sizeof(codecs)/sizeof(codecs[0]); i++) {
			ssize_t n = encode_with(codecs[i].ats, &src);
			if(n < 0) { printf("%s: ENCODE FAIL\n", codecs[i].name); return 1; }
			memset(&ext, 0, sizeof(ext));
			NetMsg_t *m = NULL;
			asn_dec_rval_t dr = asn_decode_ctx(0, codecs[i].ats,
				&asn_DEF_NetMsg, (void **)&m, &ext, enc_buf, (size_t)n);
			rc = (dr.code == RC_OK) ? check(m) : -1;
			printf("%s: asn_decode_ctx full: %s (code=%d rc=%d)\n",
				codecs[i].name, rc == 0 ? "PASS" : "FAIL", dr.code, rc);
			if(rc) return 1;
			if(m) ASN_STRUCT_FREE_CTX(asn_DEF_NetMsg, m, &ext);
		}
	}

	/* Per-codec _ctx entry points; XER/JER also chunked (RC_WMORE resume). */
	{
		ssize_t n = encode_with(ATS_BASIC_XER, &src);
		if(n < 0) return 1;
		memset(&ext, 0, sizeof(ext));
		NetMsg_t *m = NULL;
		asn_dec_rval_t dr = xer_decode_ctx(0, &asn_DEF_NetMsg, (void **)&m, &ext, enc_buf, (size_t)n);
		rc = (dr.code == RC_OK) ? check(m) : -1;
		printf("xer_decode_ctx full: %s (code=%d rc=%d)\n", rc == 0 ? "PASS" : "FAIL", dr.code, rc);
		if(rc) return 1;
		if(m) ASN_STRUCT_FREE_CTX(asn_DEF_NetMsg, m, &ext);
		m = NULL;
		rc = decode_chunked(fn_xer, &ext, enc_buf, (size_t)n, 1, 1, (void **)&m);
		if(rc == 0) rc = check(m);
		printf("chunked(1B) xer_decode_ctx: %s (rc=%d)\n", rc == 0 ? "PASS" : "FAIL", rc);
		if(rc) return 1;
		if(m) ASN_STRUCT_FREE_CTX(asn_DEF_NetMsg, m, &ext);
		/* plain xer_decode cannot resume -fno-ctx-members code */
		m = NULL;
		dr = xer_decode(0, &asn_DEF_NetMsg, (void **)&m, enc_buf, (size_t)n);
		printf("plain xer_decode on ext code: code=%d (expect %d)\n", dr.code, RC_FAIL);
		if(dr.code != RC_FAIL) return 1;
		if(m) ASN_STRUCT_FREE(asn_DEF_NetMsg, m);
	}
	{
		ssize_t n = encode_with(ATS_JER, &src);
		if(n < 0) return 1;
		memset(&ext, 0, sizeof(ext));
		NetMsg_t *m = NULL;
		asn_dec_rval_t dr = jer_decode_ctx(0, &asn_DEF_NetMsg, (void **)&m, &ext, enc_buf, (size_t)n);
		rc = (dr.code == RC_OK) ? check(m) : -1;
		printf("jer_decode_ctx full: %s (code=%d rc=%d)\n", rc == 0 ? "PASS" : "FAIL", dr.code, rc);
		if(rc) return 1;
		if(m) ASN_STRUCT_FREE_CTX(asn_DEF_NetMsg, m, &ext);
		m = NULL;
		rc = decode_chunked(fn_jer, &ext, enc_buf, (size_t)n, 1, 1, (void **)&m);
		if(rc == 0) rc = check(m);
		printf("chunked(1B) jer_decode_ctx: %s (rc=%d)\n", rc == 0 ? "PASS" : "FAIL", rc);
		if(rc) return 1;
		if(m) ASN_STRUCT_FREE_CTX(asn_DEF_NetMsg, m, &ext);
		m = NULL;
		dr = jer_decode(0, &asn_DEF_NetMsg, (void **)&m, enc_buf, (size_t)n);
		printf("plain jer_decode on ext code: code=%d (expect %d)\n", dr.code, RC_FAIL);
		if(dr.code != RC_FAIL) return 1;
		if(m) ASN_STRUCT_FREE(asn_DEF_NetMsg, m);
	}
	{
		ssize_t n = encode_with(ATS_BASIC_OER, &src);
		if(n < 0) return 1;
		memset(&ext, 0, sizeof(ext));
		NetMsg_t *m = NULL;
		asn_dec_rval_t dr = oer_decode_ctx(0, &asn_DEF_NetMsg, (void **)&m, &ext, enc_buf, (size_t)n);
		rc = (dr.code == RC_OK) ? check(m) : -1;
		printf("oer_decode_ctx full: %s (code=%d rc=%d)\n", rc == 0 ? "PASS" : "FAIL", dr.code, rc);
		if(rc) return 1;
		if(m) ASN_STRUCT_FREE_CTX(asn_DEF_NetMsg, m, &ext);
		m = NULL;
		dr = oer_decode(0, &asn_DEF_NetMsg, (void **)&m, enc_buf, (size_t)n);
		printf("plain oer_decode on ext code: code=%d (expect %d)\n", dr.code, RC_FAIL);
		if(dr.code != RC_FAIL) return 1;
		if(m) ASN_STRUCT_FREE(asn_DEF_NetMsg, m);
	}
	{
		ssize_t n = encode_with(ATS_UNALIGNED_BASIC_PER, &src);
		if(n < 0) return 1;
		memset(&ext, 0, sizeof(ext));
		NetMsg_t *m = NULL;
		asn_dec_rval_t dr = uper_decode_ctx(0, &asn_DEF_NetMsg, (void **)&m, &ext,
			enc_buf, (size_t)n, 0, 0);
		rc = (dr.code == RC_OK) ? check(m) : -1;
		printf("uper_decode_ctx: %s (code=%d bits=%zu rc=%d)\n",
			rc == 0 ? "PASS" : "FAIL", dr.code, dr.consumed, rc);
		if(rc) return 1;
		if(m) ASN_STRUCT_FREE_CTX(asn_DEF_NetMsg, m, &ext);
	}
	{
		ssize_t n = encode_with(ATS_ALIGNED_BASIC_PER, &src);
		if(n < 0) return 1;
		memset(&ext, 0, sizeof(ext));
		NetMsg_t *m = NULL;
		asn_dec_rval_t dr = aper_decode_ctx(0, &asn_DEF_NetMsg, (void **)&m, &ext,
			enc_buf, (size_t)n, 0, 0);
		rc = (dr.code == RC_OK) ? check(m) : -1;
		printf("aper_decode_ctx: %s (code=%d bits=%zu rc=%d)\n",
			rc == 0 ? "PASS" : "FAIL", dr.code, dr.consumed, rc);
		if(rc) return 1;
		if(m) ASN_STRUCT_FREE_CTX(asn_DEF_NetMsg, m, &ext);
	}
	{
		ssize_t n = encode_with(ATS_CBOR, &src);
		if(n < 0) return 1;
		memset(&ext, 0, sizeof(ext));
		NetMsg_t *m = NULL;
		asn_dec_rval_t dr = cbor_decode_ctx(0, &asn_DEF_NetMsg, (void **)&m, &ext, enc_buf, (size_t)n);
		rc = (dr.code == RC_OK) ? check(m) : -1;
		printf("cbor_decode_ctx full: %s (code=%d rc=%d)\n", rc == 0 ? "PASS" : "FAIL", dr.code, rc);
		if(rc) return 1;
		if(m) ASN_STRUCT_FREE_CTX(asn_DEF_NetMsg, m, &ext);
	}

	/* Aliasing regression: Wrap.only is inline at offset 0, so the child
	   structure shares the parent's base address; arena frames are keyed by
	   (struct address, type specifics), not address alone. */
	{
		uint8_t wbuf[64];
		Wrap_t wsrc;
		memset(&wsrc, 0, sizeof(wsrc));
		wsrc.only.v = 99;
		asn_enc_rval_t wer = der_encode_to_buffer(&asn_DEF_Wrap, &wsrc,
			wbuf, sizeof(wbuf));
		if(wer.encoded == (ssize_t)-1) { printf("WRAP ENCODE FAIL\n"); return 1; }
		memset(&ext, 0, sizeof(ext));
		Wrap_t *w = NULL;
		asn_dec_rval_t dr = ber_decode_ctx(0, &asn_DEF_Wrap, (void **)&w,
			&ext, wbuf, (size_t)wer.encoded);
		rc = (dr.code == RC_OK && w && w->only.v == 99) ? 0 : -1;
		printf("wrap ber_decode_ctx full: %s (code=%d rc=%d)\n",
			rc == 0 ? "PASS" : "FAIL", dr.code, rc);
		if(rc) return 1;
		if(w) ASN_STRUCT_FREE_CTX(asn_DEF_Wrap, w, &ext);
		w = NULL;
		rc = decode_chunked(fn_ber_wrap, &ext, wbuf, (size_t)wer.encoded, 1, 0,
			(void **)&w);
		if(rc == 0) rc = (w && ((Wrap_t *)w)->only.v == 99) ? 0 : -1;
		printf("wrap chunked(1B) ber_decode_ctx: %s (rc=%d)\n",
			rc == 0 ? "PASS" : "FAIL", rc);
		if(rc) return 1;
		if(w) ASN_STRUCT_FREE_CTX(asn_DEF_Wrap, w, &ext);
	}

	printf("ALL PASS\n");
	return 0;
}
