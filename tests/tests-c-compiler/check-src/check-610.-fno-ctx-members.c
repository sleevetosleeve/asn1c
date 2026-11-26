/*
 * check-610.-fno-ctx-members.c
 *
 * Regression for the external decode context (issue #15, Phase 0 BER/CER):
 * the module is generated with -fno-ctx-members, so NetMsg_t has no embedded
 * _asn_ctx member; decoding must go through ber_decode_ctx() with a
 * caller-owned asn_struct_external_ctx_t arena, including across RC_WMORE
 * chunk boundaries. Plain ber_decode() must fail cleanly (RC_FAIL) on such
 * code, and ASN_STRUCT_RESET_CTX() must make the struct re-decodable.
 */
#undef	NDEBUG
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <NetMsg.h>
#include <der_encoder.h>
#include <ber_decoder.h>

static asn_dec_rval_t
decode_once(NetMsg_t **msg, asn_struct_external_ctx_t *ext,
		const uint8_t *buf, size_t n) {
	return ber_decode_ctx(0, &asn_DEF_NetMsg, (void **)msg, ext, buf, n);
}

/* Feed the encoded PDU in `chunk`-sized pieces, resuming on RC_WMORE. */
static int
decode_chunked(const uint8_t *buf, size_t len, size_t chunk,
		asn_struct_external_ctx_t *ext, NetMsg_t **out) {
	NetMsg_t *msg = NULL;
	uint8_t pend[512];
	size_t plen = 0, off = 0;
	for(;;) {
		while(plen < sizeof(pend) && off < len) {
			size_t n = len - off;
			if(n > chunk) n = chunk;
			memcpy(pend + plen, buf + off, n);
			plen += n; off += n;
		}
		if(plen == 0) return -3;
		asn_dec_rval_t dr = decode_once(&msg, ext, pend, plen);
		if(dr.consumed > plen) return -4;
		memmove(pend, pend + dr.consumed, plen - dr.consumed);
		plen -= dr.consumed;
		if(dr.code == RC_OK) {
			if(plen != 0) return -2;
			*out = msg;
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
	rc = decode_once(&dec, &ext, buf, er.encoded).code == RC_OK ? 0 : -1;
	if(rc == 0) rc = check(dec);
	printf("full-buffer ber_decode_ctx: %s (rc=%d)\n", rc == 0 ? "PASS" : "FAIL", rc);
	if(rc) return 1;
	ASN_STRUCT_FREE_CTX(asn_DEF_NetMsg, dec, &ext);	/* also resets the arena */
	dec = NULL;
	rc = decode_chunked(buf, er.encoded, 1, &ext, &dec);
	if(rc == 0) rc = check(dec);
	printf("chunked(1B) ber_decode_ctx: %s (rc=%d)\n", rc == 0 ? "PASS" : "FAIL", rc);
	if(rc) return 1;

	ASN_STRUCT_FREE_CTX(asn_DEF_NetMsg, dec, &ext);
	dec = NULL;
	rc = decode_chunked(buf, er.encoded, 3, &ext, &dec);
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
	printf("ALL PASS\n");
	return 0;
}
