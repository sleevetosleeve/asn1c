/*
 * check-610.c
 *
 * Default-mode companion of check-610.-fno-ctx-members.c: same module
 * (610-ext-ctx-ber.asn1) generated WITHOUT -fno-ctx-members, so NetMsg_t
 * keeps its embedded _asn_ctx members and plain ber_decode() chunked
 * decoding must keep working (embedded-ctx regression).
 */
#undef	NDEBUG
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <NetMsg.h>
#include <der_encoder.h>
#include <ber_decoder.h>

static int
decode_chunked(const uint8_t *buf, size_t len, size_t chunk, NetMsg_t **out) {
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
		asn_dec_rval_t dr = ber_decode(0, &asn_DEF_NetMsg, (void **)&msg, pend, plen);
		if(dr.consumed > plen) return -4;
		memmove(pend, pend + dr.consumed, plen - dr.consumed);
		plen -= dr.consumed;
		if(dr.code == RC_OK) {
			if(plen != 0) return -2;
			*out = msg;
			return 0;
		}
		if(dr.code == RC_WMORE) {
			if(off >= len) return -3;
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
	assert(sizeof(NetMsg_t) >= 64);	/* embedded ctx members present */

	rc = ber_decode(0, &asn_DEF_NetMsg, (void **)&dec, buf, er.encoded).code == RC_OK ? 0 : -1;
	if(rc == 0) rc = check(dec);
	printf("full-buffer ber_decode: %s (rc=%d)\n", rc == 0 ? "PASS" : "FAIL", rc);
	if(rc) return 1;
	ASN_STRUCT_FREE(asn_DEF_NetMsg, dec);
	dec = NULL;

	rc = decode_chunked(buf, er.encoded, 1, &dec);
	if(rc == 0) rc = check(dec);
	printf("chunked(1B) ber_decode: %s (rc=%d)\n", rc == 0 ? "PASS" : "FAIL", rc);
	if(rc) return 1;
	ASN_STRUCT_FREE(asn_DEF_NetMsg, dec);

	dec = NULL;
	rc = decode_chunked(buf, er.encoded, 3, &dec);
	if(rc == 0) rc = check(dec);
	printf("chunked(3B) ber_decode: %s (rc=%d)\n", rc == 0 ? "PASS" : "FAIL", rc);
	if(rc) return 1;

	ASN_STRUCT_FREE(asn_DEF_NetMsg, dec);
	printf("ALL PASS\n");
	return 0;
}
