//
// Created by tom on 13/11/2020.
//
#include "includes.h"

//#if defined(WITH_TQS) && defined(WITH_PQ_KEX)

#include "compat.h"
#include "ssherr.h"
#include "digest.h"
#include "ssh2.h"
#include "kexpq.h"
#include "sshbuf.h"
#include "log.h"

int
pq_tqs_init(PQ_KEX_CTX **pq_kex_ctx, char *pq_kex_name) {

	PQ_KEX_CTX *buf_pq_kex_ctx = NULL;
	OQS_KEX_CTX *buf_oqs_kex_ctx = NULL;
	int alloc_pq_kex_ctx = 1; /* (0) reuse PQ-only struct (1) allocated PQ-only struct */
	int r = 0;

	/*
	 * If rekeying is performed we don't want to allocate again.
	 * Memory pointed to by *pq_kex_ctx is not free'ed before
	 * the program terminates.
	 */
	if (*pq_kex_ctx != NULL) {
		alloc_pq_kex_ctx = 0;
		buf_pq_kex_ctx = *pq_kex_ctx;
	}

	if (alloc_pq_kex_ctx == 1) {
		if ((buf_pq_kex_ctx = calloc(sizeof(*(buf_pq_kex_ctx)), 1)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
	}

	buf_pq_kex_ctx->pq_kex_name = pq_kex_name;
	buf_pq_kex_ctx->oqs_kex_ctx = NULL;

	if ((r = tqs_init(&buf_oqs_kex_ctx, pq_kex_name)) != 0)
		goto out;

	buf_pq_kex_ctx->oqs_kex_ctx = buf_oqs_kex_ctx;
	buf_oqs_kex_ctx = NULL;
	*pq_kex_ctx = buf_pq_kex_ctx;
	buf_pq_kex_ctx = NULL;

out:
	if (buf_pq_kex_ctx != NULL) {
		if (buf_pq_kex_ctx->oqs_kex_ctx != NULL)
			tqs_free(buf_pq_kex_ctx->oqs_kex_ctx);
		/*
		 * If reusing, buf_pq_kex_ctx will point to the
		 * reused memory and this wil eventually be freed
		 * by kex_free()
		 */
		if (alloc_pq_kex_ctx == 1)
			free(buf_pq_kex_ctx);
	}
	if (buf_oqs_kex_ctx != NULL)
		tqs_free(buf_oqs_kex_ctx);

	return r;
}

void
pq_tqs_free(PQ_KEX_CTX *pq_kex_ctx) {

	if (pq_kex_ctx->oqs_kex_ctx != NULL) {
		tqs_free(pq_kex_ctx->oqs_kex_ctx);
		free(pq_kex_ctx->oqs_kex_ctx);
		pq_kex_ctx->oqs_kex_ctx = NULL;
	}
}

int
pq_tqs_hash (
	int hash_alg,
	const char *client_version_string,
	const char *server_version_string,
	const uint8_t *tqs_client_public, size_t tqs_client_public_len,
	const uint8_t *tqs_server_public, size_t tqs_server_public_len,
	const u_char *tqs_full_key, size_t tqs_fullkey_size,
	u_char *hash, size_t *hash_len) {
    u_char hash1[SSH_DIGEST_MAX_LENGTH];
    u_char hash2[SSH_DIGEST_MAX_LENGTH];

    error(" client ver string %s ", client_version_string);
    error(" server ver string %s ", server_version_string);
    error(" tqs_client_public %s ", tqs_client_public);
    error(" tqs_client_public_len %zu ", tqs_client_public_len);
    error(" tqs_server_public %s ", tqs_server_public);
    error(" tqs_server_public_len %zu ", tqs_server_public_len);
    error(" tqs_full_key is %s with size %zu", tqs_full_key, tqs_fullkey_size);

	struct sshbuf *hash_buf = NULL;
	int r = 0;
	if (*hash_len < ssh_digest_bytes(hash_alg)) {
	    error(" %d", ssh_digest_bytes(hash_alg));
	    error(" Gaat deze dan mis?");
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
    error(" Lukt alles nog een beetje?" );
	if ((hash_buf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
    error(" Lukt alles nog een beetje?1" );
	/* We assume that sshbuf_put_*() correctly handles NULL parameters */
	if ((r = sshbuf_put_cstring(hash_buf, client_version_string)) != 0 ||
	    (r = sshbuf_put_cstring(hash_buf, server_version_string)) != 0)
	    /* kexinit messages: fake header: len+SSH2_MSG_KEXINIT */
		goto out;
    error(" Lukt alles nog een beetje?2" );
	if ((r = sshbuf_put_string(hash_buf, tqs_client_public,
		tqs_client_public_len)) != 0 ||
	    (r = sshbuf_put_string(hash_buf, tqs_server_public,
	    tqs_server_public_len)) != 0 ||
	    (r = sshbuf_put_string(hash_buf, tqs_full_key, tqs_fullkey_size)) != 0)
		goto out;
    error(" Lukt alles nog een beetje?3" );
	if (ssh_digest_buffer(hash_alg, hash_buf, hash, *hash_len) != 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	error("lukt alles 4");

	*hash_len = ssh_digest_bytes(hash_alg);


out:
	if (hash_buf != NULL)
		sshbuf_free(hash_buf);

	return r;
}

//#endif /* defined(WITH_TQS) && defined(WITH_PQ_KEX) */
