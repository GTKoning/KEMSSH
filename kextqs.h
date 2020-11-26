/*
* Copyright 2018 Amazon.com, Inc. or its affiliates. All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
* 1. Redistributions of source code must retain the above copyright
* notice, this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright
* notice, this list of conditions and the following disclaimer in the
* documentation and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
* IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
* OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
* IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
* INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
* NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
* THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef KEX_TQS_H
#define KEX_TQS_H

#include "includes.h"

#ifdef WITH_TQS

#include "packet.h"
#include "tqs/tqs.h"
/*
#define PQ_OQS_NAMESPACE_SUFFIX "@openquantumsafe.org"
#define PQ_OQS_KEX_SUFFIX(X) X PQ_OQS_NAMESPACE_SUFFIX
*/
typedef enum tqs_client_or_server {
	TQS_IS_CLIENT,
	TQS_IS_SERVER
} tqs_client_or_server_t;

/*
 * State information needed for the libtqs part
 * of the hybrid key exchange
 */
typedef struct tqs_kex_ctx {

	TQS_KEM *tqs_kem;	/* libtqs KEM algorithm context */
	char *tqs_method;	/* libtqs algorithm name */
	uint8_t *tqs_local_priv;	/* Local private key */
	size_t tqs_local_priv_len;	/* Local private key length */
	uint8_t *tqs_local_msg;		/* Local message */
	size_t tqs_local_msg_len;	/* Local message length */
	uint8_t *tqs_remote_msg;	/* Remote message. */
	size_t tqs_remote_msg_len;	/* Remote message length */

} TQS_KEX_CTX;

/*
 * libtqs algorithm information and stores message names used
 * during the hybrid key exchange
 */
typedef struct tqs_alg {

	char *kex_alg; 					/* SSH kex exchange name */
	char *alg_name; 				/* libtqs algorithm name */
	int ssh2_init_msg; 				/* Msg number/name mapping */
	int ssh2_reply_msg; 			/* Msg number/name mapping */

} TQS_ALG;

/* Public client functions */
int tqs_client_gen(TQS_KEX_CTX *tqs_kex_ctx);
int tqs_client_extract(struct ssh *ssh, OQS_KEX_CTX *tqs_kex_ctx);
int tqs_client_shared_secret(TQS_KEX_CTX *tqs_kex_ctx,
	u_char **tqs_shared_secret, size_t *tqs_shared_secret_len);
/* Public server  fucntions */
int tqs_server_gen_msg_and_ss(TQS_KEX_CTX *tqs_kex_ctx,
	u_char **tqs_shared_secret, size_t *tqs_shared_secret_len);
/* Public shared functions */
int tqs_init(TQS_KEX_CTX **tqs_kex_ctx, char *ssh_kex_name);
void tqs_free(TQS_KEX_CTX *tqs_kex_ctx);
const TQS_ALG * tqs_mapping(const char *ssh_kex_name);
int tqs_ssh2_init_msg(const TQS_ALG *tqs_alg);
int tqs_ssh2_reply_msg(const TQS_ALG *tqs_alg);
int tqs_deserialise(struct ssh *ssh, TQS_KEX_CTX *tqs_kex_ctx,
	tqs_client_or_server_t client_or_server);
int tqs_serialise(struct ssh *ssh, TQS_KEX_CTX *tqs_kex_ctx,
	tqs_client_or_server_t client_or_server);

#endif /* WITH_TQS */
#endif /* KEX_TQS_H */
