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

#include "oqs/oqs.h"
#include "packet.h"


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

/* Public client functions */
int tqs_client_gen(OQS_KEX_CTX *oqs_kex_ctx);
int tqs_client_extract(struct ssh *ssh, OQS_KEX_CTX *oqs_kex_ctx);
int tqs_client_shared_secret(OQS_KEX_CTX *oqs_kex_ctx,
                             u_char **tqs_key_a, u_char **tqs_key_b, u_char **tqs_full_key, size_t *tqs_fullkey_size, size_t *tqs_halfkey_size, struct sshkey **server_host_key);
/* Public server  fucntions */
int tqs_server_gen_msg_and_ss(OQS_KEX_CTX *oqs_kex_ctx,
                              u_char **tqs_key_b, size_t *tqs_key_size, u_char **oqs_shared_secret, size_t *oqs_shared_secret_len);
int tqs_server_gen_key_hmac(OQS_KEX_CTX *oqs_kex_ctx, u_char **tqs_full_key, size_t *tqs_fullkey_size);
/* Public shared functions */
int tqs_init(OQS_KEX_CTX **oqs_kex_ctx, char *ssh_kex_name);
void tqs_free(OQS_KEX_CTX *oqs_kex_ctx);
const OQS_ALG * tqs_mapping(const char *ssh_kex_name);
int tqs_ssh2_init_msg(const OQS_ALG *tqs_alg);
int tqs_ssh2_reply_msg(const OQS_ALG *tqs_alg);
int tqs_ssh2_verreply_msg(const OQS_ALG *oqs_alg);
int tqs_ssh2_verinit_msg(const OQS_ALG *oqs_alg);
int tqs_ssh2_sendct_msg(const OQS_ALG *oqs_alg);
int tqs_deserialise(struct ssh *ssh, OQS_KEX_CTX *oqs_kex_ctx,
	tqs_client_or_server_t client_or_server);
int tqs_deserialise2(struct ssh *ssh, OQS_KEX_CTX *oqs_kex_ctx,
                    tqs_client_or_server_t client_or_server);
int tqs_deserialisever(struct ssh *ssh, OQS_KEX_CTX *oqs_kex_ctx, enum tqs_client_or_server client_or_server);
int tqs_serialise(struct ssh *ssh, OQS_KEX_CTX *oqs_kex_ctx,
	tqs_client_or_server_t client_or_server);
int tqs_serialisever(struct ssh *ssh, OQS_KEX_CTX *oqs_kex_ctx, enum tqs_client_or_server client_or_server);
int tqs_serialise2(struct ssh *ssh, OQS_KEX_CTX *oqs_kex_ctx,
                  tqs_client_or_server_t client_or_server);
#endif /* KEX_TQS_H */
