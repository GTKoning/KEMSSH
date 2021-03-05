#include "includes.h"

#if defined(WITH_OQS) && defined(WITH_PQ_KEX)

#include <signal.h>
#include <string.h>

#include "sshkey.h"
#include "digest.h"
#include "ssherr.h"
#include "kex.h"
#include "ssh2.h"
#include "dispatch.h"
#include "packet.h"
#include "sshbuf.h"
#include "log.h"
#include "hmac.h"

/* Server private */
static int
pq_tqs_c2s_deserialise(struct ssh *ssh, PQ_KEX_CTX *pq_kex_ctx);
static int
pq_tqs_s2c_serialise(struct ssh *ssh, PQ_KEX_CTX *pq_kex_ctx,
                     u_char *server_host_key_blob, size_t server_host_key_blob_len);
static int
pq_tqs_s2c_serialisever(struct ssh *ssh,
                        PQ_KEX_CTX *pq_kex_ctx);
static int
pq_tqs_server_hostkey(struct ssh *ssh, struct sshkey **server_host_public,
                      struct sshkey **server_host_private, u_char **server_host_key_blob,
                      size_t *server_host_key_blob_len);
static int
input_pq_tqs_init(int type, u_int32_t seq, struct ssh *ssh);
static int
input_pq_tqs_finish(int type, u_int32_t seq,
                    struct ssh *ssh);
static int
input_pq_tqs_verinit(int type, u_int32_t seq,
                     struct ssh *ssh);

/*
 * @brief Logic that handles packet deserialisation of the client kex message
 * when using a liboqs kex
 */
static int
pq_tqs_c2s_deserialise(struct ssh *ssh,
                       PQ_KEX_CTX *pq_kex_ctx) {

    int r = 0;
    if ((r = tqs_deserialise(ssh, pq_kex_ctx->oqs_kex_ctx, TQS_IS_SERVER) != 0)) {
        error(" this is r %i", r);
        goto out;
    }
    r = sshpkt_get_end(ssh);


    out:
    return r;
}

static int
pq_tqs_c2s_deserialisever(struct ssh *ssh, PQ_KEX_CTX *pq_kex_ctx){
    int r = 0;
    if ((r = tqs_deserialisever(ssh, pq_kex_ctx->oqs_kex_ctx, TQS_IS_SERVER) != 0))
        goto out;

    r = sshpkt_get_end(ssh);

    out:
    return r;
}

/*
 * @brief Logic that handles packet serialisation of the client kex message
 * when using a liboqs kex
 */
static int
pq_tqs_s2c_serialise(struct ssh *ssh,
                     PQ_KEX_CTX *pq_kex_ctx, u_char *server_host_key_blob,
                     size_t server_host_key_blob_len) {

    int r = 0;
    error(" Ik ben hier gekomen 1" );
    if ((r = sshpkt_put_string(ssh, server_host_key_blob,
                               server_host_key_blob_len)) != 0 ||
        (r = tqs_serialise(ssh, pq_kex_ctx->oqs_kex_ctx, TQS_IS_SERVER)) != 0){
        goto out;
    }
    error(" HERE IS THE PUBLIC KEY OF SERVER %s", ssh->kex->pq_kex_ctx->oqs_kex_ctx->oqs_local_msg);


    out:
    return r;
}
static int
pq_tqs_s2c_serialisever(struct ssh *ssh,
                     PQ_KEX_CTX *pq_kex_ctx){
    int r = 0;
    if ((r = sshpkt_put_string(ssh, pq_kex_ctx->oqs_kex_ctx->digestb,
                               pq_kex_ctx->oqs_kex_ctx->digestlen) != 0))
        goto out;
    out:
    return r;

}

/*
 * @brief Retrieves host key
 */
static int
pq_tqs_server_hostkey(struct ssh *ssh, struct sshkey **server_host_public,
                      struct sshkey **server_host_private, u_char **server_host_key_blob,
                      size_t *server_host_key_blob_len) {

    struct kex *kex = NULL;
    struct sshkey *tmp_server_host_public = NULL;
    struct sshkey *tmp_server_host_private = NULL;
    u_char *tmp_server_host_key_blob = NULL;
    size_t tmp_server_host_key_blob_len = 0;
    int r = 0;

    kex = ssh->kex;

    /* Retrieve host public and private key */
    if (kex->load_host_public_key == NULL ||
        kex->load_host_private_key == NULL) {
        r = SSH_ERR_INVALID_ARGUMENT;
        goto out;
    }
    if (((tmp_server_host_public = kex->load_host_public_key(kex->hostkey_type,
                                                             kex->hostkey_nid, ssh)) == NULL) ||
        (tmp_server_host_private = kex->load_host_private_key(kex->hostkey_type,
                                                              kex->hostkey_nid, ssh)) == NULL) {
        r = SSH_ERR_NO_HOSTKEY_LOADED;
        goto out;
    }

    /* Write to blob to prepare transfer over the wire */
    if ((r = sshkey_to_blob(tmp_server_host_public, &tmp_server_host_key_blob,
                            &tmp_server_host_key_blob_len)) != 0)
        goto out;

    *server_host_public = tmp_server_host_public;
    *server_host_private = tmp_server_host_private;
    *server_host_key_blob = tmp_server_host_key_blob;
    *server_host_key_blob_len = tmp_server_host_key_blob_len;
    kex->pq_kex_ctx->oqs_kex_ctx->blob = *server_host_key_blob;
    kex->pq_kex_ctx->oqs_kex_ctx->bloblen = *server_host_key_blob_len;

    tmp_server_host_public = NULL;
    tmp_server_host_private = NULL;
    tmp_server_host_key_blob = NULL;

    out:
    return r;
}

int
pq_tqs_server(struct ssh *ssh) {

    PQ_KEX_CTX *pq_kex_ctx = NULL;
    const OQS_ALG *oqs_alg = NULL;
    int r = 0;

    /* Test whether we are prepared to handle this packet */
    if (ssh == NULL ||
        ssh->kex == NULL ||
        (pq_kex_ctx = ssh->kex->pq_kex_ctx) == NULL) {
        r = SSH_ERR_INTERNAL_ERROR;
        goto out;
    }

    if ((oqs_alg = oqs_mapping(pq_kex_ctx->pq_kex_name)) == NULL) {
        error("Unsupported libOQS algorithm \"%.100s\"", pq_kex_ctx->pq_kex_name);
        r = SSH_ERR_INTERNAL_ERROR;
        goto out;
    }

    debug("expecting %i msg init tqs serverside", tqs_ssh2_init_msg(oqs_alg));
    ssh_dispatch_set(ssh, tqs_ssh2_init_msg(oqs_alg),
                     &input_pq_tqs_init);

    out:
    return r;
}

static int
input_pq_tqs_init(int type, u_int32_t seq,
                  struct ssh *ssh) {
    PQ_KEX_CTX *pq_kex_ctx = NULL;
    OQS_KEX_CTX *oqs_kex_ctx = NULL;
    const OQS_ALG *oqs_alg = NULL;
    struct kex *kex = NULL;
    struct sshkey *server_host_public = NULL;
    struct sshkey *server_host_private = NULL;
    struct sshbuf *shared_secret_ssh_buf = NULL;
    u_char *oqs_shared_secret = NULL;
    u_char *server_host_key_blob = NULL;
    size_t server_host_key_blob_len = 0;
    size_t oqs_shared_secret_len = 0;
    u_char *tqs_key_b = NULL;
    size_t tqs_halfkey_size = 0;


    int r = 0;

    /* Test whether we are prepared to handle this packet */
    if (ssh == NULL ||
        (kex = ssh->kex) == NULL ||
        (pq_kex_ctx = kex->pq_kex_ctx) == NULL ||
        (oqs_kex_ctx = pq_kex_ctx->oqs_kex_ctx) == NULL) {

        r = SSH_ERR_INTERNAL_ERROR;
        goto out;
    }


    /* Load public and private host key */
    if ((r = pq_tqs_server_hostkey(ssh, &server_host_public,
                                   &server_host_private, &server_host_key_blob,
                                   &server_host_key_blob_len)) != 0)
        goto out;
    /* Packet comes in */
    /* Deserialise client to server packet */
    /* Gets public key of client (and length) stored in remote_msg */
    if ((r = pq_tqs_c2s_deserialise(ssh, pq_kex_ctx)) != 0)
        goto out;
    /*
     * libOQS API only supports generating the liboqs public key
     * msg and shared secret simultaneously.
     */



    if ((r = tqs_server_gen_msg_and_ss(oqs_kex_ctx,
                                       &tqs_key_b, &tqs_halfkey_size, &oqs_shared_secret, &oqs_shared_secret_len)) != 0) {
        goto out;
    }



    // K_b, ct_b made.

    if ((oqs_alg = oqs_mapping(pq_kex_ctx->pq_kex_name)) == NULL) {
        error("Unsupported libOQS algorithm \"%.100s\"", pq_kex_ctx->pq_kex_name);
        error("This is not supposed to happen oqs_alg mapping failed");
        r = SSH_ERR_INTERNAL_ERROR;
        goto out;
    }
    // Need to send ct_b and pk_b -> use serialise 2 in s2c :)
    // Also, where is pk_b currently stored?
    // Now it makes sense! that's why the blobs are made.
    pq_kex_ctx->oqs_kex_ctx->tqs_ct_a_len = sizeof(pq_kex_ctx->oqs_kex_ctx->tqs_ct_a);
    if ((r = sshpkt_start(ssh, oqs_ssh2_reply_msg(oqs_alg))) != 0 ||
        (r = pq_tqs_s2c_serialise(ssh, pq_kex_ctx, server_host_key_blob,
                                  server_host_key_blob_len)) != 0 ||
        (r = sshpkt_send(ssh)) != 0)
        goto out;
    // Sent out ct_b and pk_b

    /*
     * sshbuf_put_string() will encode the shared secret as a mpint
     * as required by SSH spec (RFC4253)
     */
    // To do, figure out wtf they mean
    // Bij nieuwe functie aan het einde nodig -> verder gaan met de rest


    oqs_kex_ctx->oqs_local_priv = server_host_private->oqs_sk;

    // We are receiving ct_a -> to make our key with
    // BUT HOW
    ssh->kex->pq_kex_ctx = pq_kex_ctx;
    debug("expecting %i msg sendct", tqs_ssh2_sendct_msg(oqs_alg));
    ssh_dispatch_set(ssh, tqs_ssh2_sendct_msg(oqs_alg),
                     &input_pq_tqs_finish);

    out:
    pq_oqs_free(pq_kex_ctx);
    /* sshbuf_free zeroises memory */
    if (shared_secret_ssh_buf != NULL)
        sshbuf_free(shared_secret_ssh_buf);
    if (oqs_shared_secret != NULL) {
        explicit_bzero(oqs_shared_secret, oqs_shared_secret_len);
        free(oqs_shared_secret);
    }
    if (server_host_key_blob != NULL)
        free(server_host_key_blob);

    return r;
}

static int
input_pq_tqs_finish(int type, u_int32_t seq,
                  struct ssh *ssh) {
    const OQS_ALG *oqs_alg = NULL;
    u_char *tqs_full_key = NULL;
    size_t tqs_fullkey_size = 0;
    u_char hash[SSH_DIGEST_MAX_LENGTH];
    size_t hash_len = 0;
    struct kex *kex = NULL;
    struct sshbuf *shared_secret_ssh_buf = NULL;
    PQ_KEX_CTX *pq_kex_ctx = NULL;
    OQS_KEX_CTX *oqs_kex_ctx = NULL;

    int r = 0;

    if (ssh == NULL ||
        (kex = ssh->kex) == NULL ||
        (pq_kex_ctx = kex->pq_kex_ctx) == NULL ||
        (oqs_kex_ctx = pq_kex_ctx->oqs_kex_ctx) == NULL) {

        r = SSH_ERR_INTERNAL_ERROR;
        goto out;
    }


    if ((r = pq_tqs_c2s_deserialise(ssh, pq_kex_ctx)) != 0)
        goto out;
    // so we got ct_a now.
    // Time to create the shared key.

    tqs_server_gen_key_hmac(oqs_kex_ctx, &tqs_full_key, &tqs_fullkey_size);
    // shared key created
    hash_len = sizeof(hash);
    if ((r = pq_oqs_hash(
            kex->hash_alg,
            kex->client_version_string,
            kex->server_version_string,
            kex->peer,
            kex->my,
            oqs_kex_ctx->blob, oqs_kex_ctx->bloblen,
            oqs_kex_ctx->oqs_remote_msg, oqs_kex_ctx->oqs_remote_msg_len,
            oqs_kex_ctx->oqs_local_msg, oqs_kex_ctx->oqs_local_msg_len,
            tqs_full_key, tqs_fullkey_size,
            hash, &hash_len)) !=0)
        goto out;
    oqs_kex_ctx->hash = hash;
    oqs_kex_ctx->hash_len = hash_len;
    oqs_kex_ctx->tqs_full_key = tqs_full_key;
    oqs_kex_ctx->tqs_fullkey_size = tqs_fullkey_size;

    if ((shared_secret_ssh_buf = sshbuf_new()) == NULL) {
        r = SSH_ERR_ALLOC_FAIL;
        goto out;
    }

    if ((r = sshbuf_put_string(shared_secret_ssh_buf, (const u_char *) tqs_full_key,
                               tqs_fullkey_size)) != 0)
        goto out;

    if ((r = kex_derive_keys(ssh, hash, hash_len, shared_secret_ssh_buf)) == 0)
        r = kex_send_newkeys(ssh);

    /* Set handler for recieving client verification initiation */
    debug("expecting %i msg verinit", tqs_ssh2_verinit_msg(oqs_alg));
    ssh_dispatch_set(ssh, tqs_ssh2_verinit_msg(oqs_alg),
                     &input_pq_tqs_verinit);
    out:
    explicit_bzero(hash, sizeof(hash));
    pq_oqs_free(pq_kex_ctx);
    return r;
}

static int
input_pq_tqs_verinit(int type, u_int32_t seq,
                  struct ssh *ssh) {
    const OQS_ALG *oqs_alg = NULL;
    struct kex *kex = NULL;
    PQ_KEX_CTX *pq_kex_ctx = NULL;
    OQS_KEX_CTX *oqs_kex_ctx = NULL;
    struct ssh_hmac_ctx *hash_ctx = NULL;
    u_char digest[16];
    u_char *macmessage;

    int r = 0;

    if (ssh == NULL ||
        (kex = ssh->kex) == NULL ||
        (pq_kex_ctx = kex->pq_kex_ctx) == NULL ||
        (oqs_kex_ctx = pq_kex_ctx->oqs_kex_ctx) == NULL) {

        r = SSH_ERR_INTERNAL_ERROR;
        goto out;
    }

    if ((r = pq_tqs_c2s_deserialisever(ssh, pq_kex_ctx)) != 0)
        goto out;

    if((hash_ctx = ssh_hmac_start(SSH_DIGEST_SHA256)) == NULL) {
        printf("ssh_hmac_start failed");
        goto out;
    }
    uint8_t *tmp_macmessage = NULL;
    uint8_t *tmp_digesta = oqs_kex_ctx->digesta;
    uint8_t *tmp_hash = oqs_kex_ctx->hash;
    *tmp_macmessage = *tmp_digesta + *tmp_hash;
    macmessage = (u_char *) tmp_macmessage;

    if((ssh_hmac_init(hash_ctx, oqs_kex_ctx->tqs_full_key, oqs_kex_ctx->tqs_fullkey_size)) < 0 ||
       (ssh_hmac_update(hash_ctx, macmessage, sizeof(macmessage))) < 0 ||
       (ssh_hmac_final(hash_ctx, digest, sizeof(digest))) < 0) {
        printf("ssh_hmac_xxx failed");
        goto out;
    }
    oqs_kex_ctx->digestb = digest;

    if ((r = sshpkt_start(ssh, oqs_ssh2_reply_msg(oqs_alg))) != 0 ||
        (r = pq_tqs_s2c_serialisever(ssh, pq_kex_ctx)) != 0 ||
        (r = sshpkt_send(ssh)) != 0)
        goto out;

    out:
    ssh_hmac_free(hash_ctx);
    pq_oqs_free(pq_kex_ctx);
    return r;
}

#endif /* defined(WITH_OQS) && defined(WITH_PQ_KEX) */
