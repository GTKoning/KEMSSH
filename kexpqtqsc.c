#include "includes.h"

#if defined(WITH_OQS) && defined(WITH_PQ_KEX) // This is fine because if OQS is active, we have TQS active as well.
// But don't we have TQS active anyway? LI.

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

static int
input_pq_tqs_reply(int type, u_int32_t seq, struct ssh *ssh);
static int
pq_tqs_s2c_deserialise(struct ssh *ssh, PQ_KEX_CTX *pq_kex_ctx,
                       struct sshkey **server_host_key, u_char **server_host_key_blob,
                       size_t *server_host_key_blob_len);
static int
pq_tqs_s2c_deserialisever(struct ssh *ssh, PQ_KEX_CTX *pq_kex_ctx);
static int pq_tqs_verinit(int type, u_int32_t seq, struct ssh *ssh);
static int input_pq_tqs_verreply(int type, u_int32_t seq, struct ssh *ssh);
static int
pq_tqs_c2s_serialise(struct ssh *ssh, PQ_KEX_CTX *pq_kex_ctx);
static int
pq_tqs_verify_hostkey(struct ssh *ssh,
                      struct sshkey *server_host_key);
static int
pq_tqs_deserialise_hostkey(struct ssh *ssh, struct sshkey **server_host_key,
                           u_char **server_host_key_blob, size_t *server_host_key_blob_len);

static int
pq_tqs_s2c_deserialise(struct ssh *ssh, PQ_KEX_CTX *pq_kex_ctx,
                       struct sshkey **server_host_key, u_char **server_host_key_blob,
                       size_t *server_host_key_blob_len) {

    int r = 0;
    /*
     * pq_tqs_server_hostkey() immediately verify
     * the host key after extracting it
     */
    // They immediately verify host key after getting it, is this realistic? Check schematic (think it is)
    // where do they store the pk_b? in the blob, where do they store the ct_b? in pq_kex_ctx->oqs_kex_ctx->oqs_remote_msg (en length)
    if ((r = pq_tqs_deserialise_hostkey(ssh, server_host_key,
                                        server_host_key_blob, server_host_key_blob_len)) != 0 ||
        (r = tqs_deserialise(ssh, pq_kex_ctx->oqs_kex_ctx, TQS_IS_CLIENT)) != 0)
        goto out;

    r = sshpkt_get_end(ssh);

    out:
    return r;
}
static int
pq_tqs_s2c_deserialisever(struct ssh *ssh, PQ_KEX_CTX *pq_kex_ctx){
    int r = 0;
    if(r = tqs_deserialisever(ssh, pq_kex_ctx->oqs_kex_ctx, TQS_IS_CLIENT) != 0)
        goto out;
    r = sshpkt_get_end(ssh);
    out:
    return r;
}

static int
pq_tqs_c2s_serialise(struct ssh *ssh, PQ_KEX_CTX *pq_kex_ctx) {
    // should send ct_a, once it has been made
    return tqs_serialise(ssh, pq_kex_ctx->oqs_kex_ctx, TQS_IS_CLIENT);
}

static int
pq_tqs_c2s_serialisever(struct ssh *ssh, PQ_KEX_CTX *pq_kex_ctx){
    return tqs_serialisever(ssh,pq_kex_ctx->oqs_kex_ctx, TQS_IS_CLIENT);
}

static int
pq_tqs_verify_hostkey(struct ssh *ssh,
                      struct sshkey *server_host_key) {

    struct kex *kex = NULL;
    int r = 0;

    kex = ssh->kex;

    /* If we can't verify the host key then abort */
    if (kex->verify_host_key == NULL) {
        r = SSH_ERR_INVALID_ARGUMENT;
        goto out;
    }

    if (server_host_key->type != kex->hostkey_type ||
        (kex->hostkey_type == KEY_ECDSA &&
         server_host_key->ecdsa_nid != kex->hostkey_nid)) {
        r = SSH_ERR_KEY_TYPE_MISMATCH;
        goto out;
    }

    /* Verify host key */
    if (kex->verify_host_key(server_host_key, ssh) == -1) {
        r = SSH_ERR_SIGNATURE_INVALID;
        goto out;
    }

    out:
    return r;
}

static int
pq_tqs_deserialise_hostkey(struct ssh *ssh,
                           struct sshkey **server_host_key, u_char **server_host_key_blob,
                           size_t *server_host_key_blob_len) {

    struct sshkey *tmp_server_host_key = NULL;
    u_char *tmp_server_host_key_blob = NULL;
    size_t tmp_server_host_key_blob_len = 0;
    int r = 0;

    /* Extract host key from packet */
    if ((r = sshpkt_get_string(ssh, &tmp_server_host_key_blob,
                               &tmp_server_host_key_blob_len)) != 0 ||
        (r = sshkey_from_blob(tmp_server_host_key_blob,
                              tmp_server_host_key_blob_len, &tmp_server_host_key)) != 0)
        goto out;

    /* Immediately verify host key */
    // Checks signature as well..
    // Tom: except we don't want this at all.
    /*
    if ((r = pq_tqs_verify_hostkey(ssh,
                                   tmp_server_host_key)) != 0)
        goto out;
    */

    *server_host_key = tmp_server_host_key;
    *server_host_key_blob = tmp_server_host_key_blob;
    *server_host_key_blob_len = tmp_server_host_key_blob_len;

    tmp_server_host_key = NULL;
    tmp_server_host_key_blob = NULL;

    out:
    if (tmp_server_host_key_blob != NULL)
        free(tmp_server_host_key_blob);
    if (tmp_server_host_key != NULL)
        sshkey_free(tmp_server_host_key);

    return r;
}

/*
 * @brief Handles the first client liboqs PQ-only key exchange message
 */
int
pq_tqs_client(struct ssh *ssh) {

    PQ_KEX_CTX *pq_kex_ctx = NULL;
    OQS_KEX_CTX *oqs_kex_ctx = NULL;
    const OQS_ALG *oqs_alg = NULL;
    int r = 0;

    /* Test whether we are prepared to handle this packet */
    if (ssh == NULL ||
        ssh->kex == NULL ||
        (pq_kex_ctx = ssh->kex->pq_kex_ctx) == NULL ||
        (oqs_kex_ctx = pq_kex_ctx->oqs_kex_ctx) == NULL) {

        r = SSH_ERR_INTERNAL_ERROR;
        goto out;
    }

    if ((oqs_alg = oqs_mapping(pq_kex_ctx->pq_kex_name)) == NULL) {
        error("Unsupported libOQS algorithm \"%.100s\"", pq_kex_ctx->pq_kex_name);
        r = SSH_ERR_INTERNAL_ERROR;
        goto out;
    }

    /* Generate oqs public key */
    if ((r = tqs_client_gen(oqs_kex_ctx)) != 0)
        goto out;

    /* Basically sends pk_a, it's in ctx as local msg and local private is sk_a. Do keep track of local msg as this can be overwritten */
    /* Send client PQ-only liboqs packet to server */
    if ((r = sshpkt_start(ssh, tqs_ssh2_init_msg(oqs_alg))) != 0 ||
        (r = pq_tqs_c2s_serialise(ssh, pq_kex_ctx)) != 0 ||
        (r = sshpkt_send(ssh)) != 0)
        goto out;

    /* Set handler for recieving server reply */
    debug("expecting %i msg", tqs_ssh2_reply_msg(oqs_alg));
    ssh_dispatch_set(ssh, tqs_ssh2_reply_msg(oqs_alg),
                     &input_pq_tqs_reply);
    /* pk_a sent, waiting for pk_b, ct_b */

    out:
    if (r != 0)
        pq_oqs_free(pq_kex_ctx);

    return r;
}

/*
 * @brief Handles the liboqs PQ-only key exchange reply from server
 */
static int
input_pq_tqs_reply(int type, u_int32_t seq, struct ssh *ssh) {

    const OQS_ALG *oqs_alg = NULL;
    PQ_KEX_CTX *pq_kex_ctx = NULL;
    OQS_KEX_CTX *oqs_kex_ctx = NULL;
    struct sshkey *server_host_key = NULL;
    struct sshbuf *shared_secret_ssh_buf = NULL;
    struct kex *kex = NULL;
    struct ssh_hmac_ctx *hash_ctx = NULL;
    u_char *server_host_key_blob = NULL;
    u_char hash[SSH_DIGEST_MAX_LENGTH];
    u_char *oqs_shared_secret = NULL;
    size_t oqs_shared_secret_len = 0;
    size_t server_host_key_blob_len = 0;
    size_t hash_len = 0;
    u_char *tqs_key_b = NULL;
    u_char *tqs_key_a = NULL;
    size_t tqs_halfkey_size = 0;
    u_char *tqs_full_key = NULL;
    size_t tqs_fullkey_size = 0;
    u_char digest[16];

    int r = 0;
    // Should be getting ct_b and pk_b
    /* Test whether we are prepared to handle this packet */
    if (ssh == NULL ||
        (kex = ssh->kex) == NULL ||
        (pq_kex_ctx = kex->pq_kex_ctx) == NULL ||
        (oqs_kex_ctx = pq_kex_ctx->oqs_kex_ctx) == NULL) {

        r = SSH_ERR_INTERNAL_ERROR;
        goto out;
    }

    /* Extract from server to client packet */
    // So from this we want ct_b and pk_b, but how?
    // pk_b is stored in server_host_key struct (or in blob), ct_b in remote_msg van ctx
    if ((r = pq_tqs_s2c_deserialise(ssh, pq_kex_ctx,
                                    &server_host_key, &server_host_key_blob,
                                    &server_host_key_blob_len)) != 0)
        goto out;


    // Getting the shared secret by decapsulating -> not the way we want to do it actually.
    // Wij willen eerst encapsulaten, dus deze functie moet worden aangepast.
    // Sws moet de struct eigenlijk worden meegegeven als argument(denk ik).
    // Probeer met enkel het blob
    if ((r = tqs_client_shared_secret(oqs_kex_ctx, &tqs_key_a, &tqs_key_b, &tqs_full_key, &tqs_fullkey_size,
                                      &tqs_halfkey_size, &server_host_key)) != 0)
        goto out;

    /*
     * Compute exchange hash
     * kex->my is client
     * kex->peer is server
     */
    hash_len = sizeof(hash);
    if ((r = pq_tqs_hash(
            kex->hash_alg,
            kex->client_version_string,
            kex->server_version_string,
            kex->my,
            kex->peer,
            server_host_key_blob, server_host_key_blob_len,
            oqs_kex_ctx->oqs_local_msg, oqs_kex_ctx->oqs_local_msg_len,
            oqs_kex_ctx->oqs_remote_msg, oqs_kex_ctx->oqs_remote_msg_len,
            tqs_full_key, tqs_fullkey_size,
            hash, &hash_len)) != 0)
        goto out;

    if((hash_ctx = ssh_hmac_start(SSH_DIGEST_SHA256)) == NULL) {
        printf("ssh_hmac_start failed");
        goto out;
    }

    if((ssh_hmac_init(hash_ctx, tqs_full_key, tqs_fullkey_size)) < 0 ||
            (ssh_hmac_update(hash_ctx, hash, hash_len)) < 0 ||
            (ssh_hmac_final(hash_ctx, digest, sizeof(digest))) < 0) {
        printf("ssh_hmac_xxx failed");
        goto out;
    }


    /* Verify signature over exchange hash */
    // Need to get rid of this (the signature part)
    // Commenting it for now
    /*
    if ((r = sshkey_verify(server_host_key, signature, signature_len, hash,
                           hash_len, kex->hostkey_alg, ssh->compat))!= 0)

        goto out;
    */
    /* Save session id */
    if (kex->session_id == NULL) {
        kex->session_id_len = hash_len;
        kex->session_id = malloc(kex->session_id_len);
        if (kex->session_id == NULL) {
            r = SSH_ERR_ALLOC_FAIL;
            goto out;
        }
        memcpy(kex->session_id, hash, kex->session_id_len);
    }
    // Still need to send over ct_a -> so that server can make the key.
    if ((r = sshpkt_start(ssh, tqs_ssh2_sendct_msg(oqs_alg))) != 0 ||
        (r = pq_tqs_c2s_serialise(ssh, pq_kex_ctx)) != 0 ||
        (r = sshpkt_send(ssh)) != 0)
        goto out;

    /*
     * sshbuf_put_string() will encode the shared secret as a mpint
     * as required by SSH spec (RFC4253)
     */
    if ((shared_secret_ssh_buf = sshbuf_new()) == NULL) {
        r = SSH_ERR_ALLOC_FAIL;
        goto out;
    }
    if ((r = sshbuf_put_string(shared_secret_ssh_buf, (const u_char *) tqs_full_key,
                               tqs_fullkey_size)) != 0)
        goto out;

    if ((r = kex_derive_keys(ssh, hash, hash_len, shared_secret_ssh_buf)) == 0)
        r = kex_send_newkeys(ssh);

    oqs_kex_ctx->digesta = digest;
    oqs_kex_ctx->digestlen = sizeof(digest);
    oqs_kex_ctx->tqs_halfkey_size = tqs_halfkey_size;
    oqs_kex_ctx->tqs_key_a = tqs_key_a;
    oqs_kex_ctx->tqs_key_b = tqs_key_b;
    oqs_kex_ctx->hash_len = hash_len;
    oqs_kex_ctx->hash = hash;
    oqs_kex_ctx->tqs_fullkey_size = tqs_fullkey_size;
    oqs_kex_ctx->tqs_full_key = tqs_full_key;
    ssh->kex->pq_kex_ctx->oqs_kex_ctx = oqs_kex_ctx;
    // Initiate the MAC round trip
    pq_tqs_verinit(type, seq, ssh);

    out:
    ssh_hmac_free(hash_ctx);
    explicit_bzero(hash, sizeof(hash));
    pq_oqs_free(pq_kex_ctx);
    /* sshbuf_free zeroises memory */
    if (shared_secret_ssh_buf != NULL)
        sshbuf_free(shared_secret_ssh_buf);
    if (server_host_key != NULL)
        sshkey_free(server_host_key);
    if (oqs_shared_secret != NULL) {
        explicit_bzero(oqs_shared_secret, oqs_shared_secret_len);
        free(oqs_shared_secret);
    }
    if (server_host_key_blob != NULL)
        free(server_host_key_blob);

    return r;
}

static int
pq_tqs_verinit(int type, u_int32_t seq, struct ssh *ssh) {
    /* need to send MAC */
    const OQS_ALG *oqs_alg = NULL;
    PQ_KEX_CTX *pq_kex_ctx = NULL;
    OQS_KEX_CTX *oqs_kex_ctx = NULL;
    struct kex *kex = NULL;
    int r = 0;
    if (ssh == NULL ||
        (kex = ssh->kex) == NULL ||
        (pq_kex_ctx = kex->pq_kex_ctx) == NULL ||
        (oqs_kex_ctx = pq_kex_ctx->oqs_kex_ctx) == NULL) {

        r = SSH_ERR_INTERNAL_ERROR;
        goto out;
    }
    if ((r = sshpkt_start(ssh, tqs_ssh2_init_msg(oqs_alg))) != 0 ||
        (r = pq_tqs_c2s_serialisever(ssh, pq_kex_ctx)) != 0 ||
        (r = sshpkt_send(ssh)) != 0)
        goto out;

    debug("expecting %i msg", tqs_ssh2_verreply_msg(oqs_alg));
    ssh_dispatch_set(ssh, tqs_ssh2_verreply_msg(oqs_alg),
                     &input_pq_tqs_verreply);
    out:
    pq_oqs_free(pq_kex_ctx);
    return r;
}

static int
input_pq_tqs_verreply(int type, u_int32_t seq, struct ssh *ssh) {
    PQ_KEX_CTX *pq_kex_ctx = NULL;
    OQS_KEX_CTX *oqs_kex_ctx = NULL;
    struct kex *kex = NULL;
    struct ssh_hmac_ctx *hash_ctx = NULL;
    u_char check_digest[16];
    u_char *macmessage;
    int r = 0;

    if (ssh == NULL ||
        (kex = ssh->kex) == NULL ||
        (pq_kex_ctx = kex->pq_kex_ctx) == NULL ||
        (oqs_kex_ctx = pq_kex_ctx->oqs_kex_ctx) == NULL) {

        r = SSH_ERR_INTERNAL_ERROR;
        goto out;
    }

    if ((r = pq_tqs_s2c_deserialisever(ssh, pq_kex_ctx)) != 0) {
        goto out;
    }

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
       (ssh_hmac_final(hash_ctx, check_digest, sizeof(check_digest))) < 0) {
        printf("ssh_hmac_xxx failed");
        goto out;
    }
    if(memcmp(check_digest, oqs_kex_ctx->digestb, oqs_kex_ctx->digestlen) != 0) {
        r = SSH_ERR_INTERNAL_ERROR;
        goto out;
    }
    out:
    pq_oqs_free(pq_kex_ctx);
    return r;
}

#endif /* defined(WITH_OQS) && defined(WITH_PQ_KEX) */