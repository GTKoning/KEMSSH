#include "includes.h"

#if defined(WITH_OQS) && defined(WITH_PQ_KEX)

#include <signal.h>
#include <string.h>

#include "digest.h"
#include "dispatch.h"
#include "hmac.h"
#include "kex.h"
#include "log.h"
#include "packet.h"
#include "ssh2.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "sshkey.h"

/* Server private */
static int pq_tqs_c2s_deserialise(struct ssh *ssh, PQ_KEX_CTX *pq_kex_ctx);
static int pq_tqs_s2c_serialise(struct ssh *ssh, PQ_KEX_CTX *pq_kex_ctx,
                                u_char *server_host_key_blob,
                                size_t server_host_key_blob_len);
static int pq_tqs_s2c_serialisever(struct ssh *ssh, PQ_KEX_CTX *pq_kex_ctx);
static int pq_tqs_server_hostkey(struct ssh *ssh,
                                 struct sshkey **server_host_public,
                                 struct sshkey **server_host_private,
                                 u_char **server_host_key_blob,
                                 size_t *server_host_key_blob_len);
static int input_pq_tqs_init(int type, u_int32_t seq, struct ssh *ssh);
static int input_pq_tqs_finish(int type, u_int32_t seq, struct ssh *ssh);
static int input_pq_tqs_verinit(int type, u_int32_t seq, struct ssh *ssh);

/*
 * @brief Logic that handles packet deserialisation of the client kex message
 * when using a liboqs kex
 */

u_char serverHash[SSH_DIGEST_MAX_LENGTH];

static int pq_tqs_c2s_deserialise(struct ssh *ssh, PQ_KEX_CTX *pq_kex_ctx) {

  int r = 0;
  if ((r = tqs_deserialise(ssh, pq_kex_ctx->oqs_kex_ctx, TQS_IS_SERVER) != 0)) {
    error(" this is r %i", r);
    goto out;
  }
  r = sshpkt_get_end(ssh);
  // error(" This is cta that we got from the package %p!!",
  // pq_kex_ctx->oqs_kex_ctx->tqs_ct_a); error(" This is remote msg that we got
  // from the package %p !!", pq_kex_ctx->oqs_kex_ctx->oqs_remote_msg);

out:
  return r;
}

static int pq_tqs_c2s_deserialisever(struct ssh *ssh, PQ_KEX_CTX *pq_kex_ctx) {
  int r = 0;
  if ((r = tqs_deserialisever(ssh, pq_kex_ctx->oqs_kex_ctx, TQS_IS_SERVER) !=
           0))
    goto out;

  r = sshpkt_get_end(ssh);

out:
  return r;
}

/*
 * @brief Logic that handles packet serialisation of the client kex message
 * when using a liboqs kex
 */
static int pq_tqs_s2c_serialise(struct ssh *ssh, PQ_KEX_CTX *pq_kex_ctx,
                                u_char *server_host_key_blob,
                                size_t server_host_key_blob_len) {

  int r = 0;
  // error(" printing server_host_key_blob_len %li", server_host_key_blob_len);
  if ((r = sshpkt_put_string(ssh, server_host_key_blob,
                             server_host_key_blob_len)) != 0 ||
      (r = tqs_serialise(ssh, pq_kex_ctx->oqs_kex_ctx, TQS_IS_SERVER)) != 0) {
    goto out;
  }

out:
  return r;
}
static int pq_tqs_s2c_serialisever(struct ssh *ssh, PQ_KEX_CTX *pq_kex_ctx) {
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
static int pq_tqs_server_hostkey(struct ssh *ssh,
                                 struct sshkey **server_host_public,
                                 struct sshkey **server_host_private,
                                 u_char **server_host_key_blob,
                                 size_t *server_host_key_blob_len) {

  struct kex *kex = NULL;
  struct sshkey *tmp_server_host_public = NULL;
  struct sshkey *tmp_server_host_private = NULL;
  u_char *tmp_server_host_key_blob = NULL;
  size_t tmp_server_host_key_blob_len = 0;
  int r = 0;

  kex = ssh->kex;
  /* Retrieve host public and private key */
  if (kex->load_host_public_key == NULL || kex->load_host_private_key == NULL) {
    r = SSH_ERR_INVALID_ARGUMENT;
    goto out;
  }
  if (((tmp_server_host_public = kex->load_host_public_key(
            kex->hostkey_type, kex->hostkey_nid, ssh)) == NULL) ||
      (tmp_server_host_private = kex->load_host_private_key(
           kex->hostkey_type, kex->hostkey_nid, ssh)) == NULL) {
    r = SSH_ERR_NO_HOSTKEY_LOADED;
    goto out;
  }
  // debug("in server_hostkey: oqs_sk = %p", tmp_server_host_public->oqs_sk);
  // debug("in server_hostkey: oqs_pk = %p", tmp_server_host_public->oqs_pk);

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
  kex->pq_kex_ctx->oqs_kex_ctx->oqs_local_msg = tmp_server_host_public->oqs_pk;
  kex->pq_kex_ctx->oqs_kex_ctx->oqs_local_priv =
      tmp_server_host_private->oqs_sk;
  kex->pq_kex_ctx->oqs_kex_ctx->oqs_local_msg_len =
      tmp_server_host_public->oqs_kem->length_public_key;
  kex->pq_kex_ctx->oqs_kex_ctx->oqs_local_priv_len =
      tmp_server_host_public->oqs_kem->length_secret_key;

  tmp_server_host_public = NULL;
  tmp_server_host_private = NULL;
  tmp_server_host_key_blob = NULL;

out:
  return r;
}

int pq_tqs_server(struct ssh *ssh) {

  PQ_KEX_CTX *pq_kex_ctx = NULL;
  const OQS_ALG *oqs_alg = NULL;
  int r = 0;

  /* Test whether we are prepared to handle this packet */
  if (ssh == NULL || ssh->kex == NULL ||
      (pq_kex_ctx = ssh->kex->pq_kex_ctx) == NULL) {
    r = SSH_ERR_INTERNAL_ERROR;
    goto out;
  }

  if ((oqs_alg = oqs_mapping(pq_kex_ctx->pq_kex_name)) == NULL) {
    error("Unsupported libOQS algorithm \"%.100s\"", pq_kex_ctx->pq_kex_name);
    r = SSH_ERR_INTERNAL_ERROR;
    goto out;
  }
  // error( "Set up confirmed, now waiting for PK_A");
  debug("expecting %i msg init tqs on serverside", tqs_ssh2_init_msg(oqs_alg));
  ssh_dispatch_set(ssh, tqs_ssh2_init_msg(oqs_alg), &input_pq_tqs_init);

out:
  return r;
}

static int input_pq_tqs_init(int type, u_int32_t seq, struct ssh *ssh) {
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
  if (ssh == NULL || (kex = ssh->kex) == NULL ||
      (pq_kex_ctx = kex->pq_kex_ctx) == NULL ||
      (oqs_kex_ctx = pq_kex_ctx->oqs_kex_ctx) == NULL) {
    error(" SETUP SERVER WENT WRONG ");
    r = SSH_ERR_INTERNAL_ERROR;
    goto out;
  }

  /* Load public and private host key */
  if ((r = pq_tqs_server_hostkey(ssh, &server_host_public, &server_host_private,
                                 &server_host_key_blob,
                                 &server_host_key_blob_len)) != 0)
    goto out;
  /* Packet comes in */
  /* Deserialise client to server packet */
  /* Gets public key of client (and length) stored in remote_msg */
  // error ( " package received from client");
  if ((r = pq_tqs_c2s_deserialise(ssh, pq_kex_ctx)) != 0) {
    error(" Something went wrong in c2s deserialise");
    goto out;
  }

  /*
   * libOQS API only supports generating the liboqs public key
   * msg and shared secret simultaneously.
   */

  // error(" we are now here, time to check if we did encaps decaps correctly");
  if ((r = tqs_server_gen_msg_and_ss(ssh, oqs_kex_ctx, &tqs_key_b,
                                     &tqs_halfkey_size, &oqs_shared_secret,
                                     &oqs_shared_secret_len)) != 0) {
    goto out;
  }

  // K_b, ct_b made.
  // Shouldn't this have happened sooner ? v
  if ((oqs_alg = oqs_mapping(pq_kex_ctx->pq_kex_name)) == NULL) {
    error("Unsupported libOQS algorithm \"%.100s\"", pq_kex_ctx->pq_kex_name);
    error("This is not supposed to happen oqs_alg mapping failed");
    r = SSH_ERR_INTERNAL_ERROR;
    goto out;
  }
  // Need to send ct_b and pk_b -> use serialise 2 in s2c :)
  // Also, where is pk_b currently stored?
  // Now it makes sense! that's why the blobs are made.

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
  // debug("local_priv vanuit host private: %p", oqs_kex_ctx->oqs_local_priv);

  // We are receiving ct_a -> to make our key with
  // BUT HOW
  ssh->kex->pq_kex_ctx = pq_kex_ctx;
  pq_kex_ctx = NULL;
  debug("expecting %i msg sendct for finish", tqs_ssh2_sendct_msg(oqs_alg));
  ssh_dispatch_set(ssh, tqs_ssh2_sendct_msg(oqs_alg), &input_pq_tqs_finish);

out:
  if (pq_kex_ctx != NULL)
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

  debug("done with this function input_pq_tqs_init");
  return r;
}

static int input_pq_tqs_finish(int type, u_int32_t seq, struct ssh *ssh) {
  // debug("hello from input_pq_tqs_finish");
  const OQS_ALG *oqs_alg = NULL;
  u_char *tqs_full_key = NULL;
  size_t tqs_fullkey_size = 0;

  size_t hash_len = 48;
  struct kex *kex = NULL;
  struct sshbuf *shared_secret_ssh_buf = NULL;
  PQ_KEX_CTX *pq_kex_ctx = NULL;
  OQS_KEX_CTX *oqs_kex_ctx = NULL;

  u_char *hash = malloc(SSH_DIGEST_MAX_LENGTH);
  if (hash == NULL) {
    error("Malloc faal");
    exit(1);
  }

  int r = 0;

  if (ssh == NULL || (kex = ssh->kex) == NULL ||
      (pq_kex_ctx = kex->pq_kex_ctx) == NULL ||
      (oqs_kex_ctx = pq_kex_ctx->oqs_kex_ctx) == NULL) {
    debug("ssh: %p\nkex: %p\npq_kex_ctx: %p\noqs_kex_ctx: %p", ssh, kex,
          pq_kex_ctx, oqs_kex_ctx);
    error("Context was somehow nullified. Not good.");
    r = SSH_ERR_INTERNAL_ERROR;
    goto out;
  }

  // debug("voor getstr");
  if ((r = sshpkt_get_string(ssh, &oqs_kex_ctx->tqs_ct_a,
                             &oqs_kex_ctx->tqs_ct_a_len)) != 0)
    goto out;
  // so we got ct_a now.
  // Time to create the shared key.
  // debug("gelukt: cta_len = %zu", oqs_kex_ctx->tqs_ct_a_len);

  tqs_server_gen_key_hmac(oqs_kex_ctx, &tqs_full_key, &tqs_fullkey_size);

  // debug("na gen hmac");
  // shared key created
  // error( "");
  // error(" ------ CHECKING SERVER SIDE HASH VALUES ------- ");
  // error(" hash_alg: %d", kex->hash_alg);
  // error(" client_version_string: %p", kex->client_version_string);
  // error(" server_version_string: %p", kex->server_version_string);
  // error(" remote msg: %p | %zu", oqs_kex_ctx->oqs_remote_msg,
  // oqs_kex_ctx->oqs_remote_msg_len); error(" local msg: %p | %zu",
  // oqs_kex_ctx->oqs_local_msg, oqs_kex_ctx->oqs_local_msg_len);

  // error(" ------ CHECKING SERVER SIDE HASH VALUES END ------- ");
  // error( "");

  if ((r = pq_tqs_hash(kex->hash_alg, kex->client_version_string,
                       kex->server_version_string, oqs_kex_ctx->oqs_remote_msg,
                       oqs_kex_ctx->oqs_remote_msg_len,
                       oqs_kex_ctx->oqs_local_msg,
                       oqs_kex_ctx->oqs_local_msg_len, tqs_full_key,
                       tqs_fullkey_size, hash, &hash_len)) != 0)
    goto out;
  oqs_kex_ctx->hash = hash;
  oqs_kex_ctx->hash_len = hash_len;
  oqs_kex_ctx->tqs_full_key = tqs_full_key;
  oqs_kex_ctx->tqs_fullkey_size = tqs_fullkey_size;
  memcpy(serverHash, hash, sizeof(serverHash));

  //    if ((shared_secret_ssh_buf = sshbuf_new()) == NULL) {
  //        r = SSH_ERR_ALLOC_FAIL;
  //        goto out;
  //    }
  //
  //    if ((r = sshbuf_put_string(shared_secret_ssh_buf, (const u_char *)
  //    tqs_full_key,
  //                               tqs_fullkey_size)) != 0)
  //        goto out;
  //
  //    if ((r = kex_derive_keys(ssh, hash, hash_len, shared_secret_ssh_buf)) ==
  //    0)
  //        r = kex_send_newkeys(ssh);

  /* Set handler for recieving client verification initiation */
  debug("expecting %i msg verinit", tqs_ssh2_verinit_msg(oqs_alg));
  ssh_dispatch_set(ssh, tqs_ssh2_verinit_msg(oqs_alg), &input_pq_tqs_verinit);
out:
  // explicit_bzero(hash, sizeof(hash));
  // pq_oqs_free(pq_kex_ctx);
  return r;
}

static int input_pq_tqs_verinit(int type, u_int32_t seq, struct ssh *ssh) {
  const OQS_ALG *oqs_alg = NULL;
  struct kex *kex = NULL;
  PQ_KEX_CTX *pq_kex_ctx = NULL;
  OQS_KEX_CTX *oqs_kex_ctx = NULL;
  struct ssh_hmac_ctx *hash_ctx = NULL;
  struct ssh_hmac_ctx *hash_checker_ctx = NULL;
  struct sshbuf *shared_secret_ssh_buf = NULL;
  u_char *digest = malloc(32);
  u_char check_digest[32];

  if (digest == NULL) {
    error("malloc fail");
    exit(1);
  }
  u_char *macmessage;

  int r = 0;

  if (ssh == NULL || (kex = ssh->kex) == NULL ||
      (pq_kex_ctx = kex->pq_kex_ctx) == NULL ||
      (oqs_kex_ctx = pq_kex_ctx->oqs_kex_ctx) == NULL) {

    r = SSH_ERR_INTERNAL_ERROR;
    goto out;
  }

  if ((r = pq_tqs_c2s_deserialisever(ssh, pq_kex_ctx)) != 0) {
    error("deserialisever failed");
    goto out;
  }

  // Let's recreate digesta already

  if ((hash_checker_ctx = ssh_hmac_start(SSH_DIGEST_SHA256)) == NULL) {
    printf("ssh_hmac_start failed");
    goto out;
  }

  // Print variables to check where it kills itself

  // dump_value("hash server", oqs_kex_ctx->hash, oqs_kex_ctx->hash_len);

  if ((ssh_hmac_init(hash_checker_ctx, oqs_kex_ctx->tqs_full_key,
                     oqs_kex_ctx->tqs_fullkey_size)) < 0 ||
      (ssh_hmac_update(hash_checker_ctx, oqs_kex_ctx->hash,
                       oqs_kex_ctx->hash_len)) < 0 ||
      (ssh_hmac_final(hash_checker_ctx, check_digest, sizeof(check_digest))) <
          0) {
    printf("ssh_hmac_xxx failed");
    goto out;
  }
  oqs_kex_ctx->check_digest = check_digest;

  // SERVER MOET DIGESTA NOG WEL CHECKEN

  // Check of the century
  if (memcmp(check_digest, pq_kex_ctx->oqs_kex_ctx->digesta,
             pq_kex_ctx->oqs_kex_ctx->digestlen) == 0) {
    error("Digest checking complete");
  }

  if ((hash_ctx = ssh_hmac_start(SSH_DIGEST_SHA256)) == NULL) {
    error("ssh_hmac_start failed");
    goto out;
  }
  // error(" HMAC start is gelukt??");
  u_char *tmp_macmessage =
      malloc(oqs_kex_ctx->digestlen + oqs_kex_ctx->hash_len);
  if (tmp_macmessage == NULL) {
    error("malloc failed");
    exit(1);
  }
  u_char *tmp_digesta = oqs_kex_ctx->digesta;
  u_char *tmp_hash = oqs_kex_ctx->hash;

  memcpy(tmp_macmessage, tmp_hash, oqs_kex_ctx->hash_len);
  memcpy(tmp_macmessage + oqs_kex_ctx->hash_len, tmp_digesta,
         oqs_kex_ctx->digestlen);
  macmessage = (u_char *)tmp_macmessage;

  // dump_value(" [Full key die wordt gebruikt] ", oqs_kex_ctx->tqs_full_key,
  // oqs_kex_ctx->tqs_fullkey_size); dump_value(" [DISGESTA die wordt gebruikt]
  // ", oqs_kex_ctx->digesta, oqs_kex_ctx->digestlen); dump_value(" [MACMESSAGE
  // die wordt gebruikt server side] ", macmessage, (oqs_kex_ctx->digestlen +
  // oqs_kex_ctx->hash_len));

  if ((r = ssh_hmac_init(hash_ctx, oqs_kex_ctx->tqs_full_key,
                         oqs_kex_ctx->tqs_fullkey_size)) < 0 ||
      (r = ssh_hmac_update(hash_ctx, macmessage,
                           (oqs_kex_ctx->digestlen + oqs_kex_ctx->hash_len))) <
          0 ||
      (r = ssh_hmac_final(hash_ctx, digest, 32) < 0)) {
    error("ssh_hmac_xxx failed");
    exit(1);
    goto out;
  }
  // error("What about second breakfast");

  oqs_kex_ctx->digestb = digest;
  // dump_value(" [DISGESTB die is gemaakt op server] ", digest,
  // oqs_kex_ctx->digestlen);
  int ptype = tqs_ssh2_verreply_msg(oqs_alg);
  // error("Type = %d", ptype);
  if ((r = sshpkt_start(ssh, ptype)) != 0 ||
      (r = pq_tqs_s2c_serialisever(ssh, pq_kex_ctx)) != 0 ||
      (r = sshpkt_send(ssh)) != 0) {
    goto out;
  }

  // confirmation message?
  //    int type_ = tqs_ssh2_sendct_msg(oqs_alg);
  //    if ((r = sshpkt_start(ssh, type_)) != 0) {
  //        puts("dit gaat mis!");
  //        exit(1);
  //        goto out;
  //    }
  //    if ((r = sshpkt_send(ssh)) != 0) {
  //        puts(" Is t deze dan????");
  //        //exit(1);
  //        goto out;
  //    }

  /* Save session id */
  if (kex->session_id == NULL) {
    kex->session_id_len = oqs_kex_ctx->hash_len;
    kex->session_id = malloc(kex->session_id_len);
    if (kex->session_id == NULL) {
      r = SSH_ERR_ALLOC_FAIL;
      goto out;
    }
    memcpy(kex->session_id, oqs_kex_ctx->hash, kex->session_id_len);
  }

  // NEWKEYS?

  if ((shared_secret_ssh_buf = sshbuf_new()) == NULL) {
    r = SSH_ERR_ALLOC_FAIL;
    goto out;
  }

  // dump_value("hash", oqs_kex_ctx->hash, oqs_kex_ctx->hash_len);
  // dump_value("session_id", kex->session_id, kex->session_id_len);

  if ((r = sshbuf_put_string(shared_secret_ssh_buf,
                             (const u_char *)oqs_kex_ctx->tqs_full_key,
                             oqs_kex_ctx->tqs_fullkey_size)) != 0)
    goto out;

  if ((r = kex_derive_keys(ssh, oqs_kex_ctx->hash, oqs_kex_ctx->hash_len,
                           shared_secret_ssh_buf)) == 0)
    r = kex_send_newkeys(ssh);

  error("Serverside is done with KEX");

out:
  ssh_hmac_free(hash_ctx);
  pq_oqs_free(pq_kex_ctx);
  return r;
}

#endif /* defined(WITH_OQS) && defined(WITH_PQ_KEX) */
