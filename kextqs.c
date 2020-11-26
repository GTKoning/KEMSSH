//
// Created by op on 26-11-20.
//
#include "includes.h"

#ifdef WITH_TQS

#include <string.h>

#include "ssherr.h"
#include "packet.h"
#include "ssh2.h"
#include "kextqs.h"

/*
 * Mapping that maps relevant named SSH key exchange methods to the needed
 * corresponding libtqs key exchange scheme
 */
static const TQS_ALG tqs_alg_mapping[] = {
#ifdef WITH_PQ_KEX
	{PQ_OQS_KEX_SUFFIX("tqsdefault-sha384"), OQS_KEM_alg_default,
	SSH2_MSG_PQ_OQSDEFAULT_INIT, SSH2_MSG_PQ_OQSDEFAULT_REPLY},
///// OQS_TEMPLATE_FRAGMENT_DEFINE_PQ_KEXS_START
#ifdef HAVE_BIKE
	{PQ_OQS_KEX_SUFFIX("bike1-l1-cpa-sha384"), OQS_KEM_alg_bike1_l1_cpa,
	SSH2_MSG_PQ_BIKE_INIT, SSH2_MSG_PQ_BIKE_REPLY},
	{PQ_OQS_KEX_SUFFIX("bike1-l3-cpa-sha384"), OQS_KEM_alg_bike1_l3_cpa,
	SSH2_MSG_PQ_BIKE_INIT, SSH2_MSG_PQ_BIKE_REPLY},
	{PQ_OQS_KEX_SUFFIX("bike1-l1-fo-sha384"), OQS_KEM_alg_bike1_l1_fo,
	SSH2_MSG_PQ_BIKE_INIT, SSH2_MSG_PQ_BIKE_REPLY},
	{PQ_OQS_KEX_SUFFIX("bike1-l3-fo-sha384"), OQS_KEM_alg_bike1_l3_fo,
	SSH2_MSG_PQ_BIKE_INIT, SSH2_MSG_PQ_BIKE_REPLY},
#endif /* HAVE_BIKE */
#ifdef HAVE_CLASSIC_MCELIECE
	{PQ_OQS_KEX_SUFFIX("classic-mceliece-348864-sha384"), OQS_KEM_alg_classic_mceliece_348864,
	SSH2_MSG_PQ_CLASSIC_MCELIECE_INIT, SSH2_MSG_PQ_CLASSIC_MCELIECE_REPLY},
	{PQ_OQS_KEX_SUFFIX("classic-mceliece-348864f-sha384"), OQS_KEM_alg_classic_mceliece_348864f,
	SSH2_MSG_PQ_CLASSIC_MCELIECE_INIT, SSH2_MSG_PQ_CLASSIC_MCELIECE_REPLY},
	{PQ_OQS_KEX_SUFFIX("classic-mceliece-460896-sha384"), OQS_KEM_alg_classic_mceliece_460896,
	SSH2_MSG_PQ_CLASSIC_MCELIECE_INIT, SSH2_MSG_PQ_CLASSIC_MCELIECE_REPLY},
	{PQ_OQS_KEX_SUFFIX("classic-mceliece-460896f-sha384"), OQS_KEM_alg_classic_mceliece_460896f,
	SSH2_MSG_PQ_CLASSIC_MCELIECE_INIT, SSH2_MSG_PQ_CLASSIC_MCELIECE_REPLY},
	{PQ_OQS_KEX_SUFFIX("classic-mceliece-6688128-sha384"), OQS_KEM_alg_classic_mceliece_6688128,
	SSH2_MSG_PQ_CLASSIC_MCELIECE_INIT, SSH2_MSG_PQ_CLASSIC_MCELIECE_REPLY},
	{PQ_OQS_KEX_SUFFIX("classic-mceliece-6688128f-sha384"), OQS_KEM_alg_classic_mceliece_6688128f,
	SSH2_MSG_PQ_CLASSIC_MCELIECE_INIT, SSH2_MSG_PQ_CLASSIC_MCELIECE_REPLY},
	{PQ_OQS_KEX_SUFFIX("classic-mceliece-6960119-sha384"), OQS_KEM_alg_classic_mceliece_6960119,
	SSH2_MSG_PQ_CLASSIC_MCELIECE_INIT, SSH2_MSG_PQ_CLASSIC_MCELIECE_REPLY},
	{PQ_OQS_KEX_SUFFIX("classic-mceliece-6960119f-sha384"), OQS_KEM_alg_classic_mceliece_6960119f,
	SSH2_MSG_PQ_CLASSIC_MCELIECE_INIT, SSH2_MSG_PQ_CLASSIC_MCELIECE_REPLY},
	{PQ_OQS_KEX_SUFFIX("classic-mceliece-8192128-sha384"), OQS_KEM_alg_classic_mceliece_8192128,
	SSH2_MSG_PQ_CLASSIC_MCELIECE_INIT, SSH2_MSG_PQ_CLASSIC_MCELIECE_REPLY},
	{PQ_OQS_KEX_SUFFIX("classic-mceliece-8192128f-sha384"), OQS_KEM_alg_classic_mceliece_8192128f,
	SSH2_MSG_PQ_CLASSIC_MCELIECE_INIT, SSH2_MSG_PQ_CLASSIC_MCELIECE_REPLY},
#endif /* HAVE_CLASSIC_MCELIECE */
#ifdef HAVE_FRODO
	{PQ_OQS_KEX_SUFFIX("frodo-640-aes-sha384"), OQS_KEM_alg_frodokem_640_aes,
	SSH2_MSG_PQ_FRODO_INIT, SSH2_MSG_PQ_FRODO_REPLY},
	{PQ_OQS_KEX_SUFFIX("frodo-640-shake-sha384"), OQS_KEM_alg_frodokem_640_shake,
	SSH2_MSG_PQ_FRODO_INIT, SSH2_MSG_PQ_FRODO_REPLY},
	{PQ_OQS_KEX_SUFFIX("frodo-976-aes-sha384"), OQS_KEM_alg_frodokem_976_aes,
	SSH2_MSG_PQ_FRODO_INIT, SSH2_MSG_PQ_FRODO_REPLY},
	{PQ_OQS_KEX_SUFFIX("frodo-976-shake-sha384"), OQS_KEM_alg_frodokem_976_shake,
	SSH2_MSG_PQ_FRODO_INIT, SSH2_MSG_PQ_FRODO_REPLY},
	{PQ_OQS_KEX_SUFFIX("frodo-1344-aes-sha384"), OQS_KEM_alg_frodokem_1344_aes,
	SSH2_MSG_PQ_FRODO_INIT, SSH2_MSG_PQ_FRODO_REPLY},
	{PQ_OQS_KEX_SUFFIX("frodo-1344-shake-sha384"), OQS_KEM_alg_frodokem_1344_shake,
	SSH2_MSG_PQ_FRODO_INIT, SSH2_MSG_PQ_FRODO_REPLY},
#endif /* HAVE_FRODO */
#ifdef HAVE_KYBER
	{PQ_OQS_KEX_SUFFIX("kyber-512-sha384"), OQS_KEM_alg_kyber_512,
	SSH2_MSG_PQ_KYBER_INIT, SSH2_MSG_PQ_KYBER_REPLY},
	{PQ_OQS_KEX_SUFFIX("kyber-768-sha384"), OQS_KEM_alg_kyber_768,
	SSH2_MSG_PQ_KYBER_INIT, SSH2_MSG_PQ_KYBER_REPLY},
	{PQ_OQS_KEX_SUFFIX("kyber-1024-sha384"), OQS_KEM_alg_kyber_1024,
	SSH2_MSG_PQ_KYBER_INIT, SSH2_MSG_PQ_KYBER_REPLY},
	{PQ_OQS_KEX_SUFFIX("kyber-512-90s-sha384"), OQS_KEM_alg_kyber_512_90s,
	SSH2_MSG_PQ_KYBER_INIT, SSH2_MSG_PQ_KYBER_REPLY},
	{PQ_OQS_KEX_SUFFIX("kyber-768-90s-sha384"), OQS_KEM_alg_kyber_768_90s,
	SSH2_MSG_PQ_KYBER_INIT, SSH2_MSG_PQ_KYBER_REPLY},
	{PQ_OQS_KEX_SUFFIX("kyber-1024-90s-sha384"), OQS_KEM_alg_kyber_1024_90s,
	SSH2_MSG_PQ_KYBER_INIT, SSH2_MSG_PQ_KYBER_REPLY},
#endif /* HAVE_KYBER */
#ifdef HAVE_NTRU
	{PQ_OQS_KEX_SUFFIX("ntru-hps-2048-509-sha384"), OQS_KEM_alg_ntru_hps2048509,
	SSH2_MSG_PQ_NTRU_INIT, SSH2_MSG_PQ_NTRU_REPLY},
	{PQ_OQS_KEX_SUFFIX("ntru-hps-2048-677-sha384"), OQS_KEM_alg_ntru_hps2048677,
	SSH2_MSG_PQ_NTRU_INIT, SSH2_MSG_PQ_NTRU_REPLY},
	{PQ_OQS_KEX_SUFFIX("ntru-hrss-701-sha384"), OQS_KEM_alg_ntru_hrss701,
	SSH2_MSG_PQ_NTRU_INIT, SSH2_MSG_PQ_NTRU_REPLY},
	{PQ_OQS_KEX_SUFFIX("ntru-hps-4096-821-sha384"), OQS_KEM_alg_ntru_hps4096821,
	SSH2_MSG_PQ_NTRU_INIT, SSH2_MSG_PQ_NTRU_REPLY},
#endif /* HAVE_NTRU */
#ifdef HAVE_SABER
	{PQ_OQS_KEX_SUFFIX("saber-lightsaber-sha384"), OQS_KEM_alg_saber_lightsaber,
	SSH2_MSG_PQ_SABER_INIT, SSH2_MSG_PQ_SABER_REPLY},
	{PQ_OQS_KEX_SUFFIX("saber-saber-sha384"), OQS_KEM_alg_saber_saber,
	SSH2_MSG_PQ_SABER_INIT, SSH2_MSG_PQ_SABER_REPLY},
	{PQ_OQS_KEX_SUFFIX("saber-firesaber-sha384"), OQS_KEM_alg_saber_firesaber,
	SSH2_MSG_PQ_SABER_INIT, SSH2_MSG_PQ_SABER_REPLY},
#endif /* HAVE_SABER */
#ifdef HAVE_SIDH
	{PQ_OQS_KEX_SUFFIX("sidh-p434-sha384"), OQS_KEM_alg_sidh_p434,
	SSH2_MSG_PQ_SIDH_INIT, SSH2_MSG_PQ_SIDH_REPLY},
	{PQ_OQS_KEX_SUFFIX("sidh-p503-sha384"), OQS_KEM_alg_sidh_p503,
	SSH2_MSG_PQ_SIDH_INIT, SSH2_MSG_PQ_SIDH_REPLY},
	{PQ_OQS_KEX_SUFFIX("sidh-p610-sha384"), OQS_KEM_alg_sidh_p610,
	SSH2_MSG_PQ_SIDH_INIT, SSH2_MSG_PQ_SIDH_REPLY},
	{PQ_OQS_KEX_SUFFIX("sidh-p751-sha384"), OQS_KEM_alg_sidh_p751,
	SSH2_MSG_PQ_SIDH_INIT, SSH2_MSG_PQ_SIDH_REPLY},
	{PQ_OQS_KEX_SUFFIX("sidh-p434-compressed-sha384"), OQS_KEM_alg_sidh_p434_compressed,
	SSH2_MSG_PQ_SIDH_INIT, SSH2_MSG_PQ_SIDH_REPLY},
	{PQ_OQS_KEX_SUFFIX("sidh-p503-compressed-sha384"), OQS_KEM_alg_sidh_p503_compressed,
	SSH2_MSG_PQ_SIDH_INIT, SSH2_MSG_PQ_SIDH_REPLY},
	{PQ_OQS_KEX_SUFFIX("sidh-p610-compressed-sha384"), OQS_KEM_alg_sidh_p610_compressed,
	SSH2_MSG_PQ_SIDH_INIT, SSH2_MSG_PQ_SIDH_REPLY},
	{PQ_OQS_KEX_SUFFIX("sidh-p751-compressed-sha384"), OQS_KEM_alg_sidh_p751_compressed,
	SSH2_MSG_PQ_SIDH_INIT, SSH2_MSG_PQ_SIDH_REPLY},
#endif /* HAVE_SIDH */
#ifdef HAVE_SIKE
	{PQ_OQS_KEX_SUFFIX("sike-p434-sha384"), OQS_KEM_alg_sike_p434,
	SSH2_MSG_PQ_SIKE_INIT, SSH2_MSG_PQ_SIKE_REPLY},
	{PQ_OQS_KEX_SUFFIX("sike-p503-sha384"), OQS_KEM_alg_sike_p503,
	SSH2_MSG_PQ_SIKE_INIT, SSH2_MSG_PQ_SIKE_REPLY},
	{PQ_OQS_KEX_SUFFIX("sike-p610-sha384"), OQS_KEM_alg_sike_p610,
	SSH2_MSG_PQ_SIKE_INIT, SSH2_MSG_PQ_SIKE_REPLY},
	{PQ_OQS_KEX_SUFFIX("sike-p751-sha384"), OQS_KEM_alg_sike_p751,
	SSH2_MSG_PQ_SIKE_INIT, SSH2_MSG_PQ_SIKE_REPLY},
	{PQ_OQS_KEX_SUFFIX("-sha384"), OQS_KEM_alg_sike_p434_compressed,
	SSH2_MSG_PQ_SIKE_INIT, SSH2_MSG_PQ_SIKE_REPLY},
	{PQ_OQS_KEX_SUFFIX("sike-p503-compressed-sha384"), OQS_KEM_alg_sike_p503_compressed,
	SSH2_MSG_PQ_SIKE_INIT, SSH2_MSG_PQ_SIKE_REPLY},
	{PQ_OQS_KEX_SUFFIX("sike-p610-compressed-sha384"), OQS_KEM_alg_sike_p610_compressed,
	SSH2_MSG_PQ_SIKE_INIT, SSH2_MSG_PQ_SIKE_REPLY},
	{PQ_OQS_KEX_SUFFIX("sike-p751-compressed-sha384"), OQS_KEM_alg_sike_p751_compressed,
	SSH2_MSG_PQ_SIKE_INIT, SSH2_MSG_PQ_SIKE_REPLY},
#endif /* HAVE_SIKE */
#ifdef HAVE_HQC
	{PQ_OQS_KEX_SUFFIX("hqc-128-1-cca2-sha384"), OQS_KEM_alg_hqc_128_1_cca2,
	SSH2_MSG_PQ_HQC_INIT, SSH2_MSG_PQ_HQC_REPLY},
	{PQ_OQS_KEX_SUFFIX("hqc-192-1-cca2-sha384"), OQS_KEM_alg_hqc_192_1_cca2,
	SSH2_MSG_PQ_HQC_INIT, SSH2_MSG_PQ_HQC_REPLY},
	{PQ_OQS_KEX_SUFFIX("hqc-192-2-cca2-sha384"), OQS_KEM_alg_hqc_192_2_cca2,
	SSH2_MSG_PQ_HQC_INIT, SSH2_MSG_PQ_HQC_REPLY},
	{PQ_OQS_KEX_SUFFIX("hqc-256-1-cca2-sha384"), OQS_KEM_alg_hqc_256_1_cca2,
	SSH2_MSG_PQ_HQC_INIT, SSH2_MSG_PQ_HQC_REPLY},
	{PQ_OQS_KEX_SUFFIX("hqc-256-2-cca2-sha384"), OQS_KEM_alg_hqc_256_2_cca2,
	SSH2_MSG_PQ_HQC_INIT, SSH2_MSG_PQ_HQC_REPLY},
	{PQ_OQS_KEX_SUFFIX("hqc-256-3-cca2-sha384"), OQS_KEM_alg_hqc_256_3_cca2,
	SSH2_MSG_PQ_HQC_INIT, SSH2_MSG_PQ_HQC_REPLY},
#endif /* HAVE_HQC */
///// OQS_TEMPLATE_FRAGMENT_DEFINE_PQ_KEXS_END
#endif /* WITH_PQ_KEX */
	{NULL,NULL,0,0} /* End of list */
};

/*
 * @brief Maps the named SSH key exchange method's PQ kex algorithm
 * to libtqs key exchange algorithm
 */
const TQS_ALG *
tqs_mapping(const char *ssh_kex_name) {

	const TQS_ALG *alg = NULL;

	for (alg = tqs_alg_mapping; alg->kex_alg != NULL; alg++) {
		if (strcmp(alg->kex_alg, ssh_kex_name) == 0) {
			return alg;
		}
	}

	return NULL;
}

/*
 * @brief Initialise key exchange libtqs specific context
 */
int
tqs_init(TQS_KEX_CTX **tqs_kex_ctx, char *ssh_kex_name) {

	TQS_KEX_CTX *tmp_tqs_kex_ctx = NULL;
	const TQS_ALG *tqs_alg = NULL;
	int r = 0;

	if ((tmp_tqs_kex_ctx = calloc(sizeof(*(tmp_tqs_kex_ctx)), 1)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	if ((tqs_alg = tqs_mapping(ssh_kex_name)) == NULL) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	tmp_tqs_kex_ctx->tqs_kem = NULL;
	tmp_tqs_kex_ctx->tqs_method = strdup(tqs_alg->alg_name);
	tmp_tqs_kex_ctx->tqs_local_priv = NULL;
	tmp_tqs_kex_ctx->tqs_local_priv_len = 0;
	tmp_tqs_kex_ctx->tqs_local_msg = NULL;
	tmp_tqs_kex_ctx->tqs_local_msg_len = 0;
	tmp_tqs_kex_ctx->tqs_remote_msg = NULL;
	tmp_tqs_kex_ctx->tqs_remote_msg_len = 0;

	/* Use PRNG provided by OpenSSH instad of libtqs's PRNG */
	TQS_randombytes_custom_algorithm((void (*)(uint8_t *, size_t)) &arc4random_buf);

	*tqs_kex_ctx = tmp_tqs_kex_ctx;
	tmp_tqs_kex_ctx = NULL;

out:
	if (tmp_tqs_kex_ctx != NULL)
		free(tmp_tqs_kex_ctx);

	return r;
}

/*
 * @brief Free memory allocated for tqs part of key exchange
 */
void
tqs_free(TQS_KEX_CTX *tqs_kex_ctx) {

	if (tqs_kex_ctx->tqs_local_msg != NULL) {
		free(tqs_kex_ctx->tqs_local_msg);
		tqs_kex_ctx->tqs_local_msg = NULL;
	}
	if (tqs_kex_ctx->tqs_remote_msg != NULL) {
		free(tqs_kex_ctx->tqs_remote_msg);
		tqs_kex_ctx->tqs_remote_msg = NULL;
	}
	if (tqs_kex_ctx->tqs_local_priv != NULL) {
		explicit_bzero(tqs_kex_ctx->tqs_local_priv, tqs_kex_ctx->tqs_local_priv_len);
		free(tqs_kex_ctx->tqs_local_priv);
		tqs_kex_ctx->tqs_local_priv = NULL;
	}
	if (tqs_kex_ctx->tqs_method != NULL) {
		free(tqs_kex_ctx->tqs_method);
		tqs_kex_ctx->tqs_method = NULL;
	}
	if (tqs_kex_ctx->tqs_kem != NULL) {
		TQS_KEM_free(tqs_kex_ctx->tqs_kem);
		tqs_kex_ctx->tqs_kem = NULL;
	}
}

/*
 * @brief SSH hybrid key exchange init message name
 */
int
tqs_ssh2_init_msg(const TQS_ALG *tqs_alg) {
	return tqs_alg->ssh2_init_msg;
}

/*
 * @brief SSH hybrid key exchange reply message name
 */
int
tqs_ssh2_reply_msg(const TQS_ALG *tqs_alg) {
	return tqs_alg->ssh2_reply_msg;
}

/*
 * @brief Generates the client side part of the libtqs kex
 */
int
tqs_client_gen(TQS_KEX_CTX *tqs_kex_ctx) {

	TQS_KEM *tqs_kem = NULL;
	int r = 0;

	if ((tqs_kem = TQS_KEM_new(tqs_kex_ctx->tqs_method)) == NULL) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	tqs_kex_ctx->tqs_local_priv = NULL;
	tqs_kex_ctx->tqs_local_msg = NULL;

	tqs_kex_ctx->tqs_local_priv_len = tqs_kem->length_secret_key;
	if ((tqs_kex_ctx->tqs_local_priv = malloc(tqs_kem->length_secret_key)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	tqs_kex_ctx->tqs_local_msg_len = tqs_kem->length_public_key;
	if ((tqs_kex_ctx->tqs_local_msg = malloc(tqs_kem->length_public_key)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	/* Generate client side part of kex */
	if (TQS_KEM_keypair(tqs_kem, tqs_kex_ctx->tqs_local_msg,
		tqs_kex_ctx->tqs_local_priv) != TQS_SUCCESS) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	tqs_kex_ctx->tqs_kem = tqs_kem;
	tqs_kem = NULL;

out:
	if (tqs_kem != NULL) {
		TQS_KEM_free(tqs_kem);
		free(tqs_kex_ctx->tqs_local_priv);
		free(tqs_kex_ctx->tqs_local_msg);
	}

	return r;
}

/*
 * @brief Deserialise libtqs specific parts of incoming packet
 */
int
tqs_deserialise(struct ssh *ssh, TQS_KEX_CTX *tqs_kex_ctx,
	enum tqs_client_or_server client_or_server) {

	return sshpkt_get_string(ssh, &(tqs_kex_ctx->tqs_remote_msg),
		&(tqs_kex_ctx->tqs_remote_msg_len));
}

/*
 * @brief Serialise libtqs specific parts of outgoing packet
 */
int
tqs_serialise(struct ssh *ssh, TQS_KEX_CTX *tqs_kex_ctx,
	enum tqs_client_or_server client_or_server) {

	return sshpkt_put_string(ssh, tqs_kex_ctx->tqs_local_msg,
		tqs_kex_ctx->tqs_local_msg_len);
}

/*
 * @brief Generates libtqs kex shared secret
 */
int
tqs_client_shared_secret(TQS_KEX_CTX *tqs_kex_ctx,
	u_char **tqs_shared_secret, size_t *tqs_shared_secret_len) {

	uint8_t *tmp_tqs_shared_secret = NULL;
	int r = 0;

	if (tqs_kex_ctx->tqs_remote_msg_len != tqs_kex_ctx->tqs_kem->length_ciphertext) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	if ((tmp_tqs_shared_secret = malloc(tqs_kex_ctx->tqs_kem->length_shared_secret)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	/* Generate shared secret from client private key and server public key */
	if (TQS_KEM_decaps(tqs_kex_ctx->tqs_kem, tmp_tqs_shared_secret,
		tqs_kex_ctx->tqs_remote_msg, tqs_kex_ctx->tqs_local_priv) != TQS_SUCCESS) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	*tqs_shared_secret = (u_char *) tmp_tqs_shared_secret;
	*tqs_shared_secret_len = tqs_kex_ctx->tqs_kem->length_shared_secret;

	tmp_tqs_shared_secret = NULL;

out:
	if (tmp_tqs_shared_secret != NULL) {
		explicit_bzero(tmp_tqs_shared_secret, tqs_kex_ctx->tqs_kem->length_shared_secret);
		free(tmp_tqs_shared_secret);
	}

	return r;
}

/*
 * @brief Generates server message and, simultanously generates
 * the shared secret from server private key and client public key
 */
int
tqs_server_gen_msg_and_ss(TQS_KEX_CTX *tqs_kex_ctx,
	u_char **tqs_shared_secret, size_t *tqs_shared_secret_len) {

	TQS_KEM *tqs_kem = NULL;
	uint8_t *tmp_tqs_shared_secret = NULL, *tmp_tqs_local_msg = NULL;
	int r = 0;

	if ((tqs_kem = TQS_KEM_new(tqs_kex_ctx->tqs_method)) == NULL) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	if (tqs_kex_ctx->tqs_remote_msg_len != tqs_kem->length_public_key) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	if ((tmp_tqs_local_msg = malloc(tqs_kem->length_ciphertext)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((tmp_tqs_shared_secret = malloc(tqs_kem->length_shared_secret)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	if (TQS_KEM_encaps(tqs_kem, tmp_tqs_local_msg, tmp_tqs_shared_secret,
		tqs_kex_ctx->tqs_remote_msg) != TQS_SUCCESS) {
				r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	*tqs_shared_secret = (u_char *) tmp_tqs_shared_secret;
	*tqs_shared_secret_len = tqs_kem->length_shared_secret;
	tqs_kex_ctx->tqs_local_msg = tmp_tqs_local_msg;
	tqs_kex_ctx->tqs_local_msg_len = tqs_kem->length_ciphertext;

	tmp_tqs_shared_secret = NULL;

out:
	if (tqs_kem != NULL) {
		TQS_KEM_free(tqs_kem);
	}
	if (tmp_tqs_shared_secret != NULL) {
		explicit_bzero(tmp_tqs_shared_secret, tqs_kem->length_shared_secret);
		free(tmp_tqs_shared_secret);
		free(tmp_tqs_local_msg);
	}

	return r;
}

#endif /* WITH_TQS */
