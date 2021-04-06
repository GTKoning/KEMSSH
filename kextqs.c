//
// Created by op on 26-11-20.
//
#include "includes.h"

//#ifdef WITH_TQS

#include <string.h>

#include "ssherr.h"
#include "packet.h"
#include "ssh2.h"
#include "kexoqs.h"
#include "kextqs.h"
#include "sshkey.h"
#include "log.h"

/*
 * Mapping that maps relevant named SSH key exchange methods to the needed
 * corresponding liboqs key exchange scheme
 */
static const OQS_ALG oqs_alg_mapping[] = {
#ifdef WITH_PQ_KEX
	{PQ_OQS_KEX_SUFFIX("oqsdefault-sha384"), OQS_KEM_alg_default,
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
 * to liboqs key exchange algorithm
 */
const OQS_ALG *
tqs_mapping(const char *ssh_kex_name) {

	const OQS_ALG *alg = NULL;

	for (alg = oqs_alg_mapping; alg->kex_alg != NULL; alg++) {
		if (strcmp(alg->kex_alg, ssh_kex_name) == 0) {
			return alg;
		}
	}

	return NULL;
}

/*
 * @brief Initialise key exchange liboqs specific context
 */
int
tqs_init(OQS_KEX_CTX **oqs_kex_ctx, char *ssh_kex_name) {

	OQS_KEX_CTX *tmp_oqs_kex_ctx = NULL;
	const OQS_ALG *oqs_alg = NULL;
	int r = 0;

	if ((tmp_oqs_kex_ctx = calloc(sizeof(*(tmp_oqs_kex_ctx)), 1)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	if ((oqs_alg = oqs_mapping(ssh_kex_name)) == NULL) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	tmp_oqs_kex_ctx->oqs_kem = NULL;
	tmp_oqs_kex_ctx->oqs_method = strdup(oqs_alg->alg_name);
	tmp_oqs_kex_ctx->oqs_local_priv = NULL;
	tmp_oqs_kex_ctx->oqs_local_priv_len = 0;
	tmp_oqs_kex_ctx->oqs_local_msg = NULL;
	tmp_oqs_kex_ctx->oqs_local_msg_len = 0;
	tmp_oqs_kex_ctx->oqs_remote_msg = NULL;
	tmp_oqs_kex_ctx->oqs_remote_msg_len = 0;

	/* Use PRNG provided by OpenSSH instad of liboqs's PRNG */
	OQS_randombytes_custom_algorithm((void (*)(uint8_t *, size_t)) &arc4random_buf);

	*oqs_kex_ctx = tmp_oqs_kex_ctx;
	tmp_oqs_kex_ctx = NULL;

out:
	if (tmp_oqs_kex_ctx != NULL)
		free(tmp_oqs_kex_ctx);

	return r;
}

/*
 * @brief Free memory allocated for oqs part of key exchange
 */
void
tqs_free(OQS_KEX_CTX *oqs_kex_ctx) {

	if (oqs_kex_ctx->oqs_local_msg != NULL) {
		free(oqs_kex_ctx->oqs_local_msg);
		oqs_kex_ctx->oqs_local_msg = NULL;
	}
	if (oqs_kex_ctx->oqs_remote_msg != NULL) {
		free(oqs_kex_ctx->oqs_remote_msg);
		oqs_kex_ctx->oqs_remote_msg = NULL;
	}
	if (oqs_kex_ctx->oqs_local_priv != NULL) {
		explicit_bzero(oqs_kex_ctx->oqs_local_priv, oqs_kex_ctx->oqs_local_priv_len);
		free(oqs_kex_ctx->oqs_local_priv);
		oqs_kex_ctx->oqs_local_priv = NULL;
	}
	if (oqs_kex_ctx->oqs_method != NULL) {
		free(oqs_kex_ctx->oqs_method);
		oqs_kex_ctx->oqs_method = NULL;
	}
	if (oqs_kex_ctx->oqs_kem != NULL) {
		OQS_KEM_free(oqs_kex_ctx->oqs_kem);
		oqs_kex_ctx->oqs_kem = NULL;
	}
}

/*
 * @brief SSH hybrid key exchange init message name
 */
int
tqs_ssh2_init_msg(const OQS_ALG *oqs_alg) {
	return oqs_alg->ssh2_init_msg;
}

int
tqs_ssh2_verinit_msg(const OQS_ALG *oqs_alg) {
    return 43;
}
/*
 * @brief SSH hybrid key exchange reply message name
 */
int
tqs_ssh2_reply_msg(const OQS_ALG *oqs_alg) {
	return oqs_alg->ssh2_reply_msg;
}

int
tqs_ssh2_sendct_msg(const OQS_ALG *oqs_alg){
    return 42;
}

int
tqs_ssh2_verreply_msg(const OQS_ALG *oqs_alg) {
    return 44;
}

/*
 * @brief Generates the client side part of the liboqs kex
 */
int
tqs_client_gen(OQS_KEX_CTX *oqs_kex_ctx) {

	OQS_KEM *oqs_kem = NULL;
	int r = 0;

	if ((oqs_kem = OQS_KEM_new(oqs_kex_ctx->oqs_method)) == NULL) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	oqs_kex_ctx->oqs_local_priv = NULL;
	oqs_kex_ctx->oqs_local_msg = NULL;

	oqs_kex_ctx->oqs_local_priv_len = oqs_kem->length_secret_key;
	if ((oqs_kex_ctx->oqs_local_priv = malloc(oqs_kem->length_secret_key)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	oqs_kex_ctx->oqs_local_msg_len = oqs_kem->length_public_key;
	if ((oqs_kex_ctx->oqs_local_msg = malloc(oqs_kem->length_public_key)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	/* Generate client side part of kex */
	if (OQS_KEM_keypair(oqs_kem, oqs_kex_ctx->oqs_local_msg,
		oqs_kex_ctx->oqs_local_priv) != OQS_SUCCESS) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	oqs_kex_ctx->oqs_kem = oqs_kem;
	oqs_kem = NULL;

out:
	if (oqs_kem != NULL) {
		OQS_KEM_free(oqs_kem);
		free(oqs_kex_ctx->oqs_local_priv);
		free(oqs_kex_ctx->oqs_local_msg);
	}

	return r;
}

/*
 * @brief Deserialise liboqs specific parts of incoming packet
 */
int
tqs_deserialise(struct ssh *ssh, OQS_KEX_CTX *oqs_kex_ctx,
	enum tqs_client_or_server client_or_server) {
    // needs to get cta if its there - > refer to 2
    // So we got the pk (or do we?) -> sshpkt_get_string consumes the entire buffer...
    return sshpkt_get_string(ssh, &(oqs_kex_ctx->oqs_remote_msg),
		&(oqs_kex_ctx->oqs_remote_msg_len));
}

int
tqs_deserialise2(struct ssh *ssh, OQS_KEX_CTX *oqs_kex_ctx,
                enum tqs_client_or_server client_or_server) {
    // So we got the pk_b, let's get the ct_b aswell.
    // UNDERCONSTRUCTION
    sshpkt_get_string(ssh, &(oqs_kex_ctx->tqs_ct_b), &(oqs_kex_ctx->tqs_ct_b_len));

    return sshpkt_get_string(ssh, &(oqs_kex_ctx->oqs_remote_msg),
                             &(oqs_kex_ctx->oqs_remote_msg_len));
}

int
tqs_deserialisever(struct ssh *ssh, OQS_KEX_CTX *oqs_kex_ctx, enum tqs_client_or_server client_or_server){
    if(client_or_server == TQS_IS_CLIENT){
        return sshpkt_get_string(ssh, &(oqs_kex_ctx->digestb), &(oqs_kex_ctx->digestlen));
    }
    return sshpkt_get_string(ssh, &(oqs_kex_ctx->digesta), &(oqs_kex_ctx->digestlen));
}


/*
 * @brief Serialise liboqs specific parts of outgoing packet
 */
int
tqs_serialise(struct ssh *ssh, OQS_KEX_CTX *oqs_kex_ctx,
	enum tqs_client_or_server client_or_server) {
    if(oqs_kex_ctx->tqs_ct_a == NULL){
        error(" OOPS no CT_A found");
    }
    else {
        error(" Went through (A)");
        sshpkt_put_string(ssh, oqs_kex_ctx->tqs_ct_a, oqs_kex_ctx->tqs_ct_a_len);
    }
    if(oqs_kex_ctx->tqs_ct_b == NULL){
        error(" OOPS no CT_B found");
    }
    else {
        error(" Went through (B)");
        sshpkt_put_string(ssh, oqs_kex_ctx->tqs_ct_b, oqs_kex_ctx->tqs_ct_b_len);
    }
    error(" !! printing tqs_ct_b_len %li", oqs_kex_ctx->tqs_ct_b_len);
    error(" !! Printing oqs_local_msg_len %li", oqs_kex_ctx->oqs_local_msg_len);
	return sshpkt_put_string(ssh, oqs_kex_ctx->oqs_local_msg,
		oqs_kex_ctx->oqs_local_msg_len);
}

int tqs_serialisever(struct ssh *ssh, OQS_KEX_CTX *oqs_kex_ctx, enum tqs_client_or_server client_or_server){
    return sshpkt_put_string(ssh, oqs_kex_ctx->digesta, oqs_kex_ctx->digestlen);
}

int
tqs_serialise2(struct ssh *ssh, OQS_KEX_CTX *oqs_kex_ctx,
              enum tqs_client_or_server client_or_server) {
    return sshpkt_put_string(ssh, oqs_kex_ctx->tqs_ct_b,
                          oqs_kex_ctx->tqs_ct_b_len);
}

/*
 * @brief Generates liboqs kex shared secret
 */
int
tqs_client_shared_secret(OQS_KEX_CTX *oqs_kex_ctx,
	u_char **tqs_key_a, u_char **tqs_key_b, u_char **tqs_full_key, size_t *tqs_fullkey_size, size_t *tqs_halfkey_size, struct sshkey **server_host_key) {
    uint8_t *tmp_tqs_ct_a = NULL;
	uint8_t *tmp_tqs_key_a = NULL;
    uint8_t *tmp_tqs_key_b = NULL;
    uint8_t *tmp_tqs_full_key = NULL;
    struct sshkey *tmp_server_host_key = *server_host_key;
    *tqs_halfkey_size = oqs_kex_ctx->oqs_kem->length_shared_secret;
    *tqs_fullkey_size = 2*sizeof(oqs_kex_ctx->oqs_kem->length_shared_secret);


	int r = 0;
    // checks ct_b length
	if (oqs_kex_ctx->oqs_remote_msg_len != oqs_kex_ctx->oqs_kem->length_public_key) {
		r = SSH_ERR_INVALID_FORMAT;

		goto out;
	}
    error("Size of remote msg: %li", oqs_kex_ctx->oqs_remote_msg_len);
    error("Size of ct_len: %li", oqs_kex_ctx->tqs_ct_b_len);
    error("Size of ciphertext expected: %li", oqs_kex_ctx->oqs_kem->length_ciphertext);

	// Make space for "key_a"
	if ((tmp_tqs_key_a = malloc(*tqs_halfkey_size)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

    // Make space for "key_b"
    if ((tmp_tqs_key_b = malloc(*tqs_halfkey_size)) == NULL) {
        r = SSH_ERR_ALLOC_FAIL;
        goto out;
    }

    // Make space for "full key"
    if ((tmp_tqs_full_key = malloc(*tqs_fullkey_size)) == NULL) {
        r = SSH_ERR_ALLOC_FAIL;
        goto out;
    }

    // Make space for "ct_a"
    if ((tmp_tqs_ct_a = malloc(oqs_kex_ctx->oqs_kem->length_ciphertext)) == NULL) {
        r = SSH_ERR_ALLOC_FAIL;
        goto out;
    }
    error("shared secret checkpoint 1");

    error("%s", tmp_server_host_key->oqs_pk);
    error("%li", *tqs_halfkey_size);
	// Nu moet de encapsulate komen !
    if (OQS_KEM_encaps(oqs_kex_ctx->oqs_kem, tmp_tqs_ct_a, tmp_tqs_key_a,
                       tmp_server_host_key->oqs_pk) != OQS_SUCCESS) {
        r = SSH_ERR_INTERNAL_ERROR;
        error(" !! encaps fails");
        goto out;
    }
    error("shared secret checkpoint 2");
	/* Generate shared secret from client private key and server public key */
	if (OQS_KEM_decaps(oqs_kex_ctx->oqs_kem, tmp_tqs_key_b,
		oqs_kex_ctx->tqs_ct_b, oqs_kex_ctx->oqs_local_priv) != OQS_SUCCESS) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

    error("shared secret checkpoint 3");

    *tmp_tqs_full_key = *tmp_tqs_key_a + *tmp_tqs_key_b;
	*tqs_key_a = (u_char *) tmp_tqs_key_a;
    *tqs_key_b = (u_char *) tmp_tqs_key_b;
    *tqs_full_key = (u_char *) tmp_tqs_full_key;
	oqs_kex_ctx->tqs_ct_a = tmp_tqs_ct_a;
    oqs_kex_ctx->tqs_ct_a_len = oqs_kex_ctx->oqs_kem->length_ciphertext;


	tmp_tqs_key_a = NULL;
	// Now for the KDF -> what to do? Added them together -> cast to u char

out:
	if (tmp_tqs_key_a != NULL) {
		explicit_bzero(tmp_tqs_key_a, oqs_kex_ctx->oqs_kem->length_shared_secret);
		free(tmp_tqs_key_a);
	}

	return r;
}

/*
 * @brief Generates server message and, simultanously generates
 * the shared secret from server private key and client public key
 */

/* Leest de public key out OQS_KEX_CTX en schrijft de ct (naar oqs_kex_ctx) */
int
tqs_server_gen_msg_and_ss(struct ssh *ssh, OQS_KEX_CTX *oqs_kex_ctx,
	u_char **tqs_key_b, size_t *tqs_halfkey_size, u_char **oqs_shared_secret, size_t *oqs_shared_secret_len) {

	OQS_KEM *oqs_kem = NULL;
	uint8_t *tmp_tqs_key_b = NULL, *tmp_tqs_ct_b = NULL;
	int r = 0;

	if ((oqs_kem = OQS_KEM_new(oqs_kex_ctx->oqs_method)) == NULL) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	if (oqs_kex_ctx->oqs_remote_msg_len != oqs_kem->length_public_key) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	if ((tmp_tqs_ct_b = malloc(oqs_kem->length_ciphertext)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	if ((tmp_tqs_key_b = malloc(oqs_kem->length_shared_secret)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}


	if (OQS_KEM_encaps(oqs_kem, tmp_tqs_ct_b, tmp_tqs_key_b,
		oqs_kex_ctx->oqs_remote_msg) != OQS_SUCCESS) {
				r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	*tqs_key_b = (u_char *) tmp_tqs_key_b;
	oqs_kex_ctx->tqs_key_b = tmp_tqs_key_b;
	*tqs_halfkey_size = oqs_kem->length_shared_secret;
	// kb set
    *oqs_shared_secret = (u_char *) tmp_tqs_key_b;
    oqs_kex_ctx->oqs_kem = oqs_kem;
    *oqs_shared_secret_len = oqs_kex_ctx->oqs_kem->length_shared_secret;
	oqs_kex_ctx->tqs_ct_b = tmp_tqs_ct_b;
	oqs_kex_ctx->tqs_ct_b_len = oqs_kex_ctx->oqs_kem->length_ciphertext;
	error( " Time to print tqs_ct_b: %s", tmp_tqs_ct_b);
    error( " Time to print tqs_key_b: %s", *tqs_key_b);
    error( " They seem to work, somewhat");



    tmp_tqs_key_b = NULL;
    tmp_tqs_ct_b = NULL;

    return r;

out:
	if (oqs_kem != NULL) {
		OQS_KEM_free(oqs_kem);
	}
	if (tmp_tqs_key_b != NULL) {
		explicit_bzero(tmp_tqs_key_b, oqs_kem->length_shared_secret);
		free(tmp_tqs_key_b);
		free(tmp_tqs_ct_b);
	}

	return r;
}

int
tqs_server_gen_key_hmac(OQS_KEX_CTX *oqs_kex_ctx, u_char **tqs_full_key, size_t *tqs_fullkey_size){
    uint8_t *tmp_tqs_key_a = NULL;
    uint8_t *tmp_tqs_key_b = oqs_kex_ctx->tqs_key_b;
    uint8_t *tmp_tqs_full_key = NULL;
    size_t tqs_halfkey_size = oqs_kex_ctx->oqs_kem->length_shared_secret;
    *tqs_fullkey_size = 2*tqs_halfkey_size;
    oqs_kex_ctx->tqs_ct_a_len = oqs_kex_ctx->oqs_kem->length_ciphertext;

    int r = 0;
    // Make space for "key_a"
    if ((tmp_tqs_key_a = malloc(tqs_halfkey_size)) == NULL) {
        r = SSH_ERR_ALLOC_FAIL;
        goto out;
    }

    // Make space for "full key"
    if ((tmp_tqs_full_key = malloc(*tqs_fullkey_size)) == NULL) {
        r = SSH_ERR_ALLOC_FAIL;
        goto out;
    }

    /* Generate shared secret from client private key and server public key */
	debug("oqs_kem: %p", oqs_kex_ctx->oqs_kem);
	debug("ct_a: %p", oqs_kex_ctx->tqs_ct_a);
	debug("local_priv: %p", oqs_kex_ctx->oqs_local_priv);
    if (OQS_KEM_decaps(oqs_kex_ctx->oqs_kem, tmp_tqs_key_a,
                       oqs_kex_ctx->tqs_ct_a, oqs_kex_ctx->oqs_local_priv) != OQS_SUCCESS) {
		debug("iedereen is dood einde");
        r = SSH_ERR_INTERNAL_ERROR;
        goto out;
    }
	debug("decaps lukte???");

    *tmp_tqs_full_key = *tmp_tqs_key_a + *tmp_tqs_key_b;
    oqs_kex_ctx->tqs_key_a = tmp_tqs_key_a;
    *tqs_full_key = (u_char *) tmp_tqs_full_key;

    tmp_tqs_key_a = NULL;

    // Thats all done ( I hope)

    out:
    if (tmp_tqs_key_a != NULL) {
        explicit_bzero(tmp_tqs_key_a, oqs_kex_ctx->oqs_kem->length_shared_secret);
        free(tmp_tqs_key_a);
    }
    return r;
}

//#endif /* WITH_TQS */
