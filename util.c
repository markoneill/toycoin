#include <openssl/evp.h> /* for pki operations */
#include <openssl/crypto.h> /* for RSA key generation */
#include <openssl/pem.h> /* for PEM format read and write */
#include "log.h"
#include "util.h"

const EVP_MD* hash_alg;

void util_init_crypto(void) {
	OpenSSL_add_all_digests();
	hash_alg = EVP_sha256();
	return;
}

void util_deinit_crypto(void) {
	EVP_cleanup();
}

int util_digestlen(void) {
	return EVP_MD_size(hash_alg);
}

int util_hash(unsigned char* data, size_t* datalen, unsigned char* digest, 
		unsigned int* digestlen) {
	EVP_MD_CTX* md_ctx;
	#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	md_ctx = EVP_MD_CTX_new();
	#else
	md_ctx = EVP_MD_CTX_create();
	#endif

	if (EVP_DigestInit_ex(md_ctx, hash_alg, NULL) == 0) {
		log_printf(LOG_ERROR, "Failed to init digest\n");		
		return 0;
	}
	if (EVP_DigestUpdate(md_ctx, data, datalen) == 0) {
		log_printf(LOG_ERROR, "Failed to update digest\n");
		return 0;
	}
	if (EVP_DigestFinal_ex(md_ctx, digest, digestlen) == 0) {
		log_printf(LOG_ERROR, "Failed to finalize digest\n");
		return 0;
	}

	#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	EVP_MD_CTX_free(md_ctx);
	#else
	EVP_MD_CTX_destroy(md_ctx);
	#endif
	return 1;
}

cryptokey_t* util_generate_key(int bits) {
	unsigned long e;
	BIGNUM* bn_e;
	RSA* rsa;
	cryptokey_t* key;
	EVP_PKEY* keypair;

	e = RSA_F4;	

	bn_e = BN_new();
	if (bn_e == NULL) {
		return NULL;
	}
	if (BN_set_word(bn_e, e) != 1) {
		BN_free(bn_e);
		return NULL;
	}

	rsa = RSA_new();
	if (rsa == NULL) {
		BN_free(bn_e);
		return NULL;
	}
	
	if (RSA_generate_key_ex(rsa, bits, bn_e, NULL) != 1) {
		BN_free(bn_e);
		RSA_free(rsa);
		return NULL;
	}

	keypair = EVP_PKEY_new();
	if (keypair == NULL) {
		RSA_free(rsa);
		BN_free(bn_e);
		return NULL;
	}

	if (EVP_PKEY_assign_RSA(keypair, rsa) != 1) {
		RSA_free(rsa);
		BN_free(bn_e);
		return NULL;
	}

	key = calloc(1, sizeof(key_t));
	if (key == NULL) {
		RSA_free(rsa);
		BN_free(bn_e);
		return NULL;
	}

	key->ossl_key = keypair;
	BN_free(bn_e);
	return key;
}

int util_hash_pubkey(cryptokey_t* key, unsigned char* digest, size_t* digest_len) {
	EVP_PKEY* keypair;
	unsigned char* encoded_pubkey;
	int encoded_len;

	keypair = key->ossl_key;

	encoded_len = i2d_PUBKEY(keypair, NULL);
	if (encoded_len < 0) {
		log_printf(LOG_ERROR, "Failed to get public key length\n");
		return 0;
	}
	encoded_pubkey = malloc(encoded_len);
	if (encoded_pubkey == NULL) {
		log_printf(LOG_ERROR, "Failed to allocate encoded key\n");
		return 0;
	}
	encoded_len = i2d_PUBKEY(keypair, &encoded_pubkey);
	if (encoded_len < 0) {
		log_printf(LOG_ERROR, "Failed to encode public key\n");
		free(encoded_pubkey);
		return 0;
	}

	if (util_hash(encoded_pubkey, encoded_len, digest, digest_len) == 0) {
		log_printf(LOG_ERROR, "Unable to hash public key\n");
		free(encoded_pubkey);
		return 0;
	}

	free(encoded_pubkey);
	return 1;
}

void util_free_key(cryptokey_t* key) {
	EVP_PKEY_free(key->ossl_key);
	free(key);
	return;
}
