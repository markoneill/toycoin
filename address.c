#include <openssl/evp.h> /* for pki operations */
#include <openssl/crypto.h> /* for RSA key generation */
#include <openssl/pem.h> /* for PEM format read and write */
#include <string.h> /* for strerror */
#include <errno.h> /* for errno */
#include <stdlib.h> /* for calloc */

#include "address.h"
#include "transaction.h"
#include "log.h"

static int generate_rsa_key(EVP_PKEY** key_out, int bits);
static int hash_pubkey(EVP_PKEY* keypair, unsigned char* digest, size_t* digest_len);

static coin_t* coin_new(transaction_t* transaction, int index);
static void coin_free(coin_t* coin);

extern const EVP_MD* hash_alg;

address_t* address_new(void) {
	EVP_PKEY* keypair;
	address_t* address;
	address = calloc(1, sizeof(address));
	if (address == NULL) {
		log_printf(LOG_ERROR, "Unable to allocate new address\n");
		return NULL;
	}
	if (generate_rsa_key(&keypair, 4096) == 0) {
		log_printf(LOG_ERROR, "Unable to generate RSA key\n");
		free(address);
		return NULL;
	}
	
	if (hash_pubkey(keypair, &address->id, &address->id_len) == 0) {
		log_printf(LOG_ERROR, "Unable to hash pubkey\n");
		free(address);
		return NULL;
	}
	address->coin = NULL;
	address->next = NULL;
	return address;
}

void address_free(address_t* address) {
	EVP_PKEY_free(address->keypair);
	if (address->coin != NULL) {
		coin_free(address->coin);
	}
	address->keypair = NULL;
	address->coin = NULL;
	address->next = NULL;
	free(address);
	return;
}


int generate_rsa_key(EVP_PKEY** key_out, int bits) {
	unsigned long e;
	BIGNUM* bn_e;
	RSA* rsa;
	EVP_PKEY* keypair;

	e = RSA_F4;	

	bn_e = BN_new();
	if (bn_e == NULL) {
		return 0;
	}
	if (BN_set_word(bn_e, e) != 1) {
		BN_free(bn_e);
		return 0;
	}

	rsa = RSA_new();
	if (rsa == NULL) {
		BN_free(bn_e);
		return 0;
	}
	
	if (RSA_generate_key_ex(rsa, bits, bn_e, NULL) != 1) {
		BN_free(bn_e);
		RSA_free(rsa);
		return 0;
	}

	keypair = EVP_PKEY_new();
	if (keypair == NULL) {
		RSA_free(rsa);
		BN_free(bn_e);
		return 0;
	}

	if (EVP_PKEY_assign_RSA(keypair, rsa) != 1) {
		RSA_free(rsa);
		BN_free(bn_e);
		return 0;
	}

	*key_out = keypair;
	BN_free(bn_e);
	return 1;
}

int hash_pubkey(EVP_PKEY* keypair, unsigned char* digest, size_t* digest_len) {
	EVP_MD_CTX* md_ctx;
	unsigned char* encoded_pubkey;
	int encoded_len;

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

	#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	md_ctx = EVP_MD_CTX_new();
	#else
	md_ctx = EVP_MD_CTX_create();
	#endif

	if (EVP_DigestInit_ex(md_ctx, hash_alg, NULL) == 0) {
		log_printf(LOG_ERROR, "Failed to init digest\n");		
		free(encoded_pubkey);
		return 0;
	}
	if (EVP_DigestUpdate(md_ctx, encoded_pubkey, encoded_len) == 0) {
		log_printf(LOG_ERROR, "Failed to update digest\n");
		free(encoded_pubkey);
		return 0;
	}
	if (EVP_DigestFinal_ex(md_ctx, digest, digest_len) == 0) {
		log_printf(LOG_ERROR, "Failed to finalize digest\n");
		free(encoded_pubkey);
		return 0;
	}

	free(encoded_pubkey);

	#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	EVP_MD_CTX_free(md_ctx);
	#else
	EVP_MD_CTX_destroy(md_ctx);
	#endif
	return 1;
}

coin_t* coin_new(transaction_t* transaction, int index) {
	coin_t* coin;
	coin = calloc(1, sizeof(coin_t));
	if (coin == NULL) {
		log_printf(LOG_ERROR, "Unable to allocate new coin\n");
		return NULL;
	}
	coin->transaction = transaction;
	coin->index = index;
	return coin;
}

void coin_free(coin_t* coin) {
	coin->transaction = NULL;
	free(coin);
	return;
}
