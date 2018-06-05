#include <openssl/evp.h> /* for pki operations */
#include <openssl/crypto.h> /* for RSA key generation */
#include <openssl/pem.h> /* for PEM format read and write */
#include <openssl/bio.h> /* for BIO operations */
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
	ENGINE_cleanup();
	CRYPTO_cleanup_all_ex_data();
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
		log_printf(LOG_ERROR, "Failed to make bignum\n");
		return NULL;
	}
	if (BN_set_word(bn_e, e) != 1) {
		log_printf(LOG_ERROR, "Failed set bignum\n");
		BN_free(bn_e);
		return NULL;
	}

	rsa = RSA_new();
	if (rsa == NULL) {
		log_printf(LOG_ERROR, "Failed to allocate new RSA\n");
		BN_free(bn_e);
		return NULL;
	}
	
	if (RSA_generate_key_ex(rsa, bits, bn_e, NULL) != 1) {
		log_printf(LOG_ERROR, "Failed to generate new RSA\n");
		BN_free(bn_e);
		RSA_free(rsa);
		return NULL;
	}

	keypair = EVP_PKEY_new();
	if (keypair == NULL) {
		log_printf(LOG_ERROR, "Failed to allocate new keypair\n");
		RSA_free(rsa);
		BN_free(bn_e);
		return NULL;
	}

	if (EVP_PKEY_assign_RSA(keypair, rsa) != 1) {
		log_printf(LOG_ERROR, "Failed to assign RSA to keypair\n");
		RSA_free(rsa);
		BN_free(bn_e);
		return NULL;
	}

	key = calloc(1, sizeof(cryptokey_t));
	if (key == NULL) {
		log_printf(LOG_ERROR, "Failed to allocate new cryptokey\n");
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
	unsigned char* encoded_pubkey_end;
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
	encoded_pubkey_end = encoded_pubkey;
	encoded_len = i2d_PUBKEY(keypair, &encoded_pubkey_end);
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

int util_serialize_key(cryptokey_t* key, unsigned char** data, int* datalen) {
	BIO* bio;
	unsigned char* bio_data;
	unsigned char* buffer;
	long len;

	bio = BIO_new(BIO_s_mem());
	if (bio == NULL) {
		log_printf(LOG_ERROR, "Unable to create bio for key\n");
		return 0;
	}
	if (PEM_write_bio_PrivateKey(bio, key->ossl_key, 
			NULL, NULL, 0, NULL, NULL) == 0) {
		log_printf(LOG_ERROR, "Unable to write PEM string for key\n");
		BIO_free(bio);
		return 0;
	}
	len = BIO_get_mem_data(bio, &bio_data);
	buffer = malloc(len);
	if (buffer == NULL) {
		log_printf(LOG_ERROR, "Unable to allocate buffer for key\n");
		BIO_free(bio);
		return 0;
	}
	memcpy(buffer, bio_data, len);
	*datalen = (int)len;
	*data = buffer;
	BIO_free(bio);
	return 1;
}

cryptokey_t* util_deserialize_key(unsigned char* data, int datalen) {
	cryptokey_t* key;
	EVP_PKEY* ossl_key;
	BIO* bio;

	bio = BIO_new_mem_buf(data, datalen);
	if (bio == NULL) {
		log_printf(LOG_ERROR, "Unable to create bio for key\n");
		return NULL;
	}
	ossl_key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
	if (ossl_key == NULL) {
		log_printf(LOG_ERROR, "Unable to read key from bio\n");
		BIO_free(bio);
		return NULL;
	}
	BIO_free(bio);
	key = calloc(1, sizeof(cryptokey_t));
	if (key == NULL) {
		log_printf(LOG_ERROR, "Failed to allocate cryptokey\n");
		return NULL;
	}

	key->ossl_key = ossl_key;
	return key;
}

int util_base64_encode(const unsigned char* input, size_t inlen, 
		char* output, size_t* outlen) {
	BIO *bio;
	BIO *bio_b64;
	char* buffer_ptr;
	int written;

	bio_b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(bio_b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
	BIO_set_close(bio, BIO_CLOSE);
	written = BIO_write(bio, input, inlen);
	if (written <= 0) {
		log_printf(LOG_ERROR, "Failed to write base64 input\n");
		BIO_free_all(bio);
		return 0;
	}
	BIO_flush(bio);

	written = BIO_get_mem_data(bio, &buffer_ptr);
	memcpy(output, buffer_ptr, written);
	output[written] = '\0';
	BIO_free_all(bio);
	*outlen = written;
	return 1;
}

